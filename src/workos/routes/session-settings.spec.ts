import { afterEach, describe, expect, it, setSystemTime } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { createEmulator, type Emulator, type EmulatorSeedConfig } from '../../index.js';
import { JWTManager } from '../../core/jwt.js';
import { validateSeedConfig } from '../config-validator.js';

const CLIENT_ID = 'client_session_settings';
const privateKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ format: 'pem', type: 'pkcs8' })
  .toString();

function seed(accessTokenTtlSeconds?: number): EmulatorSeedConfig {
  return {
    ...(accessTokenTtlSeconds === undefined
      ? {}
      : { sessionSettings: { access_token_ttl_seconds: accessTokenTtlSeconds } }),
    organizations: [
      { id: 'org_lifetime', name: 'Lifetime', memberships: [{ email: 'alice@example.test', status: 'active' }] },
    ],
    users: [{ id: 'user_lifetime', email: 'alice@example.test', password: 'test-password', email_verified: true }],
  };
}

function start(accessTokenTtlSeconds?: number) {
  return createEmulator({ port: 0, signingKey: { privateKey }, seed: seed(accessTokenTtlSeconds) });
}

async function authenticate(emulator: Emulator, refreshToken?: string) {
  const response = await fetch(`${emulator.url}/user_management/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      ...(refreshToken
        ? { grant_type: 'refresh_token', refresh_token: refreshToken }
        : {
            grant_type: 'password',
            email: 'alice@example.test',
            password: 'test-password',
            organization_id: 'org_lifetime',
          }),
    }),
  });
  expect(response.status).toBe(200);
  return response.json() as Promise<{ access_token: string; refresh_token: string }>;
}

/** Verifies against the key the emulator signs with, so a bad signature fails here too. */
function claims(emulator: Emulator, token: string) {
  return new JWTManager(emulator.url, { privateKey }).verify(token);
}

async function widgetToken(emulator: Emulator) {
  const response = await fetch(`${emulator.url}/widgets/token`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${emulator.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      organization_id: 'org_lifetime',
      user_id: 'user_lifetime',
      scopes: ['widgets:users-table:manage'],
    }),
  });
  expect(response.status).toBe(201);
  return ((await response.json()) as { token: string }).token;
}

describe('seeded session settings', () => {
  afterEach(() => setSystemTime());

  it("mints access tokens with production's five-minute default, on sign-in and on refresh", async () => {
    const emulator = await start();
    try {
      const login = await authenticate(emulator);
      const first = claims(emulator, login.access_token);
      expect(first.exp - first.iat).toBe(300);
      expect(first.sub).toBe('user_lifetime');
      expect(first.org_id).toBe('org_lifetime');

      const rotated = await authenticate(emulator, login.refresh_token);
      const renewed = claims(emulator, rotated.access_token);
      expect(renewed.exp - renewed.iat).toBe(300);
      expect(renewed.sid).toBe(first.sid);
    } finally {
      await emulator.close();
    }
  });

  it('applies a seeded lifetime to every grant, survives reset, and stays local to its instance', async () => {
    const short = await start(60);
    const standard = await start();
    try {
      for (const [emulator, expected] of [
        [short, 60],
        [standard, 300],
      ] as const) {
        const login = await authenticate(emulator);
        const first = claims(emulator, login.access_token);
        expect(first.exp - first.iat).toBe(expected);

        const rotated = await authenticate(emulator, login.refresh_token);
        expect(rotated.refresh_token).not.toBe(login.refresh_token);
        const renewed = claims(emulator, rotated.access_token);
        expect(renewed.exp - renewed.iat).toBe(expected);
        expect(renewed.sid).toBe(first.sid);

        // Only the AuthKit access token is affected; a widget token keeps its own hour.
        const widget = claims(emulator, await widgetToken(emulator));
        expect(widget.exp - widget.iat).toBe(3600);

        emulator.reset();
        const afterReset = claims(emulator, (await authenticate(emulator)).access_token);
        expect(afterReset.exp - afterReset.iat).toBe(expected);
      }
    } finally {
      await standard.close();
      await short.close();
    }
  });

  it('refuses a token past its seeded lifetime and refreshes the same session past it', async () => {
    const emulator = await start(60);
    try {
      const login = await authenticate(emulator);
      const first = claims(emulator, login.access_token);
      expect(first.exp - first.iat).toBe(60);

      // Verification fails once the whole-second clock is strictly past `exp`.
      setSystemTime(new Date((first.exp + 1) * 1000));
      expect(() => claims(emulator, login.access_token)).toThrow('Token has expired');

      const rotated = await authenticate(emulator, login.refresh_token);
      const renewed = claims(emulator, rotated.access_token);
      expect(renewed.sid).toBe(first.sid);
      expect(renewed.iat).toBeGreaterThan(first.exp);
      expect(renewed.exp - renewed.iat).toBe(60);
    } finally {
      await emulator.close();
    }
  });

  it.each([null, 0, -1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 31, Number.MAX_SAFE_INTEGER, '60', true])(
    'rejects access_token_ttl_seconds %p before the server starts',
    async (value) => {
      const config = {
        ...seed(),
        sessionSettings: { access_token_ttl_seconds: value as number },
      };
      const validation = validateSeedConfig(config);
      expect(validation.valid).toBe(false);
      expect(validation.errors.map((error) => error.path)).toEqual(['sessionSettings.access_token_ttl_seconds']);
      await expect(createEmulator({ port: 0, seed: config })).rejects.toThrow(
        'sessionSettings.access_token_ttl_seconds',
      );
    },
  );

  it('rejects a sessionSettings that is not an object', () => {
    const validation = validateSeedConfig({ ...seed(), sessionSettings: 60 as never });
    expect(validation.errors.map((error) => error.path)).toEqual(['sessionSettings']);
  });

  it('accepts an omitted access_token_ttl_seconds', () => {
    expect(validateSeedConfig({ ...seed(), sessionSettings: {} }).valid).toBe(true);
  });

  it('accepts a lifetime up to the 32-bit ceiling, which keeps exp a safe integer', () => {
    const config = { ...seed(), sessionSettings: { access_token_ttl_seconds: 2 ** 31 - 1 } };
    expect(validateSeedConfig(config).valid).toBe(true);
  });
});
