import { describe, expect, it } from 'bun:test';
import { createPublicKey, generateKeyPairSync, verify, type JsonWebKey } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { createEmulator, type Emulator, type EmulatorOptions } from './index.js';
import { JWTManager } from './core/jwt.js';

const CLIENT_ID = 'client_token_lifetime';
const privateKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({
    format: 'pem',
    type: 'pkcs8',
  })
  .toString();

function options(ttl?: number): EmulatorOptions {
  return {
    port: 0,
    authKitAccessTokenTtlSeconds: ttl,
    signingKey: { privateKey },
    seed: {
      organizations: [
        { id: 'org_lifetime', name: 'Lifetime', memberships: [{ email: 'lifetime@example.test', status: 'active' }] },
      ],
      users: [{ id: 'user_lifetime', email: 'lifetime@example.test', password: 'test-password', email_verified: true }],
    },
  };
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
            email: 'lifetime@example.test',
            password: 'test-password',
            organization_id: 'org_lifetime',
          }),
    }),
  });
  expect(response.status).toBe(200);
  return response.json() as Promise<{ access_token: string; refresh_token: string }>;
}

async function verifyAccess(emulator: Emulator, token: string) {
  const jwksResponse = await fetch(`${emulator.url}/sso/jwks/${CLIENT_ID}`);
  expect(jwksResponse.status).toBe(200);
  const jwks = (await jwksResponse.json()) as { keys: JsonWebKey[] };
  const [header, payload, signature] = token.split('.');
  expect(
    verify(
      'RSA-SHA256',
      Buffer.from(`${header}.${payload}`),
      createPublicKey({ key: jwks.keys[0]!, format: 'jwk' }),
      Buffer.from(signature!, 'base64url'),
    ),
  ).toBe(true);
  const claims = new JWTManager(emulator.url, { privateKey }).verify(token);
  expect(claims.iss).toBe(`${emulator.url}/user_management/${CLIENT_ID}`);
  expect(claims.aud).toBe(CLIENT_ID);
  expect(claims.sub).toBe('user_lifetime');
  expect(claims.org_id).toBe('org_lifetime');
  return claims;
}

describe('human AuthKit access-token lifetime', () => {
  it('keeps default and configured instances independent through login, refresh and reset', async () => {
    const configured = options(60);
    const short = await createEmulator(configured);
    let standard: Emulator | undefined;
    try {
      standard = await createEmulator(options());
      configured.authKitAccessTokenTtlSeconds = 120;
      const results = await Promise.allSettled(
        [short, standard].map(async (emulator) => {
          const expected = emulator === short ? 60 : 3600;
          const login = await authenticate(emulator);
          const first = await verifyAccess(emulator, login.access_token);
          expect(first.exp - first.iat).toBe(expected);
          const rotated = await authenticate(emulator, login.refresh_token);
          expect(rotated.refresh_token !== login.refresh_token).toBe(true);
          const renewed = await verifyAccess(emulator, rotated.access_token);
          expect(renewed.exp - renewed.iat).toBe(expected);
          expect(renewed.sid).toBe(first.sid);
          const widgetResponse = await fetch(`${emulator.url}/widgets/token`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${emulator.apiKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              organization_id: 'org_lifetime',
              user_id: 'user_lifetime',
              scopes: ['widgets:users-table:manage'],
            }),
          });
          expect(widgetResponse.status).toBe(201);
          const widget = (await widgetResponse.json()) as { token: string };
          const widgetClaims = new JWTManager(emulator.url, { privateKey }).verify(widget.token);
          expect(widgetClaims.exp - widgetClaims.iat).toBe(3600);
          emulator.reset();
          const reset = await authenticate(emulator);
          const resetClaims = await verifyAccess(emulator, reset.access_token);
          expect(resetClaims.exp - resetClaims.iat).toBe(expected);
        }),
      );
      for (const result of results) {
        if (result.status === 'rejected') throw result.reason;
      }
    } finally {
      await standard?.close();
      await short.close();
    }
  });

  it.each([null, 0, -1, 0.5, NaN, Infinity, -Infinity, '60', true, Number.MAX_SAFE_INTEGER])(
    'rejects invalid lifetime %s before startup',
    async (value) => {
      await expect(createEmulator({ port: 0, authKitAccessTokenTtlSeconds: value as number })).rejects.toThrow(
        'authKitAccessTokenTtlSeconds',
      );
    },
  );

  it('expires unchanged genuine token bytes on real time and refreshes the same session', async () => {
    const emulator = await createEmulator(options(3));
    try {
      const login = await authenticate(emulator);
      const first = await verifyAccess(emulator, login.access_token);
      expect(first.exp - first.iat).toBe(3);
      // JWTManager rejects when the whole-second clock is strictly past exp.
      await setTimeout(Math.max(0, (first.exp + 1) * 1000 - Date.now()));
      expect(() => new JWTManager(emulator.url, { privateKey }).verify(login.access_token)).toThrow(
        'Token has expired',
      );
      const rotated = await authenticate(emulator, login.refresh_token);
      expect(rotated.refresh_token !== login.refresh_token).toBe(true);
      const renewed = await verifyAccess(emulator, rotated.access_token);
      expect(renewed.sid).toBe(first.sid);
      expect(renewed.exp).toBeGreaterThan(first.exp);
      expect(renewed.exp - renewed.iat).toBe(3);
    } finally {
      await emulator.close();
    }
  }, 10_000);
});
