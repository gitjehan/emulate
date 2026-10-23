/** Typed keys for Store.getData/setData */
export const STORE_KEYS = {
  workosStore: '_workos_store',
  eventBus: 'eventBus',
  apiKeyMap: 'apiKeyMap',
  jwtTemplate: 'jwt_template',
  /** The seed's `sessionSettings`: production's Sessions tab, which has no API of its own. */
  sessionSettings: 'session_settings',
  interactiveAuth: 'interactiveAuth',
  /** Set alongside interactiveAuth when the AuthKit login page should also ask for a password. */
  interactivePassword: 'interactivePassword',
  allowedRedirectHosts: 'allowedRedirectHosts',
} as const;

/** Prefix for dynamic store keys */
export const STORE_KEY_PREFIXES = {
  pendingAuth: 'pending_auth:',
  /** A password the interactive page has checked, carried across the organization page instead of the password itself. */
  interactiveLogin: 'interactive_login:',
  /** A validated `/oauth2/authorize` request, waiting on the hosted sign-in it redirected to. */
  connectAuthorize: 'connect_authorize:',
  ssoToken: 'sso_token:',
  ssoLogout: 'sso_logout:',
  auditSchema: 'audit_schema_',
  radarIpList: 'radar_ip_list',
} as const;

/**
 * Resource type a permission or role is scoped to when the caller supplies
 * none. Production scopes both to the built-in `organization` resource type by
 * default; the emulator does the same so every response carries the
 * spec-required `resource_type_slug`.
 */
export const DEFAULT_RESOURCE_TYPE_SLUG = 'organization';

/**
 * Lifetime of the access token `/user_management/authenticate` mints when the seed's
 * `sessionSettings` sets none: five minutes, the default "Access token duration" on an
 * application's Sessions tab in the dashboard. The refresh token carries the session past it.
 */
export const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 300;

/**
 * Technical ceiling on a seeded access-token lifetime, not a production limit: it keeps `exp`
 * a safe integer once the current time is added, so the signed value is exactly the requested
 * lifetime. The 32-bit figure is otherwise arbitrary; nothing a test wants is anywhere near it.
 */
export const MAX_ACCESS_TOKEN_TTL_SECONDS = 2 ** 31 - 1;

/**
 * `resource_type_slug` is optional wherever the emulator accepts it (create
 * DTOs and seed entries), but a supplied value must be a non-empty string.
 * Resource types are not modeled, so the slug is not checked against a
 * registry the way production does.
 */
export function isValidResourceTypeSlug(value: unknown): value is string | undefined {
  return value === undefined || (typeof value === 'string' && value.length > 0);
}

/**
 * WorkOS event catalog, generated from the OpenAPI spec.
 * Regenerate with: npm run gen:events -- path/to/open-api-spec.yaml
 */
export {
  EVENTS,
  SUBSCRIBABLE_EVENTS,
  EVENT_DATA_REQUIREMENTS,
  type WorkOSEventName,
  type AuthenticationEventData,
} from './generated/events.js';
