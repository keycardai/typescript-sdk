/**
 * Offline test helpers.
 *
 * Nothing here touches the network: a fake zone client records the requests a
 * factory made, and the JWT builders produce decode-only fixtures. Import from
 * `@keycardai/eve/testing`.
 */
export {
  appPrincipal,
  bearerRequest,
  connectionContext,
  expiredJwt,
  fakeVerifier,
  fakeZoneClient,
  sessionAuthContext,
  unsignedJwt,
  userPrincipal,
  validJwt,
} from "./testUtils.js";
export type { FakeZoneClient, FakeZoneClientOptions, ZoneCalls } from "./testUtils.js";
