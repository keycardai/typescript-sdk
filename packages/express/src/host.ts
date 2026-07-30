import type { Request } from "express";

/**
 * Returns the request's host (`hostname[:port]`) with Express 5 semantics on
 * every supported Express version.
 *
 * Express 5's `req.host` is the forwarded-aware source header value,
 * including any explicit port. Express 4's `req.host` is an alias for
 * `req.hostname` and strips the port, which breaks origin comparisons and
 * RFC 9728 `resource` values on nonstandard ports. When `req.host` carries
 * no port, this helper re-reads the same header Express derived it from
 * (`X-Forwarded-Host` when the connection is trusted per the app's
 * `trust proxy` setting, else `Host`) so an explicit port is preserved.
 *
 * The header value is only used when its hostname matches `req.host`, so the
 * result never diverges from the host Express itself resolved.
 *
 * Trust model: this inherits Express's own. Without a `trust proxy`
 * setting, `req.host` (hostname and therefore the recovered port) comes
 * from the client-supplied Host header, so origin comparisons and
 * advertised resource URLs are only as trustworthy as that header. Apps
 * behind a proxy must configure `trust proxy` for these values to reflect
 * the public-facing host.
 *
 * Reading `req.host` emits a one-time depd deprecation warning on
 * Express 4. It is deliberate: `req.hostname` strips the port on both
 * majors, and the port is the point.
 */
export function getRequestHost(req: Request): string {
  const host = req.host;
  if (!host || hasExplicitPort(host)) {
    return host;
  }
  const source = hostSourceHeader(req);
  if (
    source &&
    hasExplicitPort(source) &&
    stripPort(source).toLowerCase() === host.toLowerCase()
  ) {
    return source;
  }
  return host;
}

/**
 * `${protocol}://${host}` for the request, with the port included whenever
 * the source header carries one (both Express 4 and 5).
 */
export function getRequestOrigin(req: Request): string {
  return `${req.protocol}://${getRequestHost(req)}`;
}

/**
 * The header Express derives `req.host` from: the first `X-Forwarded-Host`
 * value when the connection is trusted, the `Host` header otherwise.
 * Mirrors the precedence in Express's own `req.host` getter.
 */
function hostSourceHeader(req: Request): string | undefined {
  const forwardedHost = req.get("x-forwarded-host");
  if (forwardedHost && isTrustedProxy(req)) {
    // X-Forwarded-Host is normally a single value; take the first entry the
    // same way Express does when multiple proxies append to it.
    return forwardedHost.split(",")[0]?.trim();
  }
  return req.get("host");
}

function isTrustedProxy(req: Request): boolean {
  // "trust proxy fn" is the compiled trust function Express itself consults
  // when deriving req.host/req.hostname from X-Forwarded-Host. The setting
  // name is identical in Express 4 and 5.
  const trust: unknown = req.app?.get?.("trust proxy fn");
  if (typeof trust !== "function") {
    return false;
  }
  // Narrow the untyped app setting to the compiled trust function's shape.
  const trustFn = trust as (addr: string | undefined, index: number) => unknown;
  return Boolean(trustFn(req.socket?.remoteAddress, 0));
}

function hasExplicitPort(host: string): boolean {
  // Bracketed IPv6 literals contain colons; only look after the bracket.
  const offset = host.startsWith("[") ? host.indexOf("]") + 1 : 0;
  return host.indexOf(":", offset) !== -1;
}

function stripPort(host: string): string {
  const offset = host.startsWith("[") ? host.indexOf("]") + 1 : 0;
  const index = host.indexOf(":", offset);
  return index === -1 ? host : host.slice(0, index);
}
