import { HTTPError, ResponseBodyTooLargeError } from "./errors.js";

export class MetadataRetry {
  #failure?: { error: unknown; until: number };
  #step = 1000;

  check(now: number): void {
    if (this.#failure && now < this.#failure.until) throw this.#failure.error;
    this.forgetExpired(now);
  }

  forgetExpired(now: number): void {
    if (this.#failure && now >= this.#failure.until) this.#failure = undefined;
  }

  record(error: unknown, cause: unknown, now: number, wallTime = Date.now()): boolean {
    let delay: number | undefined;
    const status = cause instanceof HTTPError
      ? cause.status ?? 0
      : cause instanceof ResponseBodyTooLargeError ? cause.status : undefined;
    if (status !== undefined) {
      if ((status === 429 || status === 503) && cause instanceof HTTPError) {
        delay = retryAfter(cause.retryAfter, wallTime);
      }
      // An oversized body is discarded unread, so it carries no Retry-After.
      if (delay === undefined && (status < 500 || status >= 600)) return false;
    }
    if (this.#failure && now < this.#failure.until &&
        (delay === undefined || now + delay <= this.#failure.until)) return false;

    if (delay === undefined) {
      delay = Math.min(30_000, this.#step * (0.8 + Math.random() * 0.4));
      this.#step = Math.min(64_000, this.#step * 2);
    }
    this.#failure = { error, until: now + delay };
    return true;
  }

  reset(): void {
    this.#failure = undefined;
    this.#step = 1000;
  }
}

export class MetadataRetryCache {
  #entries = new Map<string, MetadataRetry>();

  check(key: string, now: number): void {
    this.#entries.get(key)?.check(now);
  }

  record(key: string, error: unknown, cause: unknown, now: number, wallTime?: number): void {
    const retry = this.#entries.get(key) ?? new MetadataRetry();
    if (!retry.record(error, cause, now, wallTime)) return;
    for (const entry of this.#entries.values()) entry.forgetExpired(now);
    this.#entries.delete(key);
    this.#entries.set(key, retry);
    if (this.#entries.size > 128) {
      const oldest = this.#entries.keys().next();
      if (!oldest.done) this.#entries.delete(oldest.value);
    }
  }

  delete(key: string): void { this.#entries.delete(key); }
  clear(): void { this.#entries.clear(); }
}

const deterministicTransportCodes = new Set([
  "ERR_INVALID_URL", "ERR_INVALID_PROTOCOL", "ERR_TLS_CERT_ALTNAME_INVALID",
  "CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
]);

export function isTransientMetadataFailure(cause: unknown): boolean {
  if (cause instanceof ResponseBodyTooLargeError) return cause.retryable;
  if (!(cause instanceof HTTPError)) {
    const nested = cause instanceof Error ? (cause as Error & { cause?: unknown }).cause : undefined;
    if (nested instanceof Error) {
      const detail = nested as Error & { code?: string };
      if (detail.code && deterministicTransportCodes.has(detail.code)) return false;
      if (detail.message === "redirect count exceeded") return false;
    }
    return true;
  }
  const status = cause.status ?? 0;
  return status === 429 || (status >= 500 && status < 600);
}

function retryAfter(header: string | undefined, now: number): number | undefined {
  const value = header?.trim();
  if (!value) return undefined;
  if (/^\d+$/.test(value)) return Math.min(60, Number(value)) * 1000;
  const imf = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/;
  const obsolete = /^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-([A-Za-z]{3})-(\d{2}) (\d{2}:\d{2}:\d{2}) GMT$/.exec(value);
  const asctime = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) [A-Za-z]{3} (?: \d|\d{2}) \d{2}:\d{2}:\d{2} \d{4}$/;
  let date: number;
  if (obsolete) {
    const [, day, month, twoDigitYear, time] = obsolete;
    const latest = new Date(now);
    latest.setUTCFullYear(latest.getUTCFullYear() + 50);
    const year = Math.floor((latest.getUTCFullYear() - Number(twoDigitYear)) / 100) * 100 + Number(twoDigitYear);
    date = Date.parse(`${day} ${month} ${year} ${time} GMT`);
    if (date > latest.getTime()) date = Date.parse(`${day} ${month} ${year - 100} ${time} GMT`);
  } else if (asctime.test(value)) {
    date = Date.parse(`${value} GMT`);
  } else if (imf.test(value)) {
    date = Date.parse(value);
  } else {
    return undefined;
  }
  if (Number.isNaN(date)) return undefined;
  const parsed = new Date(date);
  const canonical = parsed.toUTCString();
  const [weekday, day, month, year, time] = canonical.replace(",", "").split(" ");
  if (obsolete) {
    const longWeekday = parsed.toLocaleDateString("en-US", { weekday: "long", timeZone: "UTC" });
    if (value !== `${longWeekday}, ${day}-${month}-${year.slice(-2)} ${time} GMT`) return undefined;
  } else if (asctime.test(value)) {
    const suffix = `${time} ${year}`;
    if (value !== `${weekday} ${month} ${day} ${suffix}` &&
        value !== `${weekday} ${month} ${day.replace(/^0/, " ")} ${suffix}`) return undefined;
  } else if (value !== canonical) {
    return undefined;
  }
  return Math.max(0, Math.min(60_000, date - now));
}
