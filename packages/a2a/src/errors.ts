/** A delegation endpoint or origin configuration that cannot be used. */
export class A2ADiscoveryError extends Error {
  readonly retryable = false;

  constructor(message: string) {
    super(message);
    this.name = "A2ADiscoveryError";
  }
}
