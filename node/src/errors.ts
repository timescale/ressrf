export class RessrfBlockedError extends Error {
  readonly reason: string;

  constructor(reason: string, url?: string) {
    const message = url
      ? `ressrf: blocked request to ${url}: ${reason}`
      : `ressrf: blocked: ${reason}`;
    super(message);
    this.name = "RessrfBlockedError";
    this.reason = reason;
  }
}

export function isBlocked(error: unknown): error is RessrfBlockedError {
  return error instanceof RessrfBlockedError;
}
