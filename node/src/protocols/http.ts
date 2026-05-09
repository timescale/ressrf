import * as http from "node:http";
import * as https from "node:https";
import { URL } from "node:url";
import { type Policy } from "../policy.js";
import { RessrfBlockedError } from "../errors.js";
import { dnsLookup, resolveSafe } from "./tcp.js";

/**
 * Creates an http.Agent that validates DNS lookups against the SSRF policy.
 * Works with `http.request`.
 */
export function httpAgent(
  policy: Policy,
  options?: http.AgentOptions,
): http.Agent {
  return new http.Agent({
    ...options,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    lookup: dnsLookup(policy) as any,
  });
}

/**
 * Creates an https.Agent that validates DNS lookups against the SSRF policy.
 */
export function httpsAgent(
  policy: Policy,
  options?: https.AgentOptions,
): https.Agent {
  return new https.Agent({
    ...options,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    lookup: dnsLookup(policy) as any,
  });
}

/**
 * Validate a redirect target URL against the policy. Throws if the redirect
 * target resolves to a denied IP or uses a disallowed scheme.
 */
export function validateRedirect(policy: Policy, targetUrl: string): void {
  policy.isAllowed(targetUrl);
}

export interface SafeFetchOptions {
  policy: Policy;
  maxRedirects?: number;
}

/**
 * A fetch-like wrapper that validates each redirect hop against the policy.
 * Uses the global `fetch` (available in Node.js 18+) with `redirect: "manual"`.
 */
export async function safeFetch(
  url: string | URL,
  init: RequestInit & SafeFetchOptions,
): Promise<Response> {
  const { policy, maxRedirects = 10, ...fetchInit } = init;
  let currentUrl = typeof url === "string" ? url : url.href;
  let redirects = 0;

  // Validate the initial URL
  policy.isAllowed(currentUrl);

  // Pre-resolve DNS and validate IPs for the initial request
  const parsedUrl = new URL(currentUrl);
  await resolveSafe(policy, parsedUrl.hostname);

  while (true) {
    const response = await fetch(currentUrl, {
      ...fetchInit,
      redirect: "manual",
    });

    const status = response.status;
    if (status < 300 || status >= 400 || !response.headers.has("location")) {
      return response;
    }

    redirects++;
    if (redirects > maxRedirects) {
      throw new Error(`ressrf: exceeded maximum redirects (${maxRedirects})`);
    }

    const location = response.headers.get("location")!;
    const nextUrl = new URL(location, currentUrl);
    currentUrl = nextUrl.href;

    // Validate redirect target against policy
    policy.isAllowed(currentUrl);
    await resolveSafe(policy, nextUrl.hostname);
  }
}

export interface UndiciAgentOptions {
  policy: Policy;
  maxRedirects?: number;
}

/**
 * Creates an undici-compatible connect function that validates DNS resolution
 * against the policy. Dynamically imports undici to avoid hard dependency.
 *
 * Usage:
 *   import { Agent } from "undici";
 *   const agent = new Agent({ connect: undiciConnect(policy) });
 */
export function undiciConnect(
  policy: Policy,
): (
  opts: { hostname: string; port: string; protocol: string },
  callback: (err: Error | null, socket: unknown) => void,
) => void {
  return (opts, callback) => {
    const host = opts.hostname;
    resolveSafe(policy, host)
      .then(async (addresses) => {
        // Dynamic import: undici is an optional peer dependency
        const undici = await import("undici" as string);
        const connector = undici.buildConnector({});
        connector(
          { ...opts, hostname: addresses[0] } as Parameters<
            ReturnType<typeof undici.buildConnector>
          >[0],
          callback as Parameters<
            ReturnType<typeof undici.buildConnector>
          >[1],
        );
      })
      .catch((err: unknown) => {
        if (err instanceof RessrfBlockedError) {
          callback(err, null);
        } else {
          callback(err as Error, null);
        }
      });
  };
}
