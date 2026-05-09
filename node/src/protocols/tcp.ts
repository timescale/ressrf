import * as net from "node:net";
import * as dns from "node:dns";
import { type Policy } from "../policy.js";
import { RessrfBlockedError } from "../errors.js";

export interface ConnectOptions {
  host: string;
  port: number;
  timeout?: number;
}

/**
 * Resolve a hostname via DNS and validate all returned IPs against the policy.
 * Returns the list of allowed IP addresses.
 */
export async function resolveSafe(
  policy: Policy,
  host: string,
): Promise<string[]> {
  if (net.isIP(host)) {
    policy.isNetworkAllowed([host]);
    return [host];
  }

  const addresses = await new Promise<string[]>((resolve, reject) => {
    dns.resolve(host, (err, addrs) => {
      if (err) {
        dns.resolve6(host, (err6, addrs6) => {
          if (err6) reject(err);
          else resolve(addrs6);
        });
      } else {
        dns.resolve6(host, (err6, addrs6) => {
          if (err6) resolve(addrs);
          else resolve([...addrs, ...addrs6]);
        });
      }
    });
  });

  if (addresses.length === 0) {
    throw new Error(`ressrf: DNS resolution returned no addresses for ${host}`);
  }

  policy.isNetworkAllowed(addresses);
  return addresses;
}

/**
 * Create a TCP connection to the given host:port, validating the resolved
 * IP addresses against the policy before connecting.
 */
export async function createConnection(
  policy: Policy,
  options: ConnectOptions,
): Promise<net.Socket> {
  const addresses = await resolveSafe(policy, options.host);

  return new Promise<net.Socket>((resolve, reject) => {
    const socket = net.createConnection(
      {
        host: addresses[0],
        port: options.port,
        timeout: options.timeout,
      },
      () => resolve(socket),
    );
    socket.on("error", reject);
  });
}

export type DnsLookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string,
  family: number,
) => void;

export type DnsLookupAllCallback = (
  err: NodeJS.ErrnoException | null,
  addresses: Array<{ address: string; family: number }>,
) => void;

/**
 * Returns a dns.lookup-compatible function that validates resolved IPs
 * against the policy. Suitable for use with net.connect({ lookup }) or
 * http.Agent({ lookup }).
 */
export function dnsLookup(
  policy: Policy,
): (
  hostname: string,
  options: dns.LookupOptions,
  callback: DnsLookupCallback | DnsLookupAllCallback,
) => void {
  return (
    hostname: string,
    options: dns.LookupOptions,
    callback: DnsLookupCallback | DnsLookupAllCallback,
  ) => {
    dns.lookup(hostname, options, (err, addressOrAddresses, familyOrUndefined) => {
      if (err) {
        (callback as DnsLookupCallback)(err, "", 0);
        return;
      }

      try {
        if (Array.isArray(addressOrAddresses)) {
          const addrs = addressOrAddresses as Array<{
            address: string;
            family: number;
          }>;
          const ips = addrs.map((a) => a.address);
          policy.isNetworkAllowed(ips);
          (callback as DnsLookupAllCallback)(null, addrs);
        } else {
          const address = addressOrAddresses as string;
          policy.isNetworkAllowed([address]);
          (callback as DnsLookupCallback)(
            null,
            address,
            familyOrUndefined as number,
          );
        }
      } catch (e) {
        const error =
          e instanceof RessrfBlockedError
            ? Object.assign(new Error(e.message), { code: "ECONNREFUSED" })
            : (e as Error);
        (callback as DnsLookupCallback)(
          error as NodeJS.ErrnoException,
          "",
          0,
        );
      }
    });
  };
}
