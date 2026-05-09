import { type Policy } from "../policy.js";
import { createConnection, type ConnectOptions } from "./tcp.js";

export interface SafeSshConnectOptions {
  host: string;
  port?: number;
  username?: string;
  privateKey?: string | Buffer;
  password?: string;
  timeout?: number;
}

/**
 * Establish an SSH connection through a policy-validated TCP socket.
 * Uses ssh2's `sock` option to pass a pre-connected, pre-validated socket.
 *
 * Dynamically imports ssh2 to avoid hard dependency.
 */
export async function safeSshConnect(
  policy: Policy,
  options: SafeSshConnectOptions,
): Promise<unknown> {
  const connectOpts: ConnectOptions = {
    host: options.host,
    port: options.port ?? 22,
    timeout: options.timeout,
  };

  const socket = await createConnection(policy, connectOpts);

  const { Client } = await import("ssh2");

  return new Promise((resolve, reject) => {
    const client = new Client();

    client.on("ready", () => resolve(client));
    client.on("error", (err: Error) => {
      socket.destroy();
      reject(err);
    });

    client.connect({
      sock: socket,
      username: options.username,
      privateKey: options.privateKey,
      password: options.password,
    });
  });
}
