// dashboard/lib/ssh.ts
import { Client } from 'ssh2';

export interface SSHParams {
  host: string;
  port?: number;
  username: string;
  password?: string;
  privateKey?: string;
  vendor?: string;
  timeoutMs?: number;
  enablePty?: boolean;
  allowLegacyCrypto?: boolean;
}

/**
 * Executes CLI commands over SSH using an interactive shell channel for network hardware compatibility.
 */
export async function executeCLICommands(
  params: SSHParams,
  commands: string[]
) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let output = '';
    let isSettled = false;
    const timeout = params.timeoutMs || 20000;

    const cleanup = () => {
      clearTimeout(timer);
      conn.removeAllListeners();
      try {
        conn.destroy();
      } catch {
        // Socket already closed
      }
    };

    const timer = setTimeout(() => {
      if (isSettled) return;
      isSettled = true;
      cleanup();
      reject(new Error(`SSH execution timed out after ${timeout}ms on ${params.host}`));
    }, timeout);

    // Prepend terminal pagination suppression based on vendor
    const normalizedVendor = (params.vendor || '').toLowerCase();
    const preparedCommands: string[] = [];

    if (normalizedVendor.includes('juniper') || normalizedVendor.includes('junos')) {
      preparedCommands.push('set cli screen-length 0');
    } else if (normalizedVendor.includes('fortinet') || normalizedVendor.includes('fortios')) {
      preparedCommands.push('config system console\n set output standard\n end');
    } else if (!normalizedVendor.includes('generic')) {
      // Default Cisco IOS / NX-OS / Arista / Dell / HPE pagination disable
      preparedCommands.push('terminal length 0');
    }

    preparedCommands.push(...commands, 'exit');

    conn
      .on('ready', () => {
        // Network hardware requires pseudo-terminal (PTY) shell allocations
        conn.shell({ term: 'vt100', cols: 300, rows: 1000 }, (err, stream) => {
          if (err) {
            if (!isSettled) {
              isSettled = true;
              cleanup();
              reject(err);
            }
            return;
          }

          stream
            .on('close', () => {
              if (!isSettled) {
                isSettled = true;
                cleanup();
                resolve(output);
              }
            })
            .on('data', (data: Buffer) => {
              output += data.toString('utf8');
            })
            .stderr.on('data', (data: Buffer) => {
              output += data.toString('utf8');
            });

          // Pipe commands sequentially into the interactive shell stream
          const payload = preparedCommands.join('\n') + '\n';
          stream.write(payload);
        });
      })
      .on('error', (err: Error) => {
        if (!isSettled) {
          isSettled = true;
          cleanup();
          reject(err);
        }
      })
      .connect({
        host: params.host,
        port: params.port || 22,
        username: params.username,
        password: params.password,
        privateKey: params.privateKey,
        readyTimeout: 10000,
        algorithms: {
          kex: [
            'curve25519-sha256',
            'ecdh-sha2-nistp256',
            'diffie-hellman-group14-sha1',
            ...(params.allowLegacyCrypto ? (['diffie-hellman-group1-sha1'] as const) : []),
          ],
          cipher: [
            'aes128-ctr',
            'aes192-ctr',
            'aes256-ctr',
            'aes128-cbc',
            ...(params.allowLegacyCrypto ? (['3des-cbc'] as const) : []),
          ],
          serverHostKey: [
            'ssh-ed25519',
            'ecdsa-sha2-nistp256',
            'rsa-sha2-512',
            'rsa-sha2-256',
            'ssh-rsa',
          ],
        },
      });
  });
}