import path from 'path';
import crypto from 'crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { generate } from 'selfsigned';
import { getCodemiePath } from '../../../../utils/paths.js';

export interface ProxyTLSConfig {
  key: string;
  cert: string;
  certPath: string;
}

const TLS_SUBDIR = 'proxy-tls';
const CERT_FILE = 'cert.pem';
const KEY_FILE = 'key.pem';
const CERT_VALIDITY_DAYS = 365;
const RENEWAL_BUFFER_DAYS = 30;

export function getProxyCertPath(): string {
  return getCodemiePath(TLS_SUBDIR, CERT_FILE);
}

export async function getOrGenerateProxyCert(): Promise<ProxyTLSConfig> {
  const certDir = getCodemiePath(TLS_SUBDIR);
  const keyPath = path.join(certDir, KEY_FILE);
  const certPath = path.join(certDir, CERT_FILE);

  try {
    const [key, cert] = await Promise.all([
      readFile(keyPath, 'utf8'),
      readFile(certPath, 'utf8'),
    ]);
    const x509 = new crypto.X509Certificate(cert);
    const expiresAt = new Date(x509.validTo).getTime();
    if (expiresAt - Date.now() > RENEWAL_BUFFER_DAYS * 24 * 60 * 60 * 1000) {
      return { key, cert, certPath };
    }
  } catch {
    // Fall through to generate new certificate
  }

  const notAfterDate = new Date();
  notAfterDate.setDate(notAfterDate.getDate() + CERT_VALIDITY_DAYS);
  const pems = await generate([{ name: 'commonName', value: 'localhost' }], {
    keySize: 2048,
    algorithm: 'sha256',
    notAfterDate,
    extensions: [
      {
        name: 'subjectAltName',
        altNames: [
          { type: 2, value: 'localhost' },
          { type: 7, ip: '127.0.0.1' },
          { type: 7, ip: '::1' },
        ],
      },
    ],
  });

  await mkdir(certDir, { recursive: true, mode: 0o700 });
  await Promise.all([
    writeFile(keyPath, pems.private, { mode: 0o600 }),
    writeFile(certPath, pems.cert, { mode: 0o644 }),
  ]);

  return { key: pems.private, cert: pems.cert, certPath };
}
