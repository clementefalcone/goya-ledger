import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const nodeUrl = process.env.NODE_URL ?? 'http://127.0.0.1:9700/api/v1';
const seedPath = process.env.ISSUER_SEED_PATH ?? new URL('./issuer-seed.hex', import.meta.url).pathname;

function loadIssuer() {
  if (!existsSync(seedPath)) {
    throw new Error(`issuer seed not found at ${seedPath}; run "node issuer.mjs keygen" first`);
  }
  const { publicKey, secretKey } = ml_dsa65.keygen(hexToBytes(readFileSync(seedPath, 'utf8').trim()));
  return { publicKey, secretKey, did: `did:goya:${bytesToHex(sha3_512(publicKey))}` };
}

function sign(secretKey, message) {
  return bytesToHex(ml_dsa65.sign(utf8ToBytes(message), secretKey));
}

async function call(method, path, body) {
  const response = await fetch(`${nodeUrl}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(`${method} ${path} failed with ${response.status}: ${JSON.stringify(payload.error ?? payload)}`);
  }
  return payload.data;
}

function keygen() {
  if (existsSync(seedPath)) {
    throw new Error(`refusing to overwrite existing issuer seed at ${seedPath}`);
  }
  writeFileSync(seedPath, bytesToHex(randomBytes(32)), { mode: 0o600 });
  console.log(loadIssuer().did);
}

async function register() {
  const issuer = loadIssuer();
  const now = Math.floor(Date.now() / 1000);
  await call('POST', '/store/identities', {
    did: issuer.did,
    public_key: bytesToHex(issuer.publicKey),
    signature_algorithm: 'MlDsa65',
    created_at: now,
    updated_at: now,
    status: 'active',
    signature: sign(issuer.secretKey, `identity:register:${issuer.did}`),
  });
  console.log(issuer.did);
}

async function mint(to, amountText) {
  const amount = Number(amountText);
  if (!to || !Number.isSafeInteger(amount) || amount <= 0) {
    throw new Error(`usage: node issuer.mjs mint <recipient-did> <positive-integer-amount>, got "${to}" "${amountText}"`);
  }
  const issuer = loadIssuer();
  const { nonce } = await call('GET', '/accounts/0');
  const tx = await call('POST', '/transactions', {
    from: '0',
    to,
    amount,
    nonce,
    signature: sign(issuer.secretKey, `transfer:0:${to}:${amount}:${nonce}`),
  });
  console.log(JSON.stringify({ id: tx.id, to, amount, nonce }));
}

const commands = {
  keygen: () => keygen(),
  did: () => console.log(loadIssuer().did),
  register: () => register(),
  mint: (to, amount) => mint(to, amount),
};

const [command, ...args] = process.argv.slice(2);
const run = commands[command];
if (!run) {
  console.error(`unknown command "${command}"; expected one of: ${Object.keys(commands).join(', ')}`);
  process.exit(2);
}
await run(...args);
