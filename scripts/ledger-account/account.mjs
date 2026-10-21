import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const nodeUrl = process.env.NODE_URL ?? 'http://127.0.0.1:9700/api/v1';
const seedPath = process.env.SEED_PATH ?? new URL('./issuer-seed.hex', import.meta.url).pathname;

function loadAccount() {
  if (!existsSync(seedPath)) {
    throw new Error(`seed not found at ${seedPath}; run "node account.mjs keygen" first`);
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

function parseAmount(to, amountText) {
  const amount = Number(amountText);
  if (!to || !Number.isSafeInteger(amount) || amount <= 0) {
    throw new Error(`expected <recipient> <positive-integer-amount>, got "${to}" "${amountText}"`);
  }
  return amount;
}

async function submitTransfer(signer, from, to, amount) {
  const { nonce } = await call('GET', `/accounts/${from}`);
  const tx = await call('POST', '/transactions', {
    from,
    to,
    amount,
    nonce,
    signature: sign(signer.secretKey, `transfer:${from}:${to}:${amount}:${nonce}`),
  });
  console.log(JSON.stringify({ id: tx.id, from, to, amount, nonce }));
}

function keygen() {
  if (existsSync(seedPath)) {
    throw new Error(`refusing to overwrite existing seed at ${seedPath}`);
  }
  writeFileSync(seedPath, bytesToHex(randomBytes(32)), { mode: 0o600 });
  console.log(loadAccount().did);
}

async function register() {
  const account = loadAccount();
  const now = Math.floor(Date.now() / 1000);
  await call('POST', '/store/identities', {
    did: account.did,
    public_key: bytesToHex(account.publicKey),
    signature_algorithm: 'MlDsa65',
    created_at: now,
    updated_at: now,
    status: 'active',
    signature: sign(account.secretKey, `identity:register:${account.did}`),
  });
  console.log(account.did);
}

async function mint(to, amountText) {
  await submitTransfer(loadAccount(), '0', to, parseAmount(to, amountText));
}

async function transfer(to, amountText) {
  const account = loadAccount();
  await submitTransfer(account, account.did, to, parseAmount(to, amountText));
}

const commands = {
  keygen: () => keygen(),
  did: () => console.log(loadAccount().did),
  register: () => register(),
  mint: (to, amount) => mint(to, amount),
  transfer: (to, amount) => transfer(to, amount),
};

const [command, ...args] = process.argv.slice(2);
const run = commands[command];
if (!run) {
  console.error(`unknown command "${command}"; expected one of: ${Object.keys(commands).join(', ')}`);
  process.exit(2);
}
await run(...args);
