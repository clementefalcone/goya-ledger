import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
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

function signedCredential(account, line) {
  const [id, subjectDid, credType, claimsJson, expiresText] = line.split('\t');
  const expiresAt = Number(expiresText);
  if (!id || !subjectDid || !credType || !claimsJson || !Number.isSafeInteger(expiresAt)) {
    throw new Error(`expected id<TAB>subject_did<TAB>cred_type<TAB>claims_json<TAB>expires_at, got "${line}"`);
  }
  const salt = bytesToHex(randomBytes(32));
  const claimsCommitment = bytesToHex(sha256(utf8ToBytes(`${salt}${JSON.stringify(JSON.parse(claimsJson))}`)));
  const issuedAt = Math.floor(Date.now() / 1000);
  return {
    id,
    issuer_did: account.did,
    subject_did: subjectDid,
    cred_type: credType,
    issued_at: issuedAt,
    expires_at: expiresAt,
    revoked_at: null,
    status: 'active',
    claims_commitment: claimsCommitment,
    issuer_public_key: bytesToHex(account.publicKey),
    signature: sign(
      account.secretKey,
      `credential:issue:${id}:${account.did}:${subjectDid}:${credType}:${issuedAt}:${expiresAt}:${claimsCommitment}`,
    ),
  };
}

function credentials() {
  const account = loadAccount();
  readFileSync(0, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .forEach((line) => console.log(JSON.stringify(signedCredential(account, line))));
}

function revocation(id, revokedAtText) {
  const account = loadAccount();
  const revokedAt = Number(revokedAtText);
  if (!id || !Number.isSafeInteger(revokedAt)) {
    throw new Error(`expected <credential-id> <revoked-at-epoch-seconds>, got "${id}" "${revokedAtText}"`);
  }
  console.log(JSON.stringify({
    revoked_at: revokedAt,
    issuer_public_key: bytesToHex(account.publicKey),
    signature: sign(account.secretKey, `credential:revoke:${id}:${revokedAt}`),
  }));
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
  credentials: () => credentials(),
  revocation: (id, revokedAt) => revocation(id, revokedAt),
};

const [command, ...args] = process.argv.slice(2);
const run = commands[command];
if (!run) {
  console.error(`unknown command "${command}"; expected one of: ${Object.keys(commands).join(', ')}`);
  process.exit(2);
}
await run(...args);
