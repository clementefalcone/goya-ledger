import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessFile } from "./q-day.js";

const workDir = mkdtempSync(join(tmpdir(), "q-day-"));

function openssl(...args) {
  execFileSync("openssl", args, { cwd: workDir, stdio: "pipe" });
}

function issueSelfSigned(name, algorithmArgs) {
  openssl("genpkey", ...algorithmArgs, "-out", `${name}.key`);
  openssl("req", "-x509", "-key", `${name}.key`, "-out", `${name}.pem`, "-subj", `/CN=${name}`, "-days", "1");
  return `${name}.pem`;
}

function signCms(name, certificate) {
  writeFileSync(join(workDir, "contract.txt"), "contrato de prueba");
  openssl("cms", "-sign", "-binary", "-in", "contract.txt", "-signer", certificate, "-inkey", `${name}.key`, "-outform", "DER", "-out", `${name}.p7s`);
  return readFileSync(join(workDir, `${name}.p7s`));
}

function readFixture(file) {
  return new Uint8Array(readFileSync(join(workDir, file)));
}

test("RSA certificate is vulnerable", () => {
  const result = assessFile(readFixture(issueSelfSigned("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])));
  assert.equal(result.verdict, "vulnerable");
  assert.deepEqual(result.algorithms, ["RSA"]);
});

test("ECDSA certificate is vulnerable", () => {
  const result = assessFile(readFixture(issueSelfSigned("ec", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])));
  assert.equal(result.verdict, "vulnerable");
  assert.deepEqual(result.algorithms, ["ECDSA"]);
});

test("Ed25519 certificate is vulnerable", () => {
  const result = assessFile(readFixture(issueSelfSigned("ed", ["-algorithm", "ED25519"])));
  assert.deepEqual(result.algorithms, ["Ed25519"]);
});

test("ML-DSA-65 certificate is quantum safe", () => {
  const result = assessFile(readFixture(issueSelfSigned("mldsa", ["-algorithm", "ML-DSA-65"])));
  assert.equal(result.verdict, "safe");
  assert.deepEqual(result.algorithms, ["ML-DSA-65"]);
});

test("PDF signature contents are extracted and carry the signing time", () => {
  const signature = signCms("pdfsigner", issueSelfSigned("pdfsigner", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]));
  const paddedHex = Buffer.concat([signature, Buffer.alloc(64)]).toString("hex");
  const pdf = `%PDF-1.7\n1 0 obj\n<< /Type /Sig /ByteRange [0 10 20 30] /Contents <${paddedHex}> >>\nendobj\n%%EOF`;
  const result = assessFile(new TextEncoder().encode(pdf));
  assert.equal(result.verdict, "vulnerable");
  assert.equal(result.signatureCount, 1);
  assert.equal(result.signingTimes.length, 1);
  assert.ok(Math.abs(result.signingTimes[0] - Date.now()) < 60_000);
});

test("PDF without signatures has no verdict on algorithms", () => {
  const result = assessFile(new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<< /Contents 2 0 R >>\nendobj\n%%EOF"));
  assert.equal(result.verdict, "none");
  assert.equal(result.signatureCount, 0);
});

test("certificate chain mixing ML-DSA and RSA is hybrid", () => {
  const bundle = readFileSync(join(workDir, "mldsa.pem"), "utf8") + readFileSync(join(workDir, "rsa.pem"), "utf8");
  assert.equal(assessFile(new TextEncoder().encode(bundle)).verdict, "hybrid");
});

test("truncated DER is rejected with the offending offset", () => {
  assert.throws(() => assessFile(Uint8Array.from([0x30, 0x10, 0x06, 0x01])), /ASN\.1 length 16 at offset 0/);
});
