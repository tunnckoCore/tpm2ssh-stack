import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const privateKeyHex = "91cf4c92929b222c00e405453b663bea60f8e2151464e46d02b4fedb252f9b8c";
const publicKeyHex = "830cce93408db32aea1acb9a25fe22a04fba3b0e227c5a71447b7e37be326edb";
const cliSignatureHex =
  "354b1dbf7f08b1df084eb50bf9b91135c602c0f4c17979cee6e03acf5b49405b6f767fe04af89eae7d39d82dce7282df4f6eb8346dbd66450f8fa6fbd9459101";

const privateKey = hexToBytes(privateKeyHex);
const publicKey = hexToBytes(publicKeyHex);
const cliSignature = hexToBytes(cliSignatureHex);
const cargoToml = readFileSync(new URL("../../../../Cargo.toml", import.meta.url));

const derivedPublicKey = ed25519.getPublicKey(privateKey);

if (publicKeyHex !== bytesToHex(derivedPublicKey)) {
  console.error("public key mismatch");
  process.exit(1);
}

const nobleSignature = ed25519.sign(cargoToml, privateKey);

if (bytesToHex(nobleSignature) !== cliSignatureHex) {
  console.error("signature mismatch");
  process.exit(1);
}

const cliSignatureValid = ed25519.verify(cliSignature, cargoToml, publicKey);
const nobleSignatureValid = ed25519.verify(nobleSignature, cargoToml, publicKey);

if (cliSignatureValid !== nobleSignatureValid) {
  console.error("signature verification mismatch");
  process.exit(1);
}

console.log("all is fine with `ed25519` cli derivation");
