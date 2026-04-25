import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const privateKeyHex = "e85927d24af4fc8c6a1948c9621f4868bd25244af981d3f14a6d1c7a87cbb70c";
const publicKeyHex =
  "04e7e08e020a5e082fdd7b10e43b4be813ae60f6ad54f34edb083f1ad59658b57953b00cc328a60beb6395b2db2a6983fc2d81fa40b2318d9b70a7926e115f523a";
const cliSignatureHex =
  "af6ad1b5ccfa5868810f98270dfc6a1e7d894b17ebf875ca9871e11119fff9d893faa8ff820002eba3f5f97095cf192ee966b5affad53c1679ee7037a1b61c62";

const privateKey = hexToBytes(privateKeyHex);
const publicKey = hexToBytes(publicKeyHex);
const cliSignature = hexToBytes(cliSignatureHex);
const cargoToml = readFileSync(new URL("../../../../Cargo.toml", import.meta.url));

const derivedPublicKey = p256.getPublicKey(privateKey, false);

if (publicKeyHex !== bytesToHex(derivedPublicKey)) {
  console.error("public key mismatch");
  process.exit(1);
}

const digest = sha256(cargoToml);
const nobleSignature = p256.sign(digest, privateKey, {
  prehash: false,
  lowS: false,
});

if (bytesToHex(nobleSignature) !== cliSignatureHex) {
  console.error("signature mismatch");
  process.exit(1);
}

const cliSignatureValid = p256.verify(cliSignature, digest, publicKey, {
  prehash: false,
  lowS: false,
});

const nobleSignatureValid = p256.verify(nobleSignature, digest, publicKey, {
  prehash: false,
  lowS: false,
});

if (cliSignatureValid !== nobleSignatureValid) {
  console.error("signature verification mismatch");
  process.exit(1);
}

console.log("all is fine with `p256` cli derivation");
