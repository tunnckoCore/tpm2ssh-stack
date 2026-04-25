import { readFileSync } from "node:fs";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const privateKeyHex = "6931e64906920d930314067ab126dd520c5defa700626d608a2fa570801b0c26";
const publicKeyHex =
  "04d4544819157219e0ebd7ad4b707ff2007eba8819b5fcdceb059a595c8db9efd2cc8b12fd6a804afb8ee907eba649e0c76f768f821224d57057fb872041035e06";
const ethereumAddress = "0xF794a88C566b685Ac141e3002d6aF1A174EC4795";
const cliSignatureHex =
  "1252ead3a9b017fd211fb3499e39ca9ea8b8de56de2b5b81daa58fe27cdca4eb00cabb29d9b699e5750b3d962040af97e0480444be51cad7d98a8e92101a9701";

const privateKey = hexToBytes(privateKeyHex);
const publicKey = hexToBytes(publicKeyHex);
const cliSignature = hexToBytes(cliSignatureHex);
const cargoToml = readFileSync(new URL("../../../../Cargo.toml", import.meta.url));

const derivedPublicKey = secp256k1.getPublicKey(privateKey, false);

if (publicKeyHex !== bytesToHex(derivedPublicKey)) {
  console.error("public key mismatch");
  process.exit(1);
}
const derivedAddress = toChecksumAddress(keccak_256(derivedPublicKey.slice(1)).slice(-20));

if (ethereumAddress !== derivedAddress) {
  console.error("address mismatch");
  process.exit(1);
}

const nobleSignature = secp256k1.sign(cargoToml, privateKey, {
  // prehash: false,
  // lowS: false,
});

if (bytesToHex(nobleSignature) !== cliSignatureHex) {
  console.error("signature mismatch");
  process.exit(1);
}

const cliSignatureValid = secp256k1.verify(cliSignature, cargoToml, publicKey, {
  // prehash: false,
  // lowS: false,
});

const nobleSignatureValid = secp256k1.verify(nobleSignature, cargoToml, publicKey, {
  // prehash: false,
  // lowS: false,
});

if (cliSignatureValid !== nobleSignatureValid) {
  console.error("signature verification mismatch");
  process.exit(1);
}

console.log("all is fine with `secp256k1` cli derivation");

function toChecksumAddress(address: Uint8Array): string {
  const lower = bytesToHex(address);
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(lower)));
  let out = "0x";
  for (let i = 0; i < lower.length; i += 1) {
    const char = lower[i];
    const nibble = Number.parseInt(hash[i], 16);
    out += /[a-f]/.test(char) && nibble >= 8 ? char.toUpperCase() : char;
  }
  return out;
}
