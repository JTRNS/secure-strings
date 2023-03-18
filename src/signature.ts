import { timingSafeEqual } from "./lib/crypto/timingSafeEqual.js";
import * as b64url from "./lib/encoding/base64url.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

async function importSigningKey(
  secret: string,
  algorithm: HmacImportParams["hash"] = "SHA-256"
) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"]
  );
  return key;
}

async function cryptoSign(
  message: string | Uint8Array,
  secretKey: CryptoKey | string
): Promise<[Uint8Array, Uint8Array]> {
  const key =
    typeof secretKey === "string"
      ? await importSigningKey(secretKey)
      : secretKey;
  const data = typeof message === "string" ? enc.encode(message) : message;
  const signature = await crypto.subtle.sign("HMAC", key, data);
  return [data, new Uint8Array(signature)];
}

async function cryptoVerify(
  data: string | Uint8Array,
  signature: string | Uint8Array,
  secretKey: CryptoKey | string
) {
  const [, validSignature] = await cryptoSign(data, secretKey);
  const receivedSignature =
    typeof signature === "string" ? enc.encode(signature) : signature;
  return timingSafeEqual(receivedSignature, validSignature);
}

export type HmacHash = "SHA-256" | "SHA-384" | "SHA-512";

function isSupportedHashFunction(value: unknown): value is HmacHash {
  const algorithms: HmacHash[] = ["SHA-256", "SHA-384", "SHA-512"];
  return typeof value === "string" && algorithms.includes(value as HmacHash);
}

function algorithmByteLength(value: string | HmacHash) {
  if (!isSupportedHashFunction(value)) return 32;
  return parseInt(value.split("-")[1]) / 8;
}

export async function verify(signedMessage: string, secret: string) {
  const sessionBytes = b64url.decode(signedMessage);
  const algorithmBytes = sessionBytes.subarray(0, 7);
  const algorithmName = dec.decode(algorithmBytes);
  const algorithmLength = algorithmByteLength(algorithmName);
  const sessionData = sessionBytes.subarray(
    7,
    sessionBytes.byteLength - algorithmLength
  );
  const sessionSignature = sessionBytes.subarray(
    sessionBytes.byteLength - algorithmLength
  );
  return cryptoVerify(sessionData, sessionSignature, secret);
}

export async function sign(
  message: string,
  secret: string,
  algorithm: HmacHash = "SHA-256"
) {
  const [data, signature] = await cryptoSign(message, secret);
  const algorithmBytes = enc.encode(algorithm);
  const sessionBytes = new Uint8Array(
    algorithmBytes.byteLength + data.byteLength + signature.byteLength
  );
  sessionBytes.set(algorithmBytes, 0);
  sessionBytes.set(data, algorithmBytes.byteLength);
  sessionBytes.set(signature, algorithmBytes.byteLength + data.byteLength);
  return b64url.encode(sessionBytes);
}
