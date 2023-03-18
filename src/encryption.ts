import * as b64url from "./lib/encoding/base64url.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

function genSalt(length = 16) {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function deriveKey(
  password: string,
  salt?: Uint8Array
): Promise<[CryptoKey, Uint8Array]> {
  const importedKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  salt = salt || genSalt();

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 90000,
      hash: "SHA-256",
    },
    importedKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return [derivedKey, salt];
}

export async function encrypt(plaintext: string, password: string) {
  const [key, salt] = await deriveKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = enc.encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
  const cipherBytes = new Uint8Array(ciphertext);
  const buffer = new Uint8Array(
    salt.byteLength + iv.byteLength + cipherBytes.byteLength
  );
  buffer.set(salt, 0);
  buffer.set(iv, salt.byteLength);
  buffer.set(cipherBytes, salt.byteLength + iv.byteLength);
  return b64url.encode(buffer);
}

export async function decrypt(cipher: string, password: string) {
  const bytes = new Uint8Array(b64url.decode(cipher));
  const salt = bytes.subarray(0, 16);
  const iv = bytes.subarray(16, 16 + 12);
  const data = bytes.subarray(16 + 12);
  const [key] = await deriveKey(password, salt);
  const decryptedBytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
  return dec.decode(decryptedBytes);
}
