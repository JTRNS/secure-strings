import {joinBytes, splitBytes} from './byte_array.js';
import {
  SecureHashingAlgorithm,
  genIv,
  genSalt,
  hashFunctionByteLength,
} from './crypto_utils.js';
import {
  decodedBytes,
  encodedString,
  utf8Decode,
  utf8Encode,
} from './encoding.js';

export interface PbkdfOptions {
  /** The internal hashing algorithm used during key derivation.
   * @default "SHA-384"
   */
  algorithm: SecureHashingAlgorithm;
  /** Recommended **minimum** iterations:
   *  - PBKDF2-HMAC-SHA256: 600.000 iterations
   *  - PBKDF2-HMAC-SHA384: 405.000 iterations
   *  - PBKDF2-HMAC-SHA512: 210.000 iterations
   * @default 900001
   */
  iterations: number;
  /**
   * Encoding to use for the output string.
   * @default "hex"
   */
  encoding: 'hex' | 'base64url';
}

const DEFAULT_DERIVATION_OPTIONS: PbkdfOptions = {
  algorithm: 'SHA-384',
  iterations: 900001,
  encoding: 'hex',
};

function assignDerivationOptionDefaults(
  options: Partial<PbkdfOptions> = {}
): Required<PbkdfOptions> {
  return Object.assign({}, DEFAULT_DERIVATION_OPTIONS, options);
}

/**
 * Encrypts the given plaintext using AES-GCM encryption.
 * @param {string} plaintext - The plaintext to encrypt.
 * @param {string} password - The password to use for encryption.
 * @param {Partial<PbkdfOptions>} [options] - Optional parameters for key derivation.
 * @returns {Promise<string>} Promise that resolves to the encrypted ciphertext.
 *
 * @example
 * ```typescript
 * const plaintext = 'Hello World!';
 * const secret = 'my secret password';
 * const ciphertext = await encrypt(plaintext, secret);
 * console.log(ciphertext);
 * ```
 *
 * {@link https://csrc.nist.gov/publications/detail/sp/800-38d/final AES-GCM}
 */
export async function encrypt(
  plaintext: string,
  password: string,
  options?: Partial<PbkdfOptions>
) {
  const internalOptions = assignDerivationOptionDefaults(options);
  const [key, salt] = await deriveKey(password, internalOptions);
  const iv = genIv();
  const data = utf8Encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    {name: 'AES-GCM', iv: iv},
    key,
    data
  );
  const cipherBytes = new Uint8Array(ciphertext);
  const merged = joinBytes(salt, iv, cipherBytes);
  return encodedString(merged, internalOptions.encoding);
}

/**
 * Decrypts the given ciphertext using AES-GCM decryption.
 * @param {string} cipher - The ciphertext to decrypt.
 * @param {string} password - The password to use for decryption.
 * @param {Partial<PbkdfOptions>} [options] - Optional parameters for key derivation.
 * @returns {Promise<string>} - A promise that resolves to the decrypted plaintext.
 */
export async function decrypt(
  cipher: string,
  password: string,
  options?: Partial<PbkdfOptions>
) {
  const internalOptions = assignDerivationOptionDefaults(options);
  const bytes = decodedBytes(cipher, internalOptions.encoding);
  const [salt, iv, data] = splitBytes(bytes, 16, 12);
  const [key] = await deriveKey(password, salt, internalOptions);
  const decryptedBytes = await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv: iv},
    key,
    data
  );
  return utf8Decode(decryptedBytes);
}

async function deriveKey(
  password: string,
  options?: PbkdfOptions
): Promise<[CryptoKey, Uint8Array]>;
async function deriveKey(
  password: string,
  salt: Uint8Array,
  options?: PbkdfOptions
): Promise<[CryptoKey, Uint8Array]>;
async function deriveKey(
  password: string,
  saltOrOptions?: Uint8Array | PbkdfOptions,
  options?: Partial<PbkdfOptions>
): Promise<[CryptoKey, Uint8Array]> {
  const passwordBytes = utf8Encode(password);

  const importedKey = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  let salt: Uint8Array;
  if (saltOrOptions instanceof Uint8Array) {
    salt = saltOrOptions;
  } else {
    salt = genSalt();
    options = saltOrOptions;
  }

  const {iterations, algorithm} =
    assignDerivationOptionDefaults(options);

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: algorithm,
    },
    importedKey,
    {name: 'AES-GCM', length: 256},
    false,
    ['encrypt', 'decrypt']
  );

  return [derivedKey, salt];
}
