import {utf8Encode, decodedBytes, encodedString} from './encoding.js';
import {
  type SecureHashingAlgorithm,
  genSalt,
  hashFunctionByteLength,
} from './crypto_utils.js';
import {joinBytes, splitBytes} from './byte_array.js';
import {timingSafeEqual} from '../lib/crypto/timingSafeEqual.js';

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

export async function hash(
  password: string,
  options?: Partial<PbkdfOptions>
) {
  const internalOptions = assignDerivationOptionDefaults(options);
  const [hash, salt] = await pbkdf(password, internalOptions);
  return encodedString(joinBytes(hash, salt), internalOptions.encoding);
}

export async function compare(
  password: string,
  hashedPassword: string,
  options?: Partial<PbkdfOptions>
) {
  const {algorithm, iterations, encoding} =
    assignDerivationOptionDefaults(options);
  const passwordBytes = decodedBytes(hashedPassword, encoding);
  const keyLength = hashFunctionByteLength(algorithm);
  const [hash, salt] = splitBytes(passwordBytes, keyLength);
  const [inputHash] = await pbkdf(password, salt, {
    algorithm,
    iterations,
    encoding,
  });
  return timingSafeEqual(inputHash, hash);
}

async function pbkdf(
  password: string,
  options?: PbkdfOptions
): Promise<[Uint8Array, Uint8Array]>;
async function pbkdf(
  password: string,
  salt: Uint8Array,
  options?: PbkdfOptions
): Promise<[Uint8Array, Uint8Array]>;
async function pbkdf(
  password: string,
  saltOrOptions?: Uint8Array | PbkdfOptions,
  options?: Partial<PbkdfOptions>
): Promise<[Uint8Array, Uint8Array]> {
  const passwordBytes = utf8Encode(password);

  const importedKey = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveBits']
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

  const keyLength = hashFunctionByteLength(algorithm) * 8;

  const keyBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: algorithm,
      salt,
      iterations: iterations,
    },
    importedKey,
    keyLength
  );

  return [new Uint8Array(keyBuffer), salt];
}
