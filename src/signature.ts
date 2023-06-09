import {timingSafeEqual} from '../lib/crypto/timingSafeEqual.js';
import {joinBytes, splitBytes} from './byte_array.js';
import {
  SecureHashingAlgorithm,
  hashFunctionByteLength,
} from './crypto_utils.js';
import {decodedBytes, encodedString, utf8Encode} from './encoding.js';

export interface SignatureOptions {
  /** HMAC digest function to use
   * @default "SHA-384"
   */
  algorithm: SecureHashingAlgorithm;
  /**
   * Encoding to use for the output string.
   * @default "hex"
   */
  encoding: 'hex' | 'base64url';
}

const DEFAULT_SIGNATURE_OPTIONS: Required<SignatureOptions> = {
  algorithm: 'SHA-384',
  encoding: 'hex',
};

function assignSignatureOptionDefaults(
  options: Partial<SignatureOptions> = {}
) {
  return Object.assign({}, DEFAULT_SIGNATURE_OPTIONS, options);
}

export async function verify(
  signedMessage: string,
  secret: string,
  options?: Partial<SignatureOptions>
) {
  const {algorithm, encoding} = assignSignatureOptionDefaults(options);
  const signedMessageBytes = decodedBytes(signedMessage, encoding);
  const signatureByteLength = hashFunctionByteLength(algorithm);
  const messageLength =
    signedMessageBytes.byteLength - signatureByteLength;
  const [messageBytes, signatureBytes] = splitBytes(
    signedMessageBytes,
    messageLength
  );
  return cryptoVerify(messageBytes, signatureBytes, secret, algorithm);
}

export async function sign(
  message: string,
  secret: string,
  options?: Partial<SignatureOptions>
) {
  const {algorithm, encoding} = assignSignatureOptionDefaults(options);
  const [data, signature] = await cryptoSign(
    message,
    secret,
    algorithm
  );
  const signedBytes = joinBytes(data, signature);
  return encodedString(signedBytes, encoding);
}

async function importSigningKey(
  secret: string,
  algorithm: SecureHashingAlgorithm
) {
  const secretBytes = utf8Encode(secret);

  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    {name: 'HMAC', hash: algorithm},
    false,
    ['sign']
  );
  return key;
}

async function cryptoSign(
  message: string | Uint8Array,
  key: string | CryptoKey,
  algorithm: SecureHashingAlgorithm
): Promise<[Uint8Array, Uint8Array]> {
  if (typeof key === 'string')
    key = await importSigningKey(key, algorithm);
  if (typeof message === 'string') message = utf8Encode(message);
  const signature = await crypto.subtle.sign('HMAC', key, message);
  return [message, new Uint8Array(signature)];
}

async function cryptoVerify(
  data: string | Uint8Array,
  signature: string | Uint8Array,
  secretKey: string | CryptoKey,
  algorithm: SecureHashingAlgorithm
) {
  const [, validSignature] = await cryptoSign(
    data,
    secretKey,
    algorithm
  );
  if (typeof signature === 'string') signature = utf8Encode(signature);
  return timingSafeEqual(signature, validSignature);
}
