/**
 * Generates a random 96-bit Initialization Vector.
 * @returns {Uint8Array} A random 96-bit IV.
 */
export function genIv() {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Generates a random 128-bit salt.
 * @returns {Uint8Array} A random 128-bit salt.
 */
export function genSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

export type SecureHashingAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

export function isSupportedHashFunction(
  value: unknown
): value is SecureHashingAlgorithm {
  const algorithms: SecureHashingAlgorithm[] = [
    'SHA-256',
    'SHA-384',
    'SHA-512',
  ];
  return (
    typeof value === 'string' &&
    algorithms.includes(value as SecureHashingAlgorithm)
  );
}

export function hashFunctionByteLength(
  algorithm: SecureHashingAlgorithm
) {
  switch (algorithm) {
    case 'SHA-256':
      return 32;
    case 'SHA-384':
      return 48;
    case 'SHA-512':
      return 64;
  }
}
