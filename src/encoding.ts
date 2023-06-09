import * as b64url from '../lib/encoding/base64url.js';
import * as hex from '../lib/encoding/hex.js';

export function bytes(input?: string | ArrayBuffer | Uint8Array) {
  if (typeof input === 'string') {
    return utf8Encode(input);
  } else if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  } else if (input instanceof Uint8Array) {
    return input;
  } else {
    throw new Error('Invalid input type');
  }
}

export function utf8Encode(str?: string) {
  return new TextEncoder().encode(str);
}

export function utf8Decode(buffer?: BufferSource | undefined) {
  return new TextDecoder().decode(buffer);
}

export function hexEncode(bytes: Uint8Array) {
  return utf8Decode(hex.encode(bytes));
}

export function hexDecode(str: string) {
  return hex.decode(utf8Encode(str));
}

export function b64urlEncode(bytes: Uint8Array) {
  return b64url.encode(bytes);
}

export function b64urlDecode(str: string) {
  return b64url.decode(str);
}

/** Creates a hex or base64url encoded string from a Uint8Array or ArrayBuffer. */
export function encodedString(
  buffer: Uint8Array | ArrayBuffer,
  encoding: 'hex' | 'base64url' = 'hex'
) {
  if (encoding !== 'hex' && encoding !== 'base64url') {
    throw new TypeError(
      "Invalid encoding. Expected 'hex' or 'base64url'"
    );
  }

  const bytes =
    buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  return encoding === 'hex' ? hexEncode(bytes) : b64url.encode(bytes);
}

/** Creates a Uint8Array from a hex or base64url encoded string. */
export function decodedBytes(
  str: string,
  encoding: 'hex' | 'base64url' = 'hex'
) {
  if (encoding !== 'hex' && encoding !== 'base64url') {
    throw new TypeError(
      "Invalid encoding. Expected 'hex' or 'base64url'"
    );
  }

  return encoding === 'hex' ? hexDecode(str) : b64url.decode(str);
}
