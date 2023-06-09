/**
 * Joins multiple Uint8Array objects into a single Uint8Array.
 *
 * @param {...Uint8Array} byteArray - The Uint8Array objects to be joined.
 * @returns {Uint8Array} The merged Uint8Array containing the concatenated data.
 */
export function joinBytes(...byteArray: Array<Uint8Array>) {
  const length = byteArray.reduce((a, b) => a + b.byteLength, 0);
  const merged = new Uint8Array(length);
  let offset = 0;
  for (let i = 0; i < byteArray.length; i++) {
    merged.set(byteArray[i], offset);
    offset += byteArray[i].byteLength;
  }
  return merged;
}

/**
 * Splits a Uint8Array into multiple segments of specified lengths.
 *
 * @param {Uint8Array} bytes - The input Uint8Array to be split.
 * @param {...number} lengths - The lengths of the segments to split the input into.
 * @returns {Uint8Array[]} An array of Uint8Array segments.
 */
export function splitBytes(bytes: Uint8Array, ...lengths: number[]) {
  const totalLength = lengths.reduce((a, b) => a + b, 0);
  if (totalLength !== bytes.byteLength) {
    lengths.push(bytes.byteLength - totalLength);
  }
  let offset = 0;
  const split: Uint8Array[] = [];
  for (let i = 0; i < lengths.length; i++) {
    const length = lengths[i];
    split.push(bytes.subarray(offset, (offset += length)));
  }
  return split;
}
