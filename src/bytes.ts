export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function u8(value: number): Uint8Array {
  return Uint8Array.of(value & 0xff);
}

export function u16(value: number): Uint8Array {
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

export function u32(value: number): Uint8Array {
  return Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) {
    acc |= a[i] ^ b[i];
  }
  return acc === 0;
}

export function hexToBytes(hex: string): Uint8Array {
  const compact = hex.replace(/\s+/g, '').toLowerCase();
  if (compact.length % 2 !== 0) {
    throw new Error('Invalid hex length');
  }
  const out = new Uint8Array(compact.length / 2);
  for (let i = 0; i < compact.length; i += 2) {
    out[i / 2] = Number.parseInt(compact.slice(i, i + 2), 16);
  }
  return out;
}

export function bytesToHex(data: Uint8Array): string {
  return [...data].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export const textEncoder = new TextEncoder();
