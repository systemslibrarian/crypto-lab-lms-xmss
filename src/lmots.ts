import { bytesEqual, concatBytes, randomBytes, u16, u32, u8 } from './bytes';

/**
 * LM-OTS parameters per RFC 8554 Section 4.1.
 * We use LMOTS_SHA256_N32_W8 exclusively.
 */
export const LMOTS_PARAMS = {
  typecode: 0x00000004,
  n: 32,
  w: 8,
  p: 34,
  ls: 0,
  signatureBytes: 1124,
  publicKeyBytes: 32,
  privateKeyBytes: 32,
} as const;

const D_PBLC = 0x8080;
const D_MESG = 0x8181;
const ITER_MAX = (1 << LMOTS_PARAMS.w) - 1;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const normalized = Uint8Array.from(data);
  const digest = await crypto.subtle.digest('SHA-256', normalized);
  return new Uint8Array(digest);
}

/**
 * Winternitz hash chain for OTS digit `i`: iteratively hash `start` from
 * step `from` up to (but not including) `toExclusive`. The chain is one-way —
 * a value at depth `d` can be advanced to any depth `>= d` but never reversed.
 * This irreversibility is exactly what makes index reuse catastrophic (see forge.ts).
 */
export async function chain(
  I: Uint8Array,
  q: number,
  i: number,
  start: Uint8Array,
  from: number,
  toExclusive: number,
): Promise<Uint8Array> {
  let tmp = start;
  const prefix = concatBytes(I, u32(q), u16(i));
  for (let j = from; j < toExclusive; j += 1) {
    const input = concatBytes(prefix, u8(j), tmp);
    tmp = await sha256(input);
  }
  return tmp;
}

async function xValue(I: Uint8Array, q: number, i: number, seed: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(I, u32(q), u16(i), u8(0xff), seed));
}

export async function lmotsKeygen(
  I: Uint8Array,
  q: number,
  seed?: Uint8Array,
): Promise<{
  privateKey: { I: Uint8Array; q: number; seed: Uint8Array };
  publicKey: Uint8Array;
}> {
  if (I.length !== 16) {
    throw new Error('LM-OTS requires a 16-byte I identifier');
  }

  const keySeed = seed ?? randomBytes(LMOTS_PARAMS.privateKeyBytes);
  if (keySeed.length !== LMOTS_PARAMS.privateKeyBytes) {
    throw new Error('LM-OTS seed must be 32 bytes');
  }

  let ys = await Promise.all(
    Array.from({ length: LMOTS_PARAMS.p }, (_, i) => xValue(I, q, i, keySeed)),
  );

  for (let j = 0; j < ITER_MAX; j += 1) {
    ys = await Promise.all(
      ys.map((value, i) => sha256(concatBytes(I, u32(q), u16(i), u8(j), value))),
    );
  }

  const K = await sha256(concatBytes(I, u32(q), u16(D_PBLC), ...ys));
  return {
    privateKey: {
      I: new Uint8Array(I),
      q,
      seed: new Uint8Array(keySeed),
    },
    publicKey: K,
  };
}

/**
 * Given a digest (with checksum appended), extract p digits of w bits each.
 */
export function coefficient(S: Uint8Array, i: number, w: number): number {
  const bitOffset = i * w;
  const byteOffset = Math.floor(bitOffset / 8);
  const shift = 8 - w - (bitOffset % 8);
  const mask = (1 << w) - 1;
  return (S[byteOffset] >>> shift) & mask;
}

/**
 * checksum(Q) = sum_i (2^w - 1 - coef(Q, i)) for each digit.
 */
export function computeChecksum(Q: Uint8Array, w: number): Uint8Array {
  const u = Math.ceil((8 * Q.length) / w);
  const maxDigit = (1 << w) - 1;
  let sum = 0;
  for (let i = 0; i < u; i += 1) {
    sum += maxDigit - coefficient(Q, i, w);
  }

  const lsByW: Record<number, number> = { 1: 7, 2: 6, 4: 4, 8: 0 };
  const ls = lsByW[w] ?? 0;
  const shifted = (sum << ls) & 0xffff;
  return u16(shifted);
}

/**
 * The p Winternitz digits (chain depths) signed by an LM-OTS signature:
 * the n-byte message digest Q = H(I || q || D_MESG || C || message) with its
 * checksum appended, split into p coefficients of w bits each. Shared by
 * signing, verification, and the reuse-forgery attack so all three agree byte
 * for byte on how a (C, message) pair maps to chain depths.
 */
export async function lmotsCoefficients(
  I: Uint8Array,
  q: number,
  C: Uint8Array,
  message: Uint8Array,
): Promise<number[]> {
  const Q = await sha256(concatBytes(I, u32(q), u16(D_MESG), C, message));
  const QwithCksm = concatBytes(Q, computeChecksum(Q, LMOTS_PARAMS.w));
  return Array.from({ length: LMOTS_PARAMS.p }, (_, i) =>
    coefficient(QwithCksm, i, LMOTS_PARAMS.w),
  );
}

export async function lmotsSign(
  message: Uint8Array,
  privateKey: { I: Uint8Array; q: number; seed: Uint8Array },
): Promise<Uint8Array> {
  const { I, q, seed } = privateKey;
  if (I.length !== 16) {
    throw new Error('LM-OTS private key I must be 16 bytes');
  }
  if (seed.length !== 32) {
    throw new Error('LM-OTS private key seed must be 32 bytes');
  }

  const C = randomBytes(LMOTS_PARAMS.n);
  const a = await lmotsCoefficients(I, q, C, message);

  const y: Uint8Array[] = [];
  for (let i = 0; i < LMOTS_PARAMS.p; i += 1) {
    const x = await xValue(I, q, i, seed);
    y.push(await chain(I, q, i, x, 0, a[i]));
  }

  return concatBytes(u32(LMOTS_PARAMS.typecode), C, ...y);
}

export async function lmotsVerify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  I: Uint8Array,
  q: number,
): Promise<Uint8Array | null> {
  const Kc = await lmotsCandidatePublicKey(message, signature, I, q);
  if (Kc === null) {
    return null;
  }
  if (publicKey.length !== LMOTS_PARAMS.publicKeyBytes) {
    return null;
  }
  return bytesEqual(Kc, publicKey) ? Kc : null;
}

export async function lmotsCandidatePublicKey(
  message: Uint8Array,
  signature: Uint8Array,
  I: Uint8Array,
  q: number,
): Promise<Uint8Array | null> {
  if (signature.length !== LMOTS_PARAMS.signatureBytes) {
    return null;
  }
  if (I.length !== 16) {
    return null;
  }

  const sigType =
    (signature[0] << 24) |
    (signature[1] << 16) |
    (signature[2] << 8) |
    signature[3];
  if (sigType !== LMOTS_PARAMS.typecode) {
    return null;
  }

  let offset = 4;
  const C = signature.slice(offset, offset + LMOTS_PARAMS.n);
  offset += LMOTS_PARAMS.n;

  const ys: Uint8Array[] = [];
  for (let i = 0; i < LMOTS_PARAMS.p; i += 1) {
    ys.push(signature.slice(offset, offset + LMOTS_PARAMS.n));
    offset += LMOTS_PARAMS.n;
  }

  const a = await lmotsCoefficients(I, q, C, message);

  const z: Uint8Array[] = [];
  for (let i = 0; i < LMOTS_PARAMS.p; i += 1) {
    z.push(await chain(I, q, i, ys[i], a[i], ITER_MAX));
  }

  const Kc = await sha256(concatBytes(I, u32(q), u16(D_PBLC), ...z));
  return Kc;
}
