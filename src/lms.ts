import { bytesEqual, concatBytes, randomBytes, u16, u32 } from './bytes';
import {
  LMOTS_PARAMS,
  lmotsCandidatePublicKey,
  lmotsKeygen,
  lmotsSign,
  sha256,
} from './lmots';

const D_LEAF = 0x8282;
const D_INTR = 0x8383;

export const LMS_PARAMS = {
  typecode: 0x00000006,
  m: 32,
  h: 10,
  maxSignatures: 1024,
  publicKeyBytes: 56,
} as const;

const LMS_TYPE_TO_H: Record<number, number> = {
  0x00000005: 5,
  0x00000006: 10,
};

export interface LMSPrivateKey {
  typecode: number;
  otsTypecode: number;
  h: number;
  I: Uint8Array;
  seed: Uint8Array;
  q: number;
  maxQ: number;
  usedIndexes: Set<number>;
  treeNodes: Uint8Array[];
}

export interface LMSPublicKey {
  typecode: number;
  otsTypecode: number;
  I: Uint8Array;
  T1: Uint8Array;
}

function hFromTypecode(typecode: number): number {
  const h = LMS_TYPE_TO_H[typecode];
  if (h === undefined) {
    throw new Error(`Unsupported LMS typecode: 0x${typecode.toString(16)}`);
  }
  return h;
}

async function computeLeafHash(I: Uint8Array, leafNodeNumber: number, otsPublicKey: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(I, u32(leafNodeNumber), u16(D_LEAF), otsPublicKey));
}

async function computeInternalHash(
  I: Uint8Array,
  nodeNumber: number,
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  return sha256(concatBytes(I, u32(nodeNumber), u16(D_INTR), left, right));
}

export async function lmsKeygen(
  onProgress?: (leafsComputed: number, total: number) => void,
  options?: { h?: number; typecode?: number },
): Promise<{
  privateKey: LMSPrivateKey;
  publicKey: LMSPublicKey;
}> {
  const h = options?.h ?? LMS_PARAMS.h;
  const typecode = options?.typecode ?? (h === 5 ? 0x00000005 : 0x00000006);
  const maxQ = 1 << h;

  const I = randomBytes(16);
  const seed = randomBytes(32);
  const treeSize = 1 << (h + 1);
  const treeNodes: Uint8Array[] = new Array(treeSize);

  const firstLeaf = 1 << h;
  for (let q = 0; q < maxQ; q += 1) {
    const leafNode = firstLeaf + q;
    const { publicKey: otsPublicKey } = await lmotsKeygen(I, q, seed);
    treeNodes[leafNode] = await computeLeafHash(I, leafNode, otsPublicKey);
    onProgress?.(q + 1, maxQ);
  }

  for (let node = firstLeaf - 1; node >= 1; node -= 1) {
    treeNodes[node] = await computeInternalHash(I, node, treeNodes[node * 2], treeNodes[node * 2 + 1]);
  }

  const privateKey: LMSPrivateKey = {
    typecode,
    otsTypecode: LMOTS_PARAMS.typecode,
    h,
    I,
    seed,
    q: 0,
    maxQ,
    usedIndexes: new Set<number>(),
    treeNodes,
  };

  const publicKey: LMSPublicKey = {
    typecode,
    otsTypecode: LMOTS_PARAMS.typecode,
    I,
    T1: treeNodes[1],
  };

  return { privateKey, publicKey };
}

export async function lmsSign(
  message: Uint8Array,
  privateKey: LMSPrivateKey,
): Promise<{
  signature: Uint8Array;
  qUsed: number;
  remainingSignatures: number;
}> {
  const q = privateKey.q;
  if (q >= privateKey.maxQ) {
    throw new Error('LMS key exhausted');
  }
  if (privateKey.usedIndexes.has(q)) {
    throw new Error(`LMS index reuse detected for q=${q}`);
  }

  const otsSig = await lmotsSign(message, {
    I: privateKey.I,
    q,
    seed: privateKey.seed,
  });

  const authPath = computeAuthPath(privateKey.treeNodes, q, privateKey.h);
  const signature = concatBytes(u32(q), otsSig, u32(privateKey.typecode), ...authPath);

  privateKey.usedIndexes.add(q);
  privateKey.q += 1;

  return {
    signature,
    qUsed: q,
    remainingSignatures: signaturesRemaining(privateKey),
  };
}

export async function lmsVerify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: LMSPublicKey,
): Promise<boolean> {
  const h = hFromTypecode(publicKey.typecode);
  const expectedLength = 4 + LMOTS_PARAMS.signatureBytes + 4 + h * LMS_PARAMS.m;
  if (signature.length !== expectedLength) {
    return false;
  }

  let offset = 0;
  const q =
    (signature[offset] << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  offset += 4;

  if (q < 0 || q >= (1 << h)) {
    return false;
  }

  const otsSig = signature.slice(offset, offset + LMOTS_PARAMS.signatureBytes);
  offset += LMOTS_PARAMS.signatureBytes;

  const sigLmsType =
    (signature[offset] << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  offset += 4;

  if (sigLmsType !== publicKey.typecode) {
    return false;
  }

  const authPath: Uint8Array[] = [];
  for (let i = 0; i < h; i += 1) {
    authPath.push(signature.slice(offset, offset + LMS_PARAMS.m));
    offset += LMS_PARAMS.m;
  }

  const candidateOtsPublicKey = await lmotsCandidatePublicKey(message, otsSig, publicKey.I, q);
  if (candidateOtsPublicKey === null) {
    return false;
  }

  const leafNodeNumber = (1 << h) + q;
  const leafHash = await computeLeafHash(publicKey.I, leafNodeNumber, candidateOtsPublicKey);
  const computedRoot = await computeRoot(leafHash, authPath, q, publicKey.I, h);
  return bytesEqual(computedRoot, publicKey.T1);
}

export function computeAuthPath(treeNodes: Uint8Array[], q: number, h: number): Uint8Array[] {
  const authPath: Uint8Array[] = [];
  let node = (1 << h) + q;
  for (let level = 0; level < h; level += 1) {
    authPath.push(treeNodes[node ^ 1]);
    node = Math.floor(node / 2);
  }
  return authPath;
}

export async function computeRoot(
  leafHash: Uint8Array,
  authPath: Uint8Array[],
  q: number,
  I: Uint8Array,
  h: number,
): Promise<Uint8Array> {
  let nodeHash = leafHash;
  let node = (1 << h) + q;

  for (let level = 0; level < h; level += 1) {
    const sibling = authPath[level];
    const parent = Math.floor(node / 2);
    if ((node & 1) === 0) {
      nodeHash = await computeInternalHash(I, parent, nodeHash, sibling);
    } else {
      nodeHash = await computeInternalHash(I, parent, sibling, nodeHash);
    }
    node = parent;
  }

  return nodeHash;
}

export function signaturesRemaining(privateKey: LMSPrivateKey): number {
  return Math.max(0, privateKey.maxQ - privateKey.q);
}
