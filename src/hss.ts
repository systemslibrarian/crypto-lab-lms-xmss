import { concatBytes, u32 } from './bytes';
import { lmsKeygen, lmsSign, lmsVerify, signaturesRemaining } from './lms';
import type { LMSPrivateKey, LMSPublicKey } from './lms';

const DEFAULT_ROOT_H = 5;
const DEFAULT_LEAF_H = 10;

function encodeLmsPublicKey(levelUsed: number, key: LMSPublicKey): Uint8Array {
  return concatBytes(u32(levelUsed), u32(key.typecode), u32(key.otsTypecode), key.I, key.T1);
}

function hFromLmsTypecode(typecode: number): number {
  if (typecode === 0x00000005) {
    return 5;
  }
  if (typecode === 0x00000006) {
    return 10;
  }
  throw new Error(`Unsupported LMS typecode: 0x${typecode.toString(16)}`);
}

export interface HSSPrivateKey {
  rootLMSKey: LMSPrivateKey;
  activeLeafLMSKey: LMSPrivateKey;
  activeLeafPublicKey: LMSPublicKey;
  rootSignatureOfLeaf: Uint8Array;
  levelUsed: number;
  maxLevels: number;
  leafHeight: number;
}

export interface HSSPublicKey {
  L: number;
  rootLMSPublicKey: LMSPublicKey;
}

/**
 * HSS two-level hierarchy:
 *   Level 0 (root): H=5 (32 leaf trees)
 *   Level 1 (leaf): H=10 (1024 signatures each)
 *   Total capacity: 32 × 1024 = 32,768 signatures
 */
export async function hssKeygen(
  onProgress?: (stage: string, percent: number) => void,
  options?: { rootH?: number; leafH?: number },
): Promise<{
  privateKey: HSSPrivateKey;
  publicKey: HSSPublicKey;
}> {
  const rootH = options?.rootH ?? DEFAULT_ROOT_H;
  const leafH = options?.leafH ?? DEFAULT_LEAF_H;

  onProgress?.(`Generating root LMS tree (H=${rootH})`, 0);
  const { privateKey: rootLMSKey, publicKey: rootPublicKey } = await lmsKeygen(
    (computed, total) => {
      onProgress?.('Root tree', (computed / total) * 20);
    },
    { h: rootH },
  );

  onProgress?.(`Generating first leaf LMS tree (H=${leafH})`, 25);
  const { privateKey: activeLeafLMSKey, publicKey: activeLeafPublicKey } = await lmsKeygen(
    (computed, total) => {
      onProgress?.('Leaf tree 0', 25 + (computed / total) * 65);
    },
    { h: leafH },
  );

  onProgress?.('Signing leaf public key with root tree', 92);
  const { signature: rootSignatureOfLeaf } = await lmsSign(
    encodeLmsPublicKey(0, activeLeafPublicKey),
    rootLMSKey,
  );

  onProgress?.('Complete', 100);

  return {
    privateKey: {
      rootLMSKey,
      activeLeafLMSKey,
      activeLeafPublicKey,
      rootSignatureOfLeaf,
      levelUsed: 0,
      maxLevels: 1 << rootH,
      leafHeight: leafH,
    },
    publicKey: {
      L: 2,
      rootLMSPublicKey: rootPublicKey,
    },
  };
}

async function rotateLeafIfNeeded(privateKey: HSSPrivateKey): Promise<void> {
  if (signaturesRemaining(privateKey.activeLeafLMSKey) > 0) {
    return;
  }

  if (privateKey.levelUsed + 1 >= privateKey.maxLevels) {
    throw new Error('HSS exhausted: root key has no remaining leaf-tree slots');
  }

  if (signaturesRemaining(privateKey.rootLMSKey) <= 0) {
    throw new Error('HSS exhausted: root LMS key exhausted');
  }

  const nextLevel = privateKey.levelUsed + 1;
  const { privateKey: nextLeafPrivate, publicKey: nextLeafPublic } = await lmsKeygen(undefined, {
    h: privateKey.leafHeight,
  });

  const { signature: nextRootSig } = await lmsSign(
    encodeLmsPublicKey(nextLevel, nextLeafPublic),
    privateKey.rootLMSKey,
  );

  privateKey.activeLeafLMSKey = nextLeafPrivate;
  privateKey.activeLeafPublicKey = nextLeafPublic;
  privateKey.rootSignatureOfLeaf = nextRootSig;
  privateKey.levelUsed = nextLevel;
}

export async function hssSign(message: Uint8Array, privateKey: HSSPrivateKey): Promise<Uint8Array> {
  await rotateLeafIfNeeded(privateKey);

  const leafSig = await lmsSign(message, privateKey.activeLeafLMSKey);

  return concatBytes(
    u32(privateKey.levelUsed),
    privateKey.rootSignatureOfLeaf,
    u32(privateKey.activeLeafPublicKey.typecode),
    u32(privateKey.activeLeafPublicKey.otsTypecode),
    privateKey.activeLeafPublicKey.I,
    privateKey.activeLeafPublicKey.T1,
    leafSig.signature,
  );
}

export async function hssVerify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: HSSPublicKey,
): Promise<boolean> {
  if (publicKey.L !== 2) {
    return false;
  }

  let offset = 0;
  const levelUsed =
    (signature[offset] << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  offset += 4;

  if (levelUsed < 0 || levelUsed >= 0x7fffffff) {
    return false;
  }

  const rootH = hFromLmsTypecode(publicKey.rootLMSPublicKey.typecode);
  const rootSigLen = 4 + 1124 + 4 + rootH * 32;
  if (signature.length < offset + rootSigLen + 4 + 4 + 16 + 32) {
    return false;
  }

  const rootSig = signature.slice(offset, offset + rootSigLen);
  offset += rootSigLen;

  const leafTypecode =
    (signature[offset] << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  offset += 4;

  const leafOtsTypecode =
    (signature[offset] << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  offset += 4;

  const leafI = signature.slice(offset, offset + 16);
  offset += 16;

  const leafT1 = signature.slice(offset, offset + 32);
  offset += 32;

  const leafPublicKey: LMSPublicKey = {
    typecode: leafTypecode,
    otsTypecode: leafOtsTypecode,
    I: leafI,
    T1: leafT1,
  };

  const leafH = hFromLmsTypecode(leafTypecode);
  const leafSigLen = 4 + 1124 + 4 + leafH * 32;
  if (signature.length !== offset + leafSigLen) {
    return false;
  }

  const leafSig = signature.slice(offset, offset + leafSigLen);

  const rootSigMessage = encodeLmsPublicKey(levelUsed, leafPublicKey);
  const rootOk = await lmsVerify(rootSigMessage, rootSig, publicKey.rootLMSPublicKey);
  if (!rootOk) {
    return false;
  }

  return lmsVerify(message, leafSig, leafPublicKey);
}
