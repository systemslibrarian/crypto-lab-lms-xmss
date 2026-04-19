import { concatBytes, u32 } from './bytes';
import { lmsKeygen, lmsSign, lmsVerify } from './lms';
import type { LMSPrivateKey, LMSPublicKey } from './lms';

export interface HSSPrivateKey {
  rootLMSKey: LMSPrivateKey;
  activeLeafLMSKey: LMSPrivateKey;
  activeLeafPublicKey: LMSPublicKey;
  rootSignatureOfLeaf: Uint8Array;
  levelUsed: number;
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
export async function hssKeygen(onProgress?: (stage: string, percent: number) => void): Promise<{
  privateKey: HSSPrivateKey;
  publicKey: HSSPublicKey;
}> {
  onProgress?.('Generating root LMS tree (H=5)', 0);
  const { privateKey: rootLMSKey, publicKey: rootPublicKey } = await lmsKeygen(
    (computed, total) => {
      onProgress?.('Root tree', (computed / total) * 10);
    },
    { h: 5 },
  );

  onProgress?.('Generating first leaf LMS tree (H=10)', 20);
  const { privateKey: activeLeafLMSKey, publicKey: activeLeafPublicKey } = await lmsKeygen(
    (computed, total) => {
      onProgress?.('Leaf tree 0', 20 + (computed / total) * 70);
    },
    { h: 10 },
  );

  onProgress?.('Signing leaf public key with root tree', 90);
  const { signature: rootSignatureOfLeaf } = await lmsSign(
    concatBytes(
      u32(0),
      u32(activeLeafPublicKey.typecode),
      u32(activeLeafPublicKey.otsTypecode),
      activeLeafPublicKey.I,
      activeLeafPublicKey.T1,
    ),
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
    },
    publicKey: {
      L: 2,
      rootLMSPublicKey: rootPublicKey,
    },
  };
}

export async function hssSign(message: Uint8Array, privateKey: HSSPrivateKey): Promise<Uint8Array> {
  const leafSig = await lmsSign(message, privateKey.activeLeafLMSKey);

  const hssSignature = concatBytes(
    u32(privateKey.levelUsed),
    privateKey.rootSignatureOfLeaf,
    u32(privateKey.activeLeafPublicKey.typecode),
    u32(privateKey.activeLeafPublicKey.otsTypecode),
    privateKey.activeLeafPublicKey.I,
    privateKey.activeLeafPublicKey.T1,
    leafSig.signature,
  );

  return hssSignature;
}

export async function hssVerify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: HSSPublicKey,
): Promise<boolean> {
  const expectedL = publicKey.L;
  if (expectedL !== 2) {
    return false;
  }

  let offset = 0;
  const levelUsed =
    (signature[offset] << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  offset += 4;

  if (levelUsed < 0 || levelUsed >= 32) {
    return false;
  }

  const expectedRootSigLen = 4 + 1124 + 4 + 5 * 32;
  const rootSig = signature.slice(offset, offset + expectedRootSigLen);
  offset += expectedRootSigLen;

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

  const leafSigLen = 4 + 1124 + 4 + 10 * 32;
  const leafSig = signature.slice(offset, offset + leafSigLen);

  const rootSigMessage = concatBytes(
    u32(levelUsed),
    u32(leafTypecode),
    u32(leafOtsTypecode),
    leafI,
    leafT1,
  );
  const rootOk = await lmsVerify(rootSigMessage, rootSig, publicKey.rootLMSPublicKey);
  if (!rootOk) {
    return false;
  }

  return lmsVerify(message, leafSig, leafPublicKey);
}
