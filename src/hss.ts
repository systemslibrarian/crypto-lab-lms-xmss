import { concatBytes, u32 } from './bytes';
import { lmsKeygen, lmsSign, lmsVerify, signaturesRemaining } from './lms';
import type { LMSPrivateKey, LMSPublicKey } from './lms';

const DEFAULT_ROOT_H = 5;
const DEFAULT_LEAF_H = 10;

/** Levels in the hierarchy, L in RFC 8554. This implementation is fixed at two: a
 *  root tree that signs leaf-tree public keys, and leaf trees that sign messages.
 *  Both the Nspk a signature carries and the Nspk a verifier demands are derived
 *  from this one constant, so the writer and the reader cannot drift apart. */
const HSS_LEVELS = 2;

/**
 * The message a parent tree signs: the child's LMS public key, serialized exactly as
 * RFC 8554 Section 5.3 defines it — u32(LMS type) || u32(LM-OTS type) || I || T[1].
 *
 * This used to prepend u32(levelUsed), which is why RFC 8554's own Appendix F Test
 * Case 1 would not verify through `hssVerify` while BOTH of its LMS signatures verify
 * through `lmsVerify`. The prefix was also redundant: the parent's LMS signature
 * carries its own `q`, which already identifies which leaf signed this public key, so
 * the level was bound twice and the second binding was the non-conformant one.
 */
function encodeLmsPublicKey(key: LMSPublicKey): Uint8Array {
  return concatBytes(u32(key.typecode), u32(key.otsTypecode), key.I, key.T1);
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
  /** How many leaf TREES the root can certify: 1 << rootH, so 32 at the default.
   *  Named `maxLevels` until 2026-10-20, which reads like L in RFC 8554 and is a
   *  completely different number: that name is why this field's value minus one
   *  was written as an Nspk, where it is 31 rather than 1. */
  leafTreeCount: number;
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
    encodeLmsPublicKey(activeLeafPublicKey),
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
      leafTreeCount: 1 << rootH,
      leafHeight: leafH,
    },
    publicKey: {
      L: HSS_LEVELS,
      rootLMSPublicKey: rootPublicKey,
    },
  };
}

async function rotateLeafIfNeeded(privateKey: HSSPrivateKey): Promise<void> {
  if (signaturesRemaining(privateKey.activeLeafLMSKey) > 0) {
    return;
  }

  if (privateKey.levelUsed + 1 >= privateKey.leafTreeCount) {
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
    encodeLmsPublicKey(nextLeafPublic),
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
    /* RFC 8554 Section 6.1: an HSS signature opens with Nspk, the number of signed
       public keys it carries — L - 1, so 1 for this two-level hierarchy. It used to
       carry `levelUsed`, the active leaf-tree index: a different quantity that merely
       also equals 1 once the second leaf tree is in use, which is what made the bug
       survive every round-trip test. The leaf index is recoverable from the root
       signature's own q. */
    u32(HSS_LEVELS - 1),
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
  if (publicKey.L !== HSS_LEVELS) {
    return false;
  }

  let offset = 0;
  const nspk =
    (signature[offset] << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  offset += 4;

  /* RFC 8554 Section 6.2 step 1: a signature whose Nspk disagrees with the public
     key's own level count is invalid. This read the field as a leaf-tree index and
     accepted any non-negative value, so it could not reject a signature claiming the
     wrong number of signed public keys. */
  if (nspk !== publicKey.L - 1) {
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

  const rootSigMessage = encodeLmsPublicKey(leafPublicKey);
  const rootOk = await lmsVerify(rootSigMessage, rootSig, publicKey.rootLMSPublicKey);
  if (!rootOk) {
    return false;
  }

  return lmsVerify(message, leafSig, leafPublicKey);
}
