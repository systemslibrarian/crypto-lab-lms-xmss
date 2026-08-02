/**
 * Index-reuse forgery for LM-OTS / LMS.
 *
 * This module is the demo's payload: it proves *why* a stateful signature scheme
 * collapses the instant a one-time-signature index is reused. Everything here
 * runs as the **attacker** — it touches only public information (the identifier
 * I, the index q, the leaked signatures, and the message each one signed). It
 * never sees the private seed.
 *
 * The attack rests on one fact about Winternitz chains (see `chain` in lmots.ts):
 * a chain value at depth d can be advanced to any depth >= d, but never reversed.
 * A single signature on message M reveals, for each of the p positions, the chain
 * value at depth a_i(M). With k signatures reused at the *same* index, the attacker
 * learns each position's value at the *lowest* depth seen across all of them. The
 * lower the known depth, the wider the range of messages whose required depths it
 * can reach. Reuse a few times and the reachable space grows until the attacker
 * can grind a fresh randomizer C so that a chosen (malicious) message lands
 * entirely within reach — yielding a signature the real public key accepts.
 */
import { concatBytes, randomBytes, u32 } from './bytes';
import { LMOTS_PARAMS, chain, lmotsCoefficients } from './lmots';

const N = LMOTS_PARAMS.n; // 32, randomizer + chain-value byte length
const P = LMOTS_PARAMS.p; // 34, Winternitz digits per LM-OTS signature
const OTS_SIG_BYTES = LMOTS_PARAMS.signatureBytes; // 1124
const LMS_SIG_PREFIX = 4 + OTS_SIG_BYTES + 4; // q (u32) + OTS sig + LMS typecode (u32)

export interface LeakedSignature {
  message: Uint8Array;
  /** A full LMS signature, all produced at the same (reused) index q. */
  signature: Uint8Array;
}

interface ParsedLmsSignature {
  q: number;
  C: Uint8Array;
  ys: Uint8Array[];
  authPath: Uint8Array;
}

function readU32(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  );
}

function parseLmsSignature(signature: Uint8Array): ParsedLmsSignature {
  const q = readU32(signature, 0);
  const ots = signature.subarray(4, 4 + OTS_SIG_BYTES);
  const C = ots.slice(4, 4 + N);
  const ys: Uint8Array[] = [];
  let offset = 4 + N;
  for (let i = 0; i < P; i += 1) {
    ys.push(ots.slice(offset, offset + N));
    offset += N;
  }
  const authPath = signature.slice(LMS_SIG_PREFIX);
  return { q, C, ys, authPath };
}

export interface ForgeKnowledge {
  /** The reused index every leaked signature shares. */
  q: number;
  /** The Merkle authentication path for q — identical in every signature at q. */
  authPath: Uint8Array;
  /** Per position: the lowest chain depth revealed across all leaked signatures. */
  minDepth: number[];
  /** Per position: the chain value the attacker holds at `minDepth[i]`. */
  revealedValue: Uint8Array[];
  /** Per leaked signature: its full per-position depth vector (for visualization). */
  perSignatureDepths: number[][];
}

/** Count positions whose lowest revealed depth can reach a chosen comparison depth. */
export function countPositionsReachableAtDepth(depths: number[], comparisonDepth: number): number {
  return depths.filter((depth) => depth <= comparisonDepth).length;
}

/**
 * Distill the leaked signatures into the deepest knowledge the attacker can hold:
 * for every Winternitz position, the lowest chain depth (and the value at it) seen
 * across all reuses. These minima are what the forge step chains forward from.
 */
export async function gatherKnowledge(
  I: Uint8Array,
  leaked: LeakedSignature[],
): Promise<ForgeKnowledge> {
  if (leaked.length === 0) {
    throw new Error('Need at least one leaked signature to mount the attack');
  }

  const parsed = leaked.map((l) => ({ ...parseLmsSignature(l.signature), message: l.message }));
  const q = parsed[0].q;
  const authPath = parsed[0].authPath;

  const minDepth = new Array<number>(P).fill(Number.POSITIVE_INFINITY);
  const revealedValue = new Array<Uint8Array>(P);
  const perSignatureDepths: number[][] = [];

  for (const sig of parsed) {
    const depths = await lmotsCoefficients(I, q, sig.C, sig.message);
    perSignatureDepths.push(depths);
    for (let i = 0; i < P; i += 1) {
      if (depths[i] < minDepth[i]) {
        minDepth[i] = depths[i];
        revealedValue[i] = sig.ys[i];
      }
    }
  }

  return { q, authPath, minDepth, revealedValue, perSignatureDepths };
}

export interface ForgeResult {
  /** A full LMS signature on the target message that verifies against the real key. */
  signature: Uint8Array;
  /** How many randomizers were tried before one landed entirely within reach. */
  attempts: number;
  /** The forged message's per-position required depths. */
  forgedDepths: number[];
}

/**
 * Grind the randomizer C until the target message's required chain depths all sit
 * at or above the depths the attacker already knows, then build each position by
 * chaining the known value forward. The result is a structurally valid LM-OTS
 * signature wrapped in the public authentication path — i.e. a full LMS forgery.
 *
 * Returns null only if `maxAttempts` is exhausted (vanishingly unlikely once a
 * handful of signatures have been reused).
 */
export async function forgeSignature(
  I: Uint8Array,
  knowledge: ForgeKnowledge,
  targetMessage: Uint8Array,
  lmsTypecode: number,
  options?: { maxAttempts?: number; onProgress?: (attempts: number) => void },
): Promise<ForgeResult | null> {
  const { q, authPath, minDepth, revealedValue } = knowledge;
  const maxAttempts = options?.maxAttempts ?? 200_000;
  const progressEvery = 2000;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const C = randomBytes(N);
    const depths = await lmotsCoefficients(I, q, C, targetMessage);

    let reachable = true;
    for (let i = 0; i < P; i += 1) {
      if (depths[i] < minDepth[i]) {
        reachable = false;
        break;
      }
    }

    if (!reachable) {
      if (attempt % progressEvery === 0 && options?.onProgress) {
        options.onProgress(attempt);
        // Yield to the event loop so the browser can repaint progress and stay
        // responsive during the (rare) long grind. Awaited digests alone only
        // schedule microtasks, which never trigger a repaint.
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      continue;
    }

    const ys: Uint8Array[] = [];
    for (let i = 0; i < P; i += 1) {
      // Advance the known value from its depth up to the depth this message needs.
      ys.push(await chain(I, q, i, revealedValue[i], minDepth[i], depths[i]));
    }

    const otsSig = concatBytes(u32(LMOTS_PARAMS.typecode), C, ...ys);
    const signature = concatBytes(u32(q), otsSig, u32(lmsTypecode), authPath);
    return { signature, attempts: attempt, forgedDepths: depths };
  }

  return null;
}

/**
 * Convenience for callers that have the signer's private material and just want to
 * stage the leak: produce `count` full LMS signatures all reusing index `q`. This
 * is the *signer's* mistake, isolated here so the demo can hand the attacker only
 * the resulting signatures.
 */
export interface ReuseSigner {
  I: Uint8Array;
  q: number;
  lmsTypecode: number;
  authPath: Uint8Array;
  signOts: (message: Uint8Array) => Promise<Uint8Array>;
}

export async function stageReusedSignatures(
  signer: ReuseSigner,
  messages: Uint8Array[],
): Promise<LeakedSignature[]> {
  const leaked: LeakedSignature[] = [];
  for (const message of messages) {
    const otsSig = await signer.signOts(message);
    const signature = concatBytes(
      u32(signer.q),
      otsSig,
      u32(signer.lmsTypecode),
      signer.authPath,
    );
    leaked.push({ message, signature });
  }
  return leaked;
}
