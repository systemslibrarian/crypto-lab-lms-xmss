import { concatBytes, hexToBytes, textEncoder, u32 } from '../bytes';
import { lmsKeygen, lmsSign, lmsVerify } from '../lms';
import type { LMSPrivateKey, LMSPublicKey } from '../lms';
import { parseLeafIndex } from '../input';
import {
  TC1_MESSAGE_HEX,
  TC1_PUBLIC_KEY_HEX,
  TC1_SIGNATURE_HEX,
} from './rfc8554-test-case-1';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function logPass(message: string): void {
  console.log(`PASS: ${message}`);
}

function clonePrivateKey(key: LMSPrivateKey): LMSPrivateKey {
  return {
    ...key,
    I: new Uint8Array(key.I),
    seed: new Uint8Array(key.seed),
    usedIndexes: new Set<number>([...key.usedIndexes]),
    treeNodes: key.treeNodes.map((n) => new Uint8Array(n)),
  };
}

async function run(): Promise<void> {
  assert(parseLeafIndex('', 1024) === null, 'Empty q override must be rejected');
  assert(parseLeafIndex('-5', 1024) === null, 'Negative q override must be rejected');
  assert(parseLeafIndex('12.5', 1024) === null, 'Fractional q override must be rejected');
  assert(parseLeafIndex('1024', 1024) === null, 'Out-of-range q override must be rejected');
  assert(parseLeafIndex('7', 1024) === 7, 'Valid q override must parse');
  logPass('Unsafe q override parser accepts only in-range whole leaf indexes');

  const start = Date.now();
  const { privateKey, publicKey } = await lmsKeygen(undefined, { h: 5 });
  const elapsedMs = Date.now() - start;
  assert(elapsedMs < 30_000, `lmsKeygen exceeded 30 seconds (${elapsedMs}ms) for H=5`);
  logPass(`lmsKeygen H=5 completed in ${elapsedMs}ms (gate limit: 30s)`);

  const message = textEncoder.encode('Firmware v2.3.1 release');
  const first = await lmsSign(message, privateKey);
  const ok1 = await lmsVerify(message, first.signature, publicKey);
  assert(ok1, 'LMS sign + verify round-trip failed');
  logPass('LMS sign + verify round-trip');

  const second = await lmsSign(message, privateKey);
  assert(second.qUsed === first.qUsed + 1, 'LMS q did not increment between signatures');
  const ok2 = await lmsVerify(message, second.signature, publicKey);
  assert(ok2, 'Second LMS signature did not verify');
  logPass('Second signature increments q and verifies');

  const corruptedState = clonePrivateKey(privateKey);
  corruptedState.q = first.qUsed;
  let reuseBlocked = false;
  try {
    await lmsSign(message, corruptedState);
  } catch {
    reuseBlocked = true;
  }
  assert(reuseBlocked, 'Index reuse attempt did not throw');
  logPass('Attempted index reuse throws');

  for (const invalidQ of [-5, Number.NaN, 1.5, corruptedState.maxQ]) {
    const invalidState = clonePrivateKey(privateKey);
    invalidState.q = invalidQ;
    let invalidBlocked = false;
    try {
      await lmsSign(message, invalidState);
    } catch {
      invalidBlocked = true;
    }
    assert(invalidBlocked, `Invalid q=${String(invalidQ)} reached signing`);
  }
  logPass('LMS signer rejects negative, NaN, fractional, and exhausted indexes');

  const tampered = new Uint8Array(first.signature);
  tampered[tampered.length - 1] ^= 0x01;
  const tamperedResult = await lmsVerify(message, tampered, publicKey);
  assert(!tamperedResult, 'Tampered LMS signature should fail');
  logPass('Tampered LMS signature is rejected');
  /* RFC 8554 Appendix F Test Case 1, through this lab's own lmsVerify.
   *
   * THIS LINE USED TO BE A BARE logPass. It printed
   *   "RFC 8554 Appendix F LMS vector structure verified (HSS parsing in Phase 3)"
   * with no assertion above it and no vector anywhere in this file — phase2.ts held
   * zero hex literals, against 41 in phase1.ts, whose LM-OTS vector is real. So the
   * gate published a green line for a check that did not exist, and the parenthesis
   * sent a reader to Phase 3, which did not verify it either.
   *
   * Test Case 1 is a two-level HSS signature, and both of its levels are LMS
   * signatures this file can check directly:
   *   sig[1] over the published message, under the leaf public key
   *   sig[0] over the leaf public key, under the root public key
   * Between them they exercise the auth path, computeRoot, the LM-OTS candidate
   * public key, the Winternitz chain, coefficient and the checksum. */
  const tc1Pub = hexToBytes(TC1_PUBLIC_KEY_HEX);
  const tc1Msg = hexToBytes(TC1_MESSAGE_HEX);
  const tc1Sig = hexToBytes(TC1_SIGNATURE_HEX);
  const be = (b: Uint8Array, o: number): number =>
    ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

  assert(tc1Pub.length === 60, `RFC public key is ${tc1Pub.length} bytes, expected 60`);
  assert(tc1Msg.length === 162, `RFC message is ${tc1Msg.length} bytes, expected 162`);
  assert(tc1Sig.length === 2644, `RFC signature is ${tc1Sig.length} bytes, expected 2644`);

  const rootPub: LMSPublicKey = {
    typecode: be(tc1Pub, 4),
    otsTypecode: be(tc1Pub, 8),
    I: tc1Pub.slice(12, 28),
    T1: tc1Pub.slice(28, 60),
  };
  const ROOT_SIG_LEN = 4 + 1124 + 4 + 5 * 32; // q + LM-OTS sig + LMS type + path, h=5
  const rootSig = tc1Sig.slice(4, 4 + ROOT_SIG_LEN);
  const leafPubOffset = 4 + ROOT_SIG_LEN;
  const leafPub: LMSPublicKey = {
    typecode: be(tc1Sig, leafPubOffset),
    otsTypecode: be(tc1Sig, leafPubOffset + 4),
    I: tc1Sig.slice(leafPubOffset + 8, leafPubOffset + 24),
    T1: tc1Sig.slice(leafPubOffset + 24, leafPubOffset + 56),
  };
  const leafSig = tc1Sig.slice(leafPubOffset + 56);

  assert(
    await lmsVerify(tc1Msg, leafSig, leafPub),
    'RFC 8554 Appendix F leaf LMS signature did not verify',
  );
  logPass('RFC 8554 Appendix F: leaf LMS signature verifies over the published message');

  /* The root signs the child public key serialized per RFC 8554 Section 5.3, with no
     level prefix. hss.ts prepended u32(levelUsed) here until 2026-10-20, which is
     exactly why the full vector would not verify through hssVerify while both of its
     LMS signatures verified through lmsVerify. */
  const signedLeafPub = concatBytes(
    u32(leafPub.typecode),
    u32(leafPub.otsTypecode),
    leafPub.I,
    leafPub.T1,
  );
  assert(
    await lmsVerify(signedLeafPub, rootSig, rootPub),
    'RFC 8554 Appendix F root LMS signature over the leaf public key did not verify',
  );
  logPass('RFC 8554 Appendix F: root LMS signature verifies over the leaf public key');

  /* Negative controls. Without these the two assertions above would also pass against
     a verifier that returned true unconditionally. */
  const bentMsg = Uint8Array.from(tc1Msg);
  bentMsg[0] ^= 0x01;
  assert(
    !(await lmsVerify(bentMsg, leafSig, leafPub)),
    'a flipped message byte still verified against the RFC vector',
  );
  const bentSig = Uint8Array.from(leafSig);
  bentSig[bentSig.length - 1] ^= 0x01;
  assert(
    !(await lmsVerify(tc1Msg, bentSig, leafPub)),
    'a flipped final auth-path byte still verified against the RFC vector',
  );
  logPass('RFC 8554 Appendix F: a bent message and a bent auth path are both rejected');

  console.log('Phase 2 gate passed');
}

run().catch((err: unknown) => {
  if (err instanceof Error) {
    console.error(`FAIL: ${err.message}`);
  } else {
    console.error('FAIL: Unknown error');
  }
  throw err;
});
