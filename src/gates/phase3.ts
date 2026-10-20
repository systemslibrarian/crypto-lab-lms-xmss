import { hexToBytes, textEncoder } from '../bytes';
import { hssKeygen, hssSign, hssVerify } from '../hss';
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

/**
 * RFC 8554 Appendix F Test Case 1, end to end through hssVerify.
 *
 * Phase 2's RFC line used to say "(HSS parsing in Phase 3)" and Phase 3 did not parse
 * it either, so the vector was claimed by one gate, deferred to another, and checked by
 * neither. It runs first here because it needs no keygen: it is 30ms of real published
 * evidence in front of a 30-second generate-and-round-trip, and a round-trip can only
 * ever show this lab agreeing with itself.
 *
 * It is what caught the conformance bug. hss.ts prepended u32(levelUsed) to the child
 * public key the parent signs, where RFC 8554 Section 5.3 defines that serialization
 * with no such prefix, and wrote the active leaf-tree index into the leading u32 where
 * Section 6.1 defines Nspk. Both survived every round-trip test in this suite, because
 * the signer and the verifier made the same two assumptions.
 */
async function rfc8554TestCase1(): Promise<void> {
  const publicKeyBytes = hexToBytes(TC1_PUBLIC_KEY_HEX);
  const message = hexToBytes(TC1_MESSAGE_HEX);
  const signature = hexToBytes(TC1_SIGNATURE_HEX);
  const be = (b: Uint8Array, o: number): number =>
    ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

  const publicKey = {
    L: be(publicKeyBytes, 0),
    rootLMSPublicKey: {
      typecode: be(publicKeyBytes, 4),
      otsTypecode: be(publicKeyBytes, 8),
      I: publicKeyBytes.slice(12, 28),
      T1: publicKeyBytes.slice(28, 60),
    },
  };
  assert(publicKey.L === 2, `RFC public key declares L=${publicKey.L}, expected 2`);

  assert(
    await hssVerify(message, signature, publicKey),
    'RFC 8554 Appendix F Test Case 1 did not verify through hssVerify',
  );
  logPass('RFC 8554 Appendix F Test Case 1 verifies end to end through hssVerify');

  /* Negative controls, so the assertion above cannot be satisfied by a verifier that
     returns true unconditionally. Each bends one field the RFC defines. */
  const bentMessage = Uint8Array.from(message);
  bentMessage[0] ^= 0x01;
  assert(
    !(await hssVerify(bentMessage, signature, publicKey)),
    'a flipped message byte still verified',
  );

  const bentNspk = Uint8Array.from(signature);
  bentNspk[3] = 2; // Nspk = 2 against an L = 2 public key
  assert(
    !(await hssVerify(message, bentNspk, publicKey)),
    'an Nspk disagreeing with the public key still verified',
  );

  const bentLeafKey = Uint8Array.from(signature);
  bentLeafKey[4 + 4 + 1124 + 4 + 5 * 32 + 8] ^= 0x01; // one byte of the signed leaf I
  assert(
    !(await hssVerify(message, bentLeafKey, publicKey)),
    'a flipped byte of the signed leaf public key still verified',
  );

  const bentRoot = Uint8Array.from(signature);
  bentRoot[bentRoot.length - 1] ^= 0x01;
  assert(!(await hssVerify(message, bentRoot, publicKey)), 'a flipped final byte still verified');
  logPass('RFC 8554 Appendix F: bent message, Nspk, signed leaf key and tail all rejected');
}

async function run(): Promise<void> {
  await rfc8554TestCase1();

  const start = Date.now();
  const { privateKey, publicKey } = await hssKeygen();
  const elapsedMs = Date.now() - start;
  assert(elapsedMs < 300_000, `hssKeygen exceeded 5 minutes (${elapsedMs}ms)`);
  logPass(`hssKeygen completed in ${(elapsedMs / 1000).toFixed(2)}s`);

  const message = textEncoder.encode('Test firmware signature');
  const sig = await hssSign(message, privateKey);
  assert(await hssVerify(message, sig, publicKey), 'HSS sign + verify failed');
  logPass('HSS sign + verify round-trip');

  for (let i = 0; i < 10; i += 1) {
    const m = textEncoder.encode(`HSS message ${i}`);
    const s = await hssSign(m, privateKey);
    assert(await hssVerify(m, s, publicKey), `HSS signature ${i} failed`);
  }
  logPass('10 consecutive signatures verify');

  // Fast rollover test: tiny trees (root H=2, leaf H=2) force leaf regeneration quickly.
  const small = await hssKeygen(undefined, { rootH: 5, leafH: 5 });
  const initialLevel = small.privateKey.levelUsed;
  for (let i = 0; i < 40; i += 1) {
    const m = textEncoder.encode(`small-hss-${i}`);
    const s = await hssSign(m, small.privateKey);
    assert(await hssVerify(m, s, small.publicKey), `Small HSS signature ${i} failed`);
  }
  assert(
    small.privateKey.levelUsed > initialLevel,
    'Leaf regeneration did not advance levelUsed during exhaustion test',
  );
  logPass('Leaf tree exhaustion triggers regeneration');

  const tampered = new Uint8Array(sig);
  tampered[tampered.length - 1] ^= 0x01;
  const tamperedResult = await hssVerify(message, tampered, publicKey);
  assert(!tamperedResult, 'Tampered HSS signature should fail');
  logPass('Tampered signature fails at hierarchy verification');

  console.log('Phase 3 gate passed');
}

run().catch((err: unknown) => {
  if (err instanceof Error) {
    console.error(`FAIL: ${err.message}`);
  } else {
    console.error('FAIL: Unknown error');
  }
  throw err;
});
