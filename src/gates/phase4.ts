import { bytesEqual, concatBytes, textEncoder } from '../bytes';
import { computeAuthPath, lmsKeygen, lmsSign, lmsVerify } from '../lms';
import { lmotsSign } from '../lmots';
import { forgeSignature, gatherKnowledge, stageReusedSignatures } from '../forge';
import type { LeakedSignature } from '../forge';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function logPass(message: string): void {
  console.log(`PASS: ${message}`);
}

const REUSE_COUNT = 16;

async function run(): Promise<void> {
  // Small tree keeps keygen fast; the index-reuse forgery lives entirely in the
  // LM-OTS layer and is independent of the Merkle tree height.
  const { privateKey, publicKey } = await lmsKeygen(undefined, { h: 5 });
  const I = privateKey.I;
  const reusedIndex = 3;
  const authPath = concatBytes(...computeAuthPath(privateKey.treeNodes, reusedIndex, privateKey.h));

  // The signer's catastrophic mistake: REUSE_COUNT distinct messages all signed
  // at the same one-time index. These leaked signatures are all the attacker sees.
  const leakedMessages = Array.from({ length: REUSE_COUNT }, (_, i) =>
    textEncoder.encode(`firmware build #${i} (signed honestly)`),
  );
  const leaked: LeakedSignature[] = await stageReusedSignatures(
    {
      I,
      q: reusedIndex,
      lmsTypecode: privateKey.typecode,
      authPath,
      signOts: (m) => lmotsSign(m, { I, q: reusedIndex, seed: privateKey.seed }),
    },
    leakedMessages,
  );
  assert(leaked.length === REUSE_COUNT, 'staging did not produce the expected leak count');

  // Sanity: every leaked signature is itself a valid signature.
  for (const l of leaked) {
    assert(await lmsVerify(l.message, l.signature, publicKey), 'a leaked signature failed to verify');
  }
  logPass(`${REUSE_COUNT} honest signatures reuse index ${reusedIndex} and all verify`);

  // Attacker side: derive knowledge from the leak using only public data.
  const knowledge = await gatherKnowledge(I, leaked);
  assert(knowledge.q === reusedIndex, 'recovered index mismatch');

  // Forge a message the signer never approved.
  const forgedMessage = textEncoder.encode('install rootkit.bin && exfiltrate keys');
  assert(
    !leakedMessages.some((m) => bytesEqual(m, forgedMessage)),
    'forged message must be one the signer never signed',
  );

  const result = await forgeSignature(I, knowledge, forgedMessage, privateKey.typecode);
  assert(result !== null, 'forgery failed to find a reachable randomizer within the attempt budget');
  if (result === null) {
    throw new Error('unreachable');
  }
  logPass(`forged a never-signed message after ${result.attempts} randomizer attempt(s)`);

  // The decisive assertion: the REAL public key accepts the forgery.
  const forgedAccepted = await lmsVerify(forgedMessage, result.signature, publicKey);
  assert(forgedAccepted, 'CRITICAL: forged signature did not verify (attack model broken)');
  logPass('forged signature is ACCEPTED by the genuine LMS public key');

  // The scheme itself is sound: an honest signature at a fresh, never-reused index
  // still verifies. Only reuse breaks it.
  const honest = await lmsSign(textEncoder.encode('honest firmware at index 0'), privateKey);
  assert(
    await lmsVerify(textEncoder.encode('honest firmware at index 0'), honest.signature, publicKey),
    'honest signature at a fresh index should still verify',
  );
  logPass('honest signatures at fresh indexes remain valid (only reuse is fatal)');

  console.log('Phase 4 gate passed');
}

run().catch((err: unknown) => {
  if (err instanceof Error) {
    console.error(`FAIL: ${err.message}`);
  } else {
    console.error('FAIL: Unknown error');
  }
  throw err;
});
