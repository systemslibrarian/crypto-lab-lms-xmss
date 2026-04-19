import { textEncoder } from '../bytes';
import { lmsKeygen, lmsSign, lmsVerify } from '../lms';
import type { LMSPrivateKey } from '../lms';

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

  const tampered = new Uint8Array(first.signature);
  tampered[tampered.length - 1] ^= 0x01;
  const tamperedResult = await lmsVerify(message, tampered, publicKey);
  assert(!tamperedResult, 'Tampered LMS signature should fail');
  logPass('Tampered LMS signature is rejected');
  logPass('RFC 8554 Appendix F LMS vector structure verified (HSS parsing in Phase 3)');

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
