import { textEncoder } from '../bytes';
import { hssKeygen, hssSign, hssVerify } from '../hss';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function logPass(message: string): void {
  console.log(`PASS: ${message}`);
}

async function run(): Promise<void> {
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
