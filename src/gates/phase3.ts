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
  logPass(`hssKeygen completed in ${elapsedMs / 1000}s`);

  const message = textEncoder.encode('Test firmware signature');
  const hss1 = await hssSign(message, privateKey);
  const ok1 = await hssVerify(message, hss1, publicKey);
  assert(ok1, 'HSS sign + verify failed');
  logPass('HSS sign + verify round-trip');

  const hss2  = await hssSign(textEncoder.encode('Different message'), privateKey);
  const ok2 = await hssVerify(textEncoder.encode('Different message'), hss2, publicKey);
  assert(ok2, 'Second HSS signature failed');
  logPass('Second HSS signature verifies');

  const tampered = new Uint8Array(hss1);
  tampered[tampered.length - 1] ^= 0x01;
  const tamperedResult = await hssVerify(message, tampered, publicKey);
  assert(!tamperedResult, 'Tampered HSS signature should fail');
  logPass('Tampered HSS signature rejected');

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
