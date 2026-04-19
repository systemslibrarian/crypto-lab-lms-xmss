import { bytesToHex, hexToBytes, textEncoder } from '../bytes';
import { lmotsCandidatePublicKey, lmotsKeygen, lmotsSign, lmotsVerify, sha256 } from '../lmots';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function logPass(message: string): void {
  console.log(`PASS: ${message}`);
}

async function run(): Promise<void> {
  const emptyHash = bytesToHex(await sha256(new Uint8Array()));
  assert(
    emptyHash === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'sha256(empty) mismatch',
  );
  logPass('sha256(empty) matches known digest');

  const I = hexToBytes('00112233445566778899aabbccddeeff');
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');

  const { privateKey, publicKey } = await lmotsKeygen(I, 7, seed);
  const message = textEncoder.encode('Firmware v2.3.1 release');
  const signature = await lmotsSign(message, privateKey);
  const verified = await lmotsVerify(message, signature, publicKey, I, 7);
  assert(verified !== null, 'LM-OTS round-trip failed');
  logPass('LM-OTS keygen + sign + verify round-trip');

  const tamperedSig = new Uint8Array(signature);
  tamperedSig[tamperedSig.length - 1] ^= 0x01;
  const tamperedResult = await lmotsVerify(message, tamperedSig, publicKey, I, 7);
  assert(tamperedResult === null, 'Tampered signature should fail verification');
  logPass('Tampered signature is rejected');

  const signature2 = await lmotsSign(textEncoder.encode('Firmware v2.3.2 release'), privateKey);
  assert(bytesToHex(signature) !== bytesToHex(signature2), 'Different messages should produce different signatures');
  logPass('Different messages produce different signatures');

  // RFC 8554 Appendix F Test Case 1 message/q/I and LM-OTS signature body.
  // We validate the signature shape and derive a stable candidate LM-OTS key hash.
  const rfcI = hexToBytes('61a5d57d37f5e46bfb7520806b07a1b8');
  const rfcQ = 5;
  const rfcMessage = hexToBytes(
    '54686520706f77657273206e6f742064656c65676174656420746f2074686520556e6974656420537461746573206279202074686520436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920697420746f20746865205374617465732c2061726520726573657276656420746f207468652053746174657320726573706563746976656c792c206f7220746f207468652070656f706c652e0a'.replace(
      /\s+/g,
      '',
    ),
  );
  const rfcSigHex = (
    '00000004' +
    'd32b56671d7eb98833c49b433c272586bc4a1c8a8970528ffa04b966f9426eb9' +
    '965a25bfd37f196b9073f3d4a232feb69128ec45146f86292f9dff9610a7bf95' +
    'a64c7f60f6261a62043f86c70324b7707f5b4a8a6e19c114c7be866d488778a0' +
    'e05fd5c6509a6e61d559cf1a77a970de927d60c70d3de31a7fa0100994e162a2' +
    '582e8ff1b10cd99d4e8e413ef469559f7d7ed12c838342f9b9c96b83a4943d16' +
    '81d84b15357ff48ca579f19f5e71f18466f2bbef4bf660c2518eb20de2f66e3b' +
    '14784269d7d876f5d35d3fbfc7039a462c716bb9f6891a7f41ad133e9e1f6d95' +
    '60b960e7777c52f060492f2d7c660e1471e07e72655562035abc9a701b473ecb' +
    'c3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f428bab6f3a30f55dd9625563' +
    'f0a75ee390e385e3ae0b906961ecf41ae073a0590c2eb6204f44831c26dd768c' +
    '35b167b28ce8dc988a3748255230cef99ebf14e730632f27414489808afab1d1' +
    'e783ed04516de012498682212b07810579b250365941bcc98142da13609e9768' +
    'aaf65de7620dabec29eb82a17fde35af15ad238c73f81bdb8dec2fc0e7f93270' +
    '1099762b37f43c4a3c20010a3d72e2f606be108d310e639f09ce7286800d9ef8' +
    'a1a40281cc5a7ea98d2adc7c7400c2fe5a101552df4e3cccfd0cbf2ddf5dc677' +
    '9cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0a750b73ccdcf3c79e6580c15' +
    '4f8a58f7f24335eec5c5eb5e0cf01dcf4439424095fceb077f66ded5bec73b27' +
    'c5b9f64a2a9af2f07c05e99e5cf80f00252e39db32f6c19674f190c9fbc506d8' +
    '26857713afd2ca6bb85cd8c107347552f30575a5417816ab4db3f603f2df56fb' +
    'c413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403466b1afe78b94f7e' +
    'cf7cc62fb92be14f18c2192384ebceaf8801afdf947f698ce9c6ceb696ed70e9' +
    'e87b0144417e8d7baf25eb5f70f09f016fc925b4db048ab8d8cb2a661ce3b57a' +
    'da67571f5dd546fc22cb1f97e0ebd1a65926b1234fd04f171cf469c76b884cf3' +
    '115cce6f792cc84e36da58960c5f1d760f32c12faef477e94c92eb75625b6a37' +
    '1efc72d60ca5e908b3a7dd69fef0249150e3eebdfed39cbdc3ce9704882a2072' +
    'c75e13527b7a581a556168783dc1e97545e31865ddc46b3c957835da252bb732' +
    '8d3ee2062445dfb85ef8c35f8e1f3371af34023cef626e0af1e0bc017351aae2' +
    'ab8f5c612ead0b729a1d059d02bfe18efa971b7300e882360a93b025ff97e9e0' +
    'eec0f3f3f13039a17f88b0cf808f488431606cb13f9241f40f44e537d302c64a' +
    '4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510f150c85fb525bf25703df720' +
    '9b6066f09c37280d59128d2f0f637c7d7d7fad4ed1c1ea04e628d221e3d8db77' +
    'b7c878c9411cafc5071a34a00f4cf07738912753dfce48f07576f0d4f94f42c6' +
    'd76f7ce973e9367095ba7e9a3649b7f461d9f9ac1332a4d1044c96aefee67676' +
    '401b64457c54d65fef6500c59cdfb69af7b6dddfcb0f086278dd8ad0686078df' +
    'b0f3f79cd893d314168648499898fbc0ced5f95b74e8ff14d735cdea968bee74'
  ).toLowerCase();
  const rfcSig = hexToBytes(rfcSigHex);
  assert(rfcSig.length === 1124, 'RFC LM-OTS signature length mismatch');

  const candidate = await lmotsCandidatePublicKey(
    rfcMessage,
    rfcSig,
    rfcI,
    rfcQ,
  );
  assert(candidate !== null, 'RFC Appendix F LM-OTS vector failed');
  if (candidate === null) {
    throw new Error('RFC Appendix F LM-OTS vector produced null candidate');
  }
  const candidateHex = bytesToHex(candidate);
  assert(
    candidateHex === '8560c5688ade2de58e07a5f729b074e48000d45aeb160f9bc7d01bdb279d3f48',
    `RFC Appendix F LM-OTS vector mismatch: ${candidateHex}`,
  );
  logPass('RFC 8554 Appendix F LM-OTS vector check');

  console.log('Phase 1 gate passed');
}

run().catch((err: unknown) => {
  if (err instanceof Error) {
    console.error(`FAIL: ${err.message}`);
  } else {
    console.error('FAIL: Unknown error');
  }
  throw err;
});
