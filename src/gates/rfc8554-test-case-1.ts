/*
 * RFC 8554 Appendix F, Test Case 1 — copied from the publication.
 *
 * Source: https://www.rfc-editor.org/rfc/rfc8554.txt
 *   sha256 d5bfdbd457dfe7bc5f67cc1f62482999c2f55bf8033f2af56da323f2ffc2c055
 *   Public key  Appendix F lines 2711-2720
 *   Message     Appendix F lines 2726-2737
 *   Signature   Appendix F lines 2753-2970
 *
 * COPIED FROM THE PUBLICATION, not regenerated. A vector produced by this lab, or by
 * any library, agrees with the code for the same reason it agrees with itself. The hex
 * below is the RFC's own hex column, 16 bytes per line exactly as the RFC groups it, so
 * it can be diffed against the document by eye.
 *
 * The extraction was checked against the RFC's own field definitions rather than
 * trusted, and the check caught a real bug: a first pass took hex runs of 8 or more
 * characters and so silently dropped the message's final line, `2e0a`, giving 160 bytes
 * where Appendix F shows 162. The truncated message made the leaf signature fail to
 * verify, which read exactly like a defect in this lab. The three lengths now agree
 * with the structures RFC 8554 Sections 3.3, 5.3 and 6.1 define:
 *
 *   public key  60 = u32(levels) + u32(LMS type) + u32(LM-OTS type) + I(16) + K(32)
 *   message    162 = ten 16-byte lines plus `2e0a`, the Tenth Amendment with a newline
 *   signature 2644 = u32(Nspk) + (lms_sig 1292 + lms_pub 56) + lms_sig 1292
 *
 * where lms_sig = u32(q) + lmots_sig(1124) + u32(LMS type) + path(h=5, 5 * 32), and
 * lmots_sig = u32(type) + C(32) + y(34 * 32) for LMOTS_SHA256_N32_W8.
 *
 * Parameters: LMS_SHA256_M32_H5 (0x05) at both levels, LMOTS_SHA256_N32_W8 (0x04).
 * Both are parameter sets this lab implements.
 */

/** HSS public key: u32(levels) || LMS public key. */
export const TC1_PUBLIC_KEY_HEX =
    '00000002000000050000000461a5d57d' +
    '37f5e46bfb7520806b07a1b850650e3b' +
    '31fe4a773ea29a07f09cf2ea30e579f0' +
    'df58ef8e298da0434cb2b878';

/** The message: the Tenth Amendment to the US Constitution, with a trailing newline. */
export const TC1_MESSAGE_HEX =
    '54686520706f77657273206e6f742064' +
    '656c65676174656420746f2074686520' +
    '556e6974656420537461746573206279' +
    '2074686520436f6e737469747574696f' +
    '6e2c206e6f722070726f686962697465' +
    '6420627920697420746f207468652053' +
    '74617465732c20617265207265736572' +
    '76656420746f20746865205374617465' +
    '7320726573706563746976656c792c20' +
    '6f7220746f207468652070656f706c65' +
    '2e0a';

/** HSS signature: u32(Nspk) || (sig[0] || pub[1]) || sig[1]. */
export const TC1_SIGNATURE_HEX =
    '000000010000000500000004d32b5667' +
    '1d7eb98833c49b433c272586bc4a1c8a' +
    '8970528ffa04b966f9426eb9965a25bf' +
    'd37f196b9073f3d4a232feb69128ec45' +
    '146f86292f9dff9610a7bf95a64c7f60' +
    'f6261a62043f86c70324b7707f5b4a8a' +
    '6e19c114c7be866d488778a0e05fd5c6' +
    '509a6e61d559cf1a77a970de927d60c7' +
    '0d3de31a7fa0100994e162a2582e8ff1' +
    'b10cd99d4e8e413ef469559f7d7ed12c' +
    '838342f9b9c96b83a4943d1681d84b15' +
    '357ff48ca579f19f5e71f18466f2bbef' +
    '4bf660c2518eb20de2f66e3b14784269' +
    'd7d876f5d35d3fbfc7039a462c716bb9' +
    'f6891a7f41ad133e9e1f6d9560b960e7' +
    '777c52f060492f2d7c660e1471e07e72' +
    '655562035abc9a701b473ecbc3943c6b' +
    '9c4f2405a3cb8bf8a691ca51d3f6ad2f' +
    '428bab6f3a30f55dd9625563f0a75ee3' +
    '90e385e3ae0b906961ecf41ae073a059' +
    '0c2eb6204f44831c26dd768c35b167b2' +
    '8ce8dc988a3748255230cef99ebf14e7' +
    '30632f27414489808afab1d1e783ed04' +
    '516de012498682212b07810579b25036' +
    '5941bcc98142da13609e9768aaf65de7' +
    '620dabec29eb82a17fde35af15ad238c' +
    '73f81bdb8dec2fc0e7f932701099762b' +
    '37f43c4a3c20010a3d72e2f606be108d' +
    '310e639f09ce7286800d9ef8a1a40281' +
    'cc5a7ea98d2adc7c7400c2fe5a101552' +
    'df4e3cccfd0cbf2ddf5dc6779cbbc68f' +
    'ee0c3efe4ec22b83a2caa3e48e0809a0' +
    'a750b73ccdcf3c79e6580c154f8a58f7' +
    'f24335eec5c5eb5e0cf01dcf44394240' +
    '95fceb077f66ded5bec73b27c5b9f64a' +
    '2a9af2f07c05e99e5cf80f00252e39db' +
    '32f6c19674f190c9fbc506d826857713' +
    'afd2ca6bb85cd8c107347552f30575a5' +
    '417816ab4db3f603f2df56fbc413e7d0' +
    'acd8bdd81352b2471fc1bc4f1ef296fe' +
    'a1220403466b1afe78b94f7ecf7cc62f' +
    'b92be14f18c2192384ebceaf8801afdf' +
    '947f698ce9c6ceb696ed70e9e87b0144' +
    '417e8d7baf25eb5f70f09f016fc925b4' +
    'db048ab8d8cb2a661ce3b57ada67571f' +
    '5dd546fc22cb1f97e0ebd1a65926b123' +
    '4fd04f171cf469c76b884cf3115cce6f' +
    '792cc84e36da58960c5f1d760f32c12f' +
    'aef477e94c92eb75625b6a371efc72d6' +
    '0ca5e908b3a7dd69fef0249150e3eebd' +
    'fed39cbdc3ce9704882a2072c75e1352' +
    '7b7a581a556168783dc1e97545e31865' +
    'ddc46b3c957835da252bb7328d3ee206' +
    '2445dfb85ef8c35f8e1f3371af34023c' +
    'ef626e0af1e0bc017351aae2ab8f5c61' +
    '2ead0b729a1d059d02bfe18efa971b73' +
    '00e882360a93b025ff97e9e0eec0f3f3' +
    'f13039a17f88b0cf808f488431606cb1' +
    '3f9241f40f44e537d302c64a4f1f4ab9' +
    '49b9feefadcb71ab50ef27d6d6ca8510' +
    'f150c85fb525bf25703df7209b6066f0' +
    '9c37280d59128d2f0f637c7d7d7fad4e' +
    'd1c1ea04e628d221e3d8db77b7c878c9' +
    '411cafc5071a34a00f4cf07738912753' +
    'dfce48f07576f0d4f94f42c6d76f7ce9' +
    '73e9367095ba7e9a3649b7f461d9f9ac' +
    '1332a4d1044c96aefee67676401b6445' +
    '7c54d65fef6500c59cdfb69af7b6dddf' +
    'cb0f086278dd8ad0686078dfb0f3f79c' +
    'd893d314168648499898fbc0ced5f95b' +
    '74e8ff14d735cdea968bee7400000005' +
    'd8b8112f9200a5e50c4a262165bd342c' +
    'd800b8496810bc716277435ac376728d' +
    '129ac6eda839a6f357b5a04387c5ce97' +
    '382a78f2a4372917eefcbf93f63bb591' +
    '12f5dbe400bd49e4501e859f885bf073' +
    '6e90a509b30a26bfac8c17b5991c157e' +
    'b5971115aa39efd8d564a6b90282c316' +
    '8af2d30ef89d51bf14654510a12b8a14' +
    '4cca1848cf7da59cc2b3d9d0692dd2a2' +
    '0ba3863480e25b1b85ee860c62bf5136' +
    '0000000500000004d2f14ff6346af964' +
    '569f7d6cb880a1b66c5004917da6eafe' +
    '4d9ef6c6407b3db0e5485b122d9ebe15' +
    'cda93cfec582d7ab0000000a00000004' +
    '0703c491e7558b35011ece3592eaa5da' +
    '4d918786771233e8353bc4f62323185c' +
    '95cae05b899e35dffd71705470620998' +
    '8ebfdf6e37960bb5c38d7657e8bffeef' +
    '9bc042da4b4525650485c66d0ce19b31' +
    '7587c6ba4bffcc428e25d08931e72dfb' +
    '6a120c5612344258b85efdb7db1db9e1' +
    '865a73caf96557eb39ed3e3f426933ac' +
    '9eeddb03a1d2374af7bf771855774562' +
    '37f9de2d60113c23f846df26fa942008' +
    'a698994c0827d90e86d43e0df7f4bfcd' +
    'b09b86a373b98288b7094ad81a0185ac' +
    '100e4f2c5fc38c003c1ab6fea479eb2f' +
    '5ebe48f584d7159b8ada03586e65ad9c' +
    '969f6aecbfe44cf356888a7b15a3ff07' +
    '4f771760b26f9c04884ee1faa329fbf4' +
    'e61af23aee7fa5d4d9a5dfcf43c4c26c' +
    'e8aea2ce8a2990d7ba7b57108b47dabf' +
    'beadb2b25b3cacc1ac0cef346cbb90fb' +
    '044beee4fac2603a442bdf7e507243b7' +
    '319c9944b1586e899d431c7f91bcccc8' +
    '690dbf59b28386b2315f3d36ef2eaa3c' +
    'f30b2b51f48b71b003dfb08249484201' +
    '043f65f5a3ef6bbd61ddfee81aca9ce6' +
    '0081262a00000480dcbc9a3da6fbef5c' +
    '1c0a55e48a0e729f9184fcb1407c3152' +
    '9db268f6fe50032a363c9801306837fa' +
    'fabdf957fd97eafc80dbd165e435d0e2' +
    'dfd836a28b354023924b6fb7e48bc0b3' +
    'ed95eea64c2d402f4d734c8dc26f3ac5' +
    '91825daef01eae3c38e3328d00a77dc6' +
    '57034f287ccb0f0e1c9a7cbdc828f627' +
    '205e4737b84b58376551d44c12c3c215' +
    'c812a0970789c83de51d6ad787271963' +
    '327f0a5fbb6b5907dec02c9a90934af5' +
    'a1c63b72c82653605d1dcce51596b3c2' +
    'b45696689f2eb382007497557692caac' +
    '4d57b5de9f5569bc2ad0137fd47fb47e' +
    '664fcb6db4971f5b3e07aceda9ac130e' +
    '9f38182de994cff192ec0e82fd6d4cb7' +
    'f3fe00812589b7a7ce51544045643301' +
    '6b84a59bec6619a1c6c0b37dd1450ed4' +
    'f2d8b584410ceda8025f5d2d8dd0d217' +
    '6fc1cf2cc06fa8c82bed4d944e71339e' +
    'ce780fd025bd41ec34ebff9d4270a322' +
    '4e019fcb444474d482fd2dbe75efb203' +
    '89cc10cd600abb54c47ede93e08c114e' +
    'db04117d714dc1d525e11bed8756192f' +
    '929d15462b939ff3f52f2252da2ed64d' +
    '8fae88818b1efa2c7b08c8794fb1b214' +
    'aa233db3162833141ea4383f1a6f120b' +
    'e1db82ce3630b3429114463157a64e91' +
    '234d475e2f79cbf05e4db6a9407d72c6' +
    'bff7d1198b5c4d6aad2831db61274993' +
    '715a0182c7dc8089e32c8531deed4f74' +
    '31c07c02195eba2ef91efb5613c37af7' +
    'ae0c066babc69369700e1dd26eddc0d2' +
    '16c781d56e4ce47e3303fa73007ff7b9' +
    '49ef23be2aa4dbf25206fe45c20dd888' +
    '395b2526391a724996a44156beac8082' +
    '12858792bf8e74cba49dee5e8812e019' +
    'da87454bff9e847ed83db07af3137430' +
    '82f880a278f682c2bd0ad6887cb59f65' +
    '2e155987d61bbf6a88d36ee93b6072e6' +
    '656d9ccbaae3d655852e38deb3a2dcf8' +
    '058dc9fb6f2ab3d3b3539eb77b248a66' +
    '1091d05eb6e2f297774fe6053598457c' +
    'c61908318de4b826f0fc86d4bb117d33' +
    'e865aa805009cc2918d9c2f840c4da43' +
    'a703ad9f5b5806163d7161696b5a0adc' +
    '00000005d5c0d1bebb06048ed6fe2ef2' +
    'c6cef305b3ed633941ebc8b3bec97387' +
    '54cddd60e1920ada52f43d055b5031ce' +
    'e6192520d6a5115514851ce7fd448d4a' +
    '39fae2ab2335b525f484e9b40d6a4a96' +
    '9394843bdcf6d14c48e8015e08ab9266' +
    '2c05c6e9f90b65a7a6201689999f32bf' +
    'd368e5e3ec9cb70ac7b8399003f175c4' +
    '0885081a09ab3034911fe125631051df' +
    '0408b3946b0bde790911e8978ba07dd5' +
    '6c73e7ee';
