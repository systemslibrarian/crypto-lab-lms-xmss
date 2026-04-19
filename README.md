# crypto-lab-lms-xmss

Browser-based educational demo of Leighton-Micali Signatures (LMS) and the Hierarchical Signature System (HSS), following RFC 8554 and NIST SP 800-208 using SHA-256.

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
> 1 Corinthians 10:31

## What It Is

This project demonstrates stateful hash-based signatures in the browser:

- LM-OTS (Winternitz one-time signatures), parameter set `LMOTS_SHA256_N32_W8`
- LMS Merkle signatures, parameter set `LMS_SHA256_M32_H10` (1024 signatures per tree)
- Two-level HSS hierarchy (root `H=5`, leaf `H=10`) for 32,768 total signatures

All hashing uses Web Crypto `subtle.digest('SHA-256', ...)`.

The UI is built as five exhibits focused on the key operational fact most demos skip: LMS is stateful, and index reuse is catastrophic.

## When to Use It

Use this demo when you need to:

- Teach the difference between stateful hash-based signatures (LMS/XMSS) and stateless schemes (SLH-DSA)
- Show why LMS can have tighter signature sizes than stateless hash-based alternatives
- Demonstrate Merkle-authentication-path verification step by step
- Explain why production LMS deployments require strict state governance (HSM counters, ceremonies, locks)

Do not use this code as production signing infrastructure. It is intentionally educational and browser-first.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-lms-xmss/

## What Can Go Wrong

- State reuse destroys security: signing two different messages with the same LMS/LM-OTS index can leak enough structure to enable forgery.
- Key exhaustion is real: `H=10` means exactly 1024 signatures for one LMS tree.
- HSS delays exhaustion, it does not remove it: eventually root-tree slots run out too.
- Browser storage is not an HSM: this demo persists used indexes in localStorage for teaching, not for high-assurance key custody.
- Key generation cost is non-trivial in pure TypeScript/Web Crypto for large trees.

## Real-World Usage

LMS/XMSS were deployed in real firmware and platform trust chains before the latest lattice standards were finalized:

- Cisco firmware-signing paths
- AWS Nitro-related signing and attestation paths
- TPM 2.0 optional support tracks
- HSM and long-term-signature ecosystems where auditable state is feasible

Why teams still pick LMS in those niches:

- Security assumption is hash-based (collision/second-preimage resistance of SHA-256 family)
- Signature sizes are practical for many firmware and boot-chain contexts
- Operational model matches bounded-signature workflows with strong process controls

---

## Development

```bash
npm install
npm run dev
npm run build
```

Phase gates:

```bash
npm run gate:phase1
npm run gate:phase2
npm run gate:phase3
```
