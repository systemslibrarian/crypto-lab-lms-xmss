# crypto-lab-lms-xmss

## What It Is

Browser-based educational demo of Leighton-Micali Signatures (LMS) and the Hierarchical Signature System (HSS), following RFC 8554 and NIST SP 800-208 using SHA-256.

This project demonstrates stateful hash-based signatures in the browser:

- LM-OTS (Winternitz one-time signatures), parameter set `LMOTS_SHA256_N32_W8`
- LMS Merkle signatures, parameter set `LMS_SHA256_M32_H10` (1024 signatures per tree)
- Two-level HSS hierarchy (root `H=5`, leaf `H=10`) for 32,768 total signatures

All hashing uses Web Crypto `subtle.digest('SHA-256', ...)`.

The UI is built as seven exhibits focused on the key operational fact most demos skip: LMS is stateful, and index reuse is catastrophic. Exhibit 5 doesn't just assert this — it mounts a **live, working forgery**: reuse one one-time-signature index a handful of times and an attacker, using only the leaked signatures, forges a brand-new message that the genuine public key accepts.

The exhibits build the picture bottom-up so the forgery lands as understanding, not spectacle:

1. **Merkle Tree of OTS Keys** — generate `LMS_SHA256_M32_H10` (1024 leaves) and inspect each leaf's state.
2. **Signing Consumes State** — sign a message, watch `q` (the leaf index) advance and localStorage enforce single use.
3. **Inside One OTS — the Winternitz Chain** — draw the one-way hash chains a leaf is made of; sign message A, then see that a different message B needs a *shallower* depth an attacker can't reach from one signature. This is the prerequisite the forgery weaponizes.
4. **Authentication Path Walk** — a real slice of the same Merkle tree, climbing sibling-by-sibling from the signed leaf up to the root `T[1]`.
5. **Index Reuse → Live Forgery** — dial how many times the signer reused one index and watch the attacker's per-position reachable depth drop until a chosen malicious message is forgeable and the genuine public key accepts it.
6. **HSS Hierarchy** — a two-level tree signing 32,768 messages total.
7. **When Stateful Signatures Win** — where LMS/XMSS is the right tool and where it is not.

Every symbol (`I`, `q`, `T[1]`, LM-OTS, depth) is glossed inline at the top of the page so a newcomer to RFC 8554 notation can follow along, while the real per-position depth vectors and honest reach caveats keep it worthwhile for a professional.

## When to Use It

Use this demo when you need to:

- Teach the difference between stateful hash-based signatures (LMS/XMSS) and stateless schemes (SLH-DSA)
- Show why LMS can have tighter signature sizes than stateless hash-based alternatives
- Demonstrate Merkle-authentication-path verification step by step
- Explain why production LMS deployments require strict state governance (HSM counters, ceremonies, locks)
- Do NOT use this code as production signing infrastructure — it is intentionally educational and browser-first.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-lms-xmss](https://systemslibrarian.github.io/crypto-lab-lms-xmss/)**

Walk the seven exhibits: generate LM-OTS and LMS keys, see the one-way Winternitz chains inside a single leaf, step through Merkle-authentication-path verification, build the two-level HSS hierarchy, and — in Exhibit 5 — deliberately reuse an index to watch a working forgery be constructed from the leaked signatures and accepted by the genuine public key.

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

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-lms-xmss
cd crypto-lab-lms-xmss
npm install
npm run dev
```

## Related Demos

- [crypto-lab-lms-ledger](https://systemslibrarian.github.io/crypto-lab-lms-ledger/) — sibling LMS/HSS demo focused on key-state management.
- [crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) — stateless hash-based signatures (FIPS 205).
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — Merkle tree construction and inclusion proofs.
- [crypto-lab-falcon-seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — NTRU lattice signatures for contrast.
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA lattice-based signatures (FIPS 204).

## How the Forgery Works

Winternitz hash chains are one-way: a chain value at depth `d` can be advanced to any depth `≥ d`, but never reversed. A single LM-OTS signature reveals, for each of the 34 positions, the chain value at the depth that message required. Reuse the same index across `k` messages and the attacker learns each position's value at the *lowest* depth seen across all of them. The checksum that normally blocks single-signature forgery is overcome by grinding the signature randomizer `C` until a chosen message's required depths all sit at or above the known depths — then each position is rebuilt by chaining forward. The result reconstructs the real public key and verifies. See `src/forge.ts`; the attack is exercised end-to-end in `src/gates/phase4.ts`.

## Tests

The crypto is validated against RFC 8554 test vectors and the reuse-forgery is proven end-to-end. CI (`.github/workflows/ci.yml`) runs the type-check and the full gate suite on every push and pull request, and the GitHub Pages deploy is gated on the same checks.

```bash
npm test          # type-check is separate; this runs all four gates
npm run typecheck
```

Individual phase gates:

```bash
npm run gate:phase1   # LM-OTS primitives + RFC 8554 Appendix F vector
npm run gate:phase2   # LMS Merkle sign/verify + index-reuse refusal
npm run gate:phase3   # HSS hierarchy, rollover, tamper rejection
npm run gate:phase4   # live index-reuse forgery is accepted by the real key
```

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
