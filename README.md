<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Mahdi Akil -->

# Read receipts for health twins

**Work in progress.**

A health twin's records should be readable only after the read has been written into a public log, where the patient's own monitor finds it. Every read would then leave a receipt the patient can check, one the hospital, the log operator or an AI agent cannot quietly skip.

## Claim we want to test

If twin records are encrypted under keys that 3 of 5 independent trustees release only for requests already in a witness-cosigned, append-only log, then no read succeeds without a receipt the patient's monitor sees within about one hour. The receipt must be in scope and name the actual reader.

The claim is refuted if any attack in a red-team harness obtains a record without such a receipt and without being flagged.

Out of scope by design: data already held in plaintext outside the key-release path, three or more trustees colluding, and what an authorised reader does with data after reading.

## Plan

- Append-only Merkle log (RFC 9162) with witness cosigning
- 3-of-5 key release gated on log inclusion
- Consult-scoped delegation to clinicians and AI agents, building on our [DPM 2026 paper](https://deic.uab.cat/dpm/dpm2026/resources/dpm2026-preproceedings.pdf)
- The patient's monitor
- An attack harness and a one-command experiment on synthetic data only

## Licence

The code is Apache-2.0 (`LICENSE`), the documentation CC BY 4.0, and generated data CC0 1.0. AI tools (Claude, Anthropic) assist with drafting code and text. The author reviews and is responsible for every claim.
