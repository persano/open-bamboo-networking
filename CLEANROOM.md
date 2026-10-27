# Clean-room status

**Not claimed as of 2026-10-27.** Explicit project decision: a clean-room
posture is a later goal, tracked here so the claim never needs a re-audit
from scratch. Workspace-level provenance records live in
`INTERESTING_REPOS.md` (input rules per repo) and `BALTOBU_CROSSCHECK.md`
(cross-validation of adopted facts) at the workspace root.

## How the research corpus derives its facts

`research/` (see `research/00-intro.md`) is built from three sources, none
of them binary disassembly:

1. read-through of pinned `bambulab/BambuStudio` / `SoftFever/OrcaSlicer`
   sources (every Studio-side claim has file + line citations),
2. MITM captures of the stock plugin against Bambu cloud and LAN endpoints,
3. cross-ABI matrix runs of stock plugin versions against live printers.

Spec-layer adoption from the baltobu MIT docs is tagged per page
(cross-check rows #10–#18). Their raw decompile output
(`output/ghidra_decompile/`) is **never read and never vendored** — their
own clean-room rule, also ours.

## Known blockers to a clean-room claim

1. **Embedded vendor secret.** `kClientAuthSecret` in
   `src/appcert_cipher.cpp` was extracted from a live stock Bambu Studio
   memory dump (`tools/extract_key_from_dump.py`). Mitigation shipped
   2026-10-27: `OBN_CLIENT_AUTH_SECRET` (43 ASCII bytes) overrides it at
   runtime, and the no-embedded build path is strip-constant + env var or
   the manual `slicer_cert.pem` disk fallback (`cert_store.cpp`, ClusterM
   PR #95). The default build still embeds the value.
2. **Binary-analysis-derived knowledge in shipped source — not yet
   inventoried file-by-file.** Known instance: the app-cert custom-S-box
   AES-256-CTR cipher (`src/appcert_cipher.cpp`, `src/appcert_fetch.cpp`,
   `include/obn/appcert.hpp`) whose algorithm understanding ran through
   dump analysis and the community work it was ported from (ClusterM PR
   #67 discussion + BambuSlicerKeySaver commit `ac097b62`), validated
   against public KATs. The `server_wrap_key` is a public certificate
   (fact-level material, from the reverse-networking docs' `service.crt`).
   Any other shipped file whose derivation ran through binary analysis
   must be found in the provenance pass below.

## Input rules already in force

- baltobu repos: MIT fresh-prose docs are safe spec-layer input; raw
  decompile output never read, never vendored.
- AGPL repos (beambam, bambuddy, bami): facts only, never copy code.
- Unlicensed repos: facts only.
- The vendor binary itself: never redistributed (SHA-256 only).

## Upgrade path to a claim

1. Strip `kClientAuthSecret` from default builds (plumbing ready: env
   override + disk fallback above) or gate it behind an explicit build
   flag.
2. File-by-file provenance pass over `src/` — classify each file as
   MITM-derived / Studio-source-derived / community-derived /
   binary-analysis-derived; record the table here.
3. Only after 1 + 2: use "clean-room" wording in `README.md` and the
   workspace `PROJECT_OVERVIEW.md` (both currently use it loosely).
