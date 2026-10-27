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
2. **Binary-analysis-derived knowledge in shipped source — inventoried
   2026-10-27, see the table below.** Sole instance in `src/`: the app-cert
   pair (`src/appcert_cipher.cpp`, `src/appcert_fetch.cpp`,
   `include/obn/appcert.hpp`) — secret recovered from a memory dump, cipher
   understanding ran through dump analysis + the community work it was
   ported from (ClusterM PR #67 discussion + BambuSlicerKeySaver commit
   `ac097b62`), validated against public KATs. The `server_wrap_key` is a
   public certificate (fact-level material, reverse-networking
   `service.crt`). No other shipped file shows binary-analysis markers.

## Provenance of every shipped file under `src/` (2026-10-27)

Method: per-file marker scan (`PROVENANCE` / `ported from` / `MITM` /
`on the wire` / `slic3r/` / `issue #N` / `disassembl|ghidra|rodata` /
`research/` citations) over every tracked `.cpp` / `.h` / `.hpp`, plus the
per-file header comments. Files are listed under their primary basis; most
protocol files are mixed (Studio contract + wire confirmation), noted where
the markers are strongest. "Research-cited" = facts documented in
`research/` pages (Studio source / MITM / matrix runs — the three sources
above).

| Class | Files | Evidence |
|-------|-------|----------|
| **Binary-analysis-derived** | `appcert_cipher.cpp`, `appcert_fetch.cpp` (+ their `include/obn/appcert.hpp`) | `PROVENANCE` block: secret from `tools/extract_key_from_dump.py` memory dump; cipher "ported 1:1" from community PR #67 / BambuSlicerKeySaver lineage; KATs from `tools/fetch_slicer_credentials.py --self-test` |
| **Vendor data (facts, no code)** | `err_table.cpp`, `err_table_data.cpp` (auto-generated) | ATILLLLITA/OpenBambuFarmAPI `farm-errors.md` (GNU FDL) + PandaSpy HMS `en.json` asset, both attributed in-file |
| **Wire (MITM) primary** | `camera/ICameraSource.hpp`, `camera/TutkCameraSource.cpp`, `camera/TutkCameraSource.hpp`, `camera/tutk/Fec.cpp`, `camera/tutk/Fec.hpp`, `camera/tutk/IotcClient.cpp`, `camera/tutk/IotcProtocol.hpp`, `camera/tutk/TutkSession.cpp`, `camera/tutk/TutkSession.hpp`, `camera_probe.cpp`, `camera_url.cpp`, `abi_http.cpp`, `abi_makerworld.cpp`, `abi_user.cpp`, `cloud_auth.cpp`, `cloud_print.cpp`, `cloud_filament.cpp`, `cloud_presets.cpp`, `ftps.cpp`, `ftps_parse.hpp`, `mqtt_client.cpp`, `bind_cloud.cpp`, `lan_bind_tcp.cpp`, `lan_session.cpp`, `ssdp.cpp`, `tunnel_local.cpp`, `tunnel_upload.cpp`, `tls_dial.cpp`, `cover_cache.cpp`, `cover_server.cpp` | `WIRE`/`RESEARCH` markers; TUTK client explicitly "as observed on the wire" (clean-room P2P, `SOLUTIONS_AND_FINDINGS.md` §3); `bind_cloud` "Stock: POST/GET…" comments |
| **Studio source primary** | `abi_bind.cpp`, `abi_callbacks.cpp`, `abi_camera.cpp`, `abi_cloud.cpp`, `abi_filament.cpp`, `abi_ft.cpp`, `abi_lan.cpp`, `abi_lifecycle.cpp`, `abi_meta.cpp`, `abi_presets.cpp`, `abi_print.cpp`, `abi_track.cpp`, `print_job.cpp`, `signing.cpp`, `config.cpp`, `lan_tls.cpp`, `cert_store.cpp`, `auth.cpp`, `state.cpp`, `print_job_naming.cpp`, `print_params_ftp_prefs.cpp` | `STUDIO` markers / in-file Studio citations (`abi_ft`: `slic3r/Utils/FileTransferUtils.hpp`; `print_job`: `PrintJob::process` lan branch); ABI contract = Studio C ABI |
| **Community-derived (published, license-checked)** | `cover_key.cpp` (bambuddy PR #2931 — AGPL, facts only, stated in-file), `agent.cpp`, `openssl_host_check.cpp`; issue-driven fixes inside `abi_user.cpp`, `cloud_print.cpp`, `tunnel_local.cpp` | `COMMUNITY`/`issue #N` markers; fact-level adoption per `INTERESTING_REPOS.md` license rule |
| **Self-authored infrastructure** | `json_lite.cpp`, `log.cpp`, `os_compat.cpp`, `net_compat.cpp`, `http_client.cpp`, `cloud_ca_bundle.cpp`, `cloud_session.cpp`, `dll_main.cpp`, `plugin_load_banner.cpp`, `oss_sign.cpp` | no provenance markers; generic plumbing / standard-algorithm signing (AWS SigV4, Aliyun OSS), behavior pinned by own tests |

All 68 tracked files under `src/` are listed above (mixed files sit under
their primary basis: `abi_http`/`abi_makerworld`/`abi_user` are ABI shims
whose *contract* is Studio but whose wire details are MITM-confirmed;
`cloud_print.cpp` mixes all three non-binary classes).

**Caveats:** (a) marker absence is not proof — files classed
"self-authored" or "Studio primary" without inline citations rest on the
`research/` pages that motivated them, which are themselves MITM/Studio
derived (fact-level, not code). (b) `research/08.06-bind.md` records a
"rodata-recovered" key superset — a binary-derived *fact* in the research
corpus, exact nesting not disassembled, cross-checked against MITM. Facts
are not copyrightable; no code came from it. (c) The TUTK client derives
from wire observation only — the SDK itself was never decompiled.

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
2. ~~File-by-file provenance pass over `src/`~~ — **done 2026-10-27**, table
   above; all 68 tracked files classified, sole binary-analysis instance =
   the app-cert pair.
3. Only after 1 + 2: use "clean-room" wording in `README.md` and the
   workspace `PROJECT_OVERVIEW.md` (both currently use it loosely).
