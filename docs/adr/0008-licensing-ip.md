# ADR 0008: Licensing and clean-spin-out IP hygiene

Status: accepted

## Decision
- **AGPL-3.0-or-later** core. The network-use clause aligns with the verifiability /
  open-core wedge (operators of a network service must offer source).
- **DCO** sign-off required on every commit (CI-enforced); **CLA** for clean IP
  ownership enabling a possible future spin-out built without third-party (TraceMem)
  resources. Single dedicated copyright holder.
- Monorepo, single Cargo workspace (`crates/*`, `bins/*`, `xtask`).

## Dependency license hygiene (spin-out-safe)
- Trustee: Apache-2.0. `gix`: MIT/Apache-2.0. aws-lc-rs/aws-lc-sys: Apache-2.0 after
  the ~Mar 2026 relicense (old OpenSSL advertising clause resolved). x25519-dalek:
  BSD-3-Clause.
- `cargo deny` enforces the license allow-list AND the provider-neutrality ban-list
  (no cloud attestation crates).

## Note
`LICENSE` carries the SPDX header and the standard AGPL notice. The full canonical
AGPL-3.0 text must be vendored verbatim as `LICENSE.AGPL-3.0.txt` at release time
(`curl -fsSL https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE.AGPL-3.0.txt`); a
legal document is never hand-transcribed.
