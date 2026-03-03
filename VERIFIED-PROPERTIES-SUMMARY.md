# Verified Properties in minimal.dev Packages

## What we built

[gleisner-forge](crates/gleisner-forge/) is an incremental Nickel package
evaluator for [minimal.dev](https://minimal.dev) — a source-based Linux
distribution where every package is a Nickel declaration. We extended the
package schema and forge pipeline to support **formally verified properties**.

Packages can now declare `verified_properties` in their `attrs`:

```nickel
attrs = {
  verified_properties = [
    {
      property = "zlib_roundtrip",
      description = "decompress(compress(data)) = data for all compression levels (RFC 1950)",
      proof_system = "lean4",
      kernel_version = "leanprover/lean4:v4.29.0-rc2",
      specification_hash = "sha256:d5d9988f1fdc28c2a0a947190bc901559d54f75a",
      proof_hash = "sha256:41d114c4d451f5d8cd6f5f63a8d674fb4e793dec",
      proof_uri = "https://github.com/kim-em/lean-zip/blob/master/Zip/Spec/ZlibCorrect.lean",
    },
  ],
} | Attrs,
```

When the forge runs with `--verify`, it:

1. Detects packages with `verified_properties`
2. Extracts GitHub repo URLs from `proof_uri` fields
3. Clones the proof repo and runs `lake build`
4. Marks each property as `verified_by_forge: true/false/null`
5. Produces a `VerificationSummary` in the attestation output

## zlib as proof-of-concept

We used [lean-zip](https://github.com/kim-em/lean-zip) as the first
real-world test case. Three properties verified end-to-end:

| Property | Theorem | RFC |
|----------|---------|-----|
| `zlib_roundtrip` | `zlib_decompressSingle_compress` | 1950 |
| `deflate_roundtrip` | `inflate_deflateRaw` | 1951 |
| `gzip_roundtrip` | `gzip_decompressSingle_compress` | 1952 |

```
forge: zlib — 3/3 verified, 0 failed
```

The full 226-package pipeline evaluates and produces attestation output
with verification status per property. Packages without proofs are
reported as `unchecked` rather than failed.

## How it fits in the SBOM

Verification results flow into the attestation layer as `VerifiedProperty`
structs (proof system, kernel version, spec/proof hashes, forge verification
status). The `VerificationSummary` reports aggregate counts. This is designed
to map cleanly to CycloneDX 1.6's `evidence` and `formulation` fields,
connecting package identity to machine-checkable proof artifacts.

## Dual-kernel verification (nanoda)

When both `lean4export` and `nanoda_bin` are available, the forge runs
**independent dual-kernel verification**:

1. `lake build` — reference C++ kernel checks the proofs
2. `lean4export <module>` — exports declarations as NDJSON
3. `nanoda_bin <config>` — independent Rust type checker re-verifies

Agreement between two independent kernel implementations (C++ and Rust)
is a much stronger signal than a single-kernel check. Properties verified
by both are reported as `DualVerified` in the attestation.

```
gleisner forge --pkgs-dir packages/ --stdlib-dir stdlib/ --verify \
  --lean4export-bin ~/.elan/bin/lean4export \
  --nanoda-bin ~/.cargo/bin/nanoda_bin
```

```
forge: dual-kernel verification enabled (Lean C++ + nanoda Rust)
forge: zlib — 3/3 verified (3 dual-kernel), 0 failed
```

## Next steps

- **Verification caching**: Cache results keyed on `sha256(proof_repo_commit)`
  to avoid re-running `lake build` on unchanged proofs.
- **More packages**: Any minimal.dev package can declare verified properties.
  The schema supports arbitrary proof systems — Lean 4 is just the first.

## Links

- [gleisner-forge source](crates/gleisner-forge/)
- [zlib build.ncl with verified_properties](https://github.com/user/minimal-pkgs/blob/feat/verified-properties-example/packages/zlib/build.ncl)
- [Nickel attr class definition](https://github.com/user/minimal-std/blob/feat/verified-properties-attr/attr_classes.ncl)
- [lean-zip](https://github.com/kim-em/lean-zip) — the proofs we verify
