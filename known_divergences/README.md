# Known divergences

Allowlist of benign, documented differences between implementations, one TOML file per entry.
A divergence that matches an entry is reported as `KNOWN` instead of `HARD_DIVERGE`.

**Currently empty**: Core and btcd agree on every runnable corpus vector.

```toml
id = "btcd-example"
description = "What differs, in one or two sentences."
impls_affected = ["btcd"]
flags_condition = ["TAPROOT"]          # flags that must all be set; may be empty
example_case = "known_divergences/examples/btcd-example.json"
reference_url = "https://github.com/btcsuite/btcd/issues/0000"
reason = "Why this is benign."

[match]
accepts = ["core"]                     # implementations that accept
rejects = ["btcd"]                     # implementations that reject
reject_error_classes = ["SCRIPT_NUM"]  # optional: any-of
raw_error_contains = "number too big"  # optional
```

Rules, enforced by the loader (`crates/oracle/src/known.rs`):

- every field above the `[match]` table is required and non-empty; `reference_url` must be a
  real URL. No entry without a citation;
- `[match]` must state the direction (`accepts` and `rejects`). An entry never matches the
  opposite direction;
- implementations outside `impls_affected` must be unanimous, so the entry has to explain the
  whole disagreement;
- `example_case` must exist.

Keep entries narrow. A broad entry hides real bugs.
