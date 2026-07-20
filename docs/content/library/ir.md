# `rsigma-ir`

Shared intermediate representation (HIR) for Sigma rules. Sits between the parser AST and the eval/convert consumers so modifier resolution and selector collapse happen once.

- [docs.rs/rsigma-ir](https://docs.rs/rsigma-ir)
- [README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-ir/README.md)
- [crates.io/crates/rsigma-ir](https://crates.io/crates/rsigma-ir)

## When to use

- Lower a parsed `SigmaRule` into a modifier-resolved, selector-free form before custom analysis.
- Share one canonical rule shape between evaluation and query conversion.
- Inspect detections, conditions, correlation, or filter shapes without compiling regex/`IpNet` matchers.

Most embedders never depend on `rsigma-ir` directly: [`rsigma-eval`](eval.md) routes `compile_rule` through `lower_rule` → `compile_to_compiled` already.

## Install

```toml
[dependencies]
rsigma-parser = "{{ rsigma.version }}"
rsigma-ir = "{{ rsigma.version }}"
```

The crate is sync-only (no tokio/reqwest).

## Public surface

| Type / function | Purpose |
|-----------------|---------|
| `IrRule` / `IrDetection` / `IrMatcher` / `IrCondition` | Detection-rule HIR. `IrCondition` has no `Selector` variant. |
| `IrCorrelation` / `IrFilter` | Correlation and filter HIR. |
| `IrRuleMetadata` | Metadata superset used when projecting eval `RuleHeader`. |
| `SurfaceSpec` | Optional sidecar on detection items for convert fidelity. |
| `lower_rule` / `lower_detection` / `lower_condition` | AST → HIR. |
| `lower_correlation` / `lower_filter` | Parallel walkers for those shapes. |
| `LowerOptions` | Strict (default) vs placeholder-preserving lowering. |

## Lowering notes

- Selectors such as `1 of selection_*` and `all of them` collapse at lower time into `Or` / `And` / `Detection` trees. Vacuous `all of <pattern>` over zero matching names becomes an empty `And` (true).
- `them` skips detection names that begin with `_`; glob/prefix patterns that explicitly match `_`-prefixed names still include them.
- Modifier contradictions (`|cidr|contains`, `|base64|base64offset`, …) fail at lower time with the same error kinds eval previously surfaced from `compile_rule`.

## Related

- [`rsigma-eval`](eval.md) — `compile_rule` (IR path) and `compile_rule_legacy` (dual-path differential).
- [`rsigma-parser`](parser.md) — source AST.
