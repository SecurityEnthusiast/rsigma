# rsigma-ir

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-ir` is the intermediate representation for [Sigma](https://github.com/SigmaHQ/sigma) rules shared by evaluation and conversion.

This library is part of [rsigma].

## Role

```text
YAML → parser(AST) → static pipelines → lower(HIR) → compile(CompiledRule)
                                           │
                                       convert(backends)
```

The HIR is modifier-resolved and selector-free. Compiled artifacts (`Regex`, `IpNet`, Aho-Corasick automata) are materialised later in `rsigma-eval`.

## Public API

| Item | Description |
|------|-------------|
| [`IrRule`] / [`IrDetection`] / [`IrMatcher`] / [`IrCondition`] | Detection-rule HIR |
| [`IrCorrelation`] / [`IrFilter`] | Correlation and filter HIR shapes |
| [`lower_rule`] / [`lower_detection`] / [`lower_condition`] | AST → HIR |
| [`lower_correlation`] / [`lower_filter`] | Parallel walkers for those shapes |
| [`LowerOptions`] | Strict vs placeholder-preserving lowering |

## Constraints

- Sync-only: no tokio, reqwest, or other async runtime dependencies.
- Default lowering rejects unresolved `${source.*}` placeholders.

## License

MIT. See the repository root.

[rsigma]: https://github.com/timescale/rsigma
[`IrRule`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.IrRule.html
[`IrDetection`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/enum.IrDetection.html
[`IrMatcher`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/enum.IrMatcher.html
[`IrCondition`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/enum.IrCondition.html
[`IrCorrelation`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.IrCorrelation.html
[`IrFilter`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.IrFilter.html
[`lower_rule`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/fn.lower_rule.html
[`lower_detection`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/lower/fn.lower_detection.html
[`lower_condition`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/lower/fn.lower_condition.html
[`lower_correlation`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/lower/fn.lower_correlation.html
[`lower_filter`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/lower/fn.lower_filter.html
[`LowerOptions`]: https://docs.rs/rsigma-ir/latest/rsigma_ir/struct.LowerOptions.html
