# Incident f8bcd62a829b1126

- Generated: 2026-07-26T12:00:00Z
- State: open
- Highest severity: high
- Window: 1767225000 to 1767225600
- Contributing results: 3
- Retained samples: results

## Grouping

- `match.User`: alice

## Contributing rules

### `rule-retired` (1 result)

No loaded rule carries this key. The rule set most likely changed while the incident was open.

### `rule-whoami` (2 results)

**Whoami execution**

- Level: high
- Tags: attack.discovery, attack.t1033

*Goal*

Detects whoami execution, a common discovery step.

*Categorization*

- attack.discovery
- attack.t1033

*Strategy*

Watch process creation for the whoami binary.

*Technical context*

Requires process_creation telemetry with CommandLine.

*Blind spots*

- A renamed binary evades the command-line match.

*False positives*

- Administrators enumerating their own privileges

*Validation*

Run whoami in a lab and confirm the rule fires.

*Priority*

High because discovery precedes lateral movement.

*Response*

- Confirm the user and host.
- Correlate with other discovery.

## Risk

### user: alice

- Score: 120
- Distinct tactics: 2
- Contributing sources: 2
- Window: 1767225000 to 1767225600
- Matched on: a contributing result's risk objects

