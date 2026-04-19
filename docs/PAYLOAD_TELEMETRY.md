# Payload Telemetry Guide

**Updated**: April 20, 2026  
**Audience**: Operators, Analysts, Engineering

## Purpose

Payload telemetry summarizes payload generation effectiveness in postmortem artifacts.

## Telemetry Fields

- `total_generations`
- `preflight_rejected`
- `tools_used`
- `techniques_attempted`
- `mutation_rounds`
- `semantic_outcomes`

## Quick Extraction

```bash
jq '.payload_telemetry' reports/postmortem_<engagement-id>.json
```

## Interpretation

- High `preflight_rejected`: ROE/policy patterns may be too strict.
- High `mutation_rounds`: payload adaptation loop is expensive; inspect defenses and tool strategy.
- Narrow `tools_used`: planner capability routing may be constrained.
- `semantic_outcomes` skewed to failure/timeout: validate target responsiveness and timeout settings.

## Minimal KPI Query Pattern

Track across engagements:
- rejection rate = `preflight_rejected / total_generations`
- average mutation rounds
- tool diversity count

## Related Documents

- [DEPLOYMENT.md](DEPLOYMENT.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
