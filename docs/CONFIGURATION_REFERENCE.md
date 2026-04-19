# Configuration Reference

**Updated**: April 20, 2026  
**Audience**: Operators and Platform Engineers

## Resolution Order

Configuration precedence:
1. `PWNPILOT_CONFIG`
2. `./config.yaml`
3. `~/.pwnpilot/config.yaml`
4. `/etc/pwnpilot/config.yaml`

## Important Options

### Policy

- `policy.active_scan_rate_limit` (default: 10)

### Tool overrides

- `tools.gobuster.wordlist`

### LLM

- `llm.model_name`
- `llm.cloud_allowed`
- `llm.api_key`
- fallback fields

### Enrichment

- `NVD_API_KEY` (environment variable) for improved CVE API throughput

## Recommended Production Pattern

Pin config path in service env:

```bash
PWNPILOT_CONFIG=/etc/pwnpilot/config.yaml
```

## Related Documents

- [DEPLOYMENT.md](DEPLOYMENT.md)
- [README.md](README.md)
