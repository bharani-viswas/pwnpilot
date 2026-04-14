# PwnPilot Implementation Plan

## Status

All previously listed open issues in this plan are now fixed.

---

### Fix 1 — sqlmap targets SPA roots instead of API endpoints
- **File:** planner context + pwnpilot/plugins/adapters/sqlmap.py
- **Problem:** sqlmap is frequently pointed at SPA root URLs where static form discovery fails.
- **Fix Applied:** Planner attack-surface targeting now prefers discovered API endpoints, appends parameterized query targets when available, and configures sqlmap for API-aware testing (`forms=false`, `data` fallback).
- **Status:** ✅ Fixed (2026-04-14)

---

### Fix 2 — Gobuster SPA wildcard noise filtering support
- **File:** pwnpilot/plugins/adapters/gobuster.py
- **Problem:** Without exclude-length support, SPA wildcard responses create noisy false positives.
- **Fix Applied:** Added `exclude_length` adapter parameter with validation and command passthrough to gobuster `-bl` in dir mode.
- **Status:** ✅ Fixed (2026-04-14)

---

### Fix 3 — Finding evidence backlinks attached per finding
- **File:** pwnpilot/agent/executor.py
- **Problem:** Findings are persisted with empty evidence backlink arrays.
- **Fix Applied:** Executor now passes run evidence IDs (stdout/stderr evidence artifacts) when persisting finding records.
- **Status:** ✅ Fixed (2026-04-14)

---

### Fix 4 — Gobuster confidence inflation under wildcard noise
- **File:** pwnpilot/plugins/adapters/gobuster.py
- **Problem:** Confidence remains high when output is dominated by wildcard-derived paths.
- **Fix Applied:** Gobuster parser now lowers confidence (0.45) when wildcard hints are detected alongside findings.
- **Status:** ✅ Fixed (2026-04-14)

---

### Fix 5 — Execution recovery gap hardening
- **Files:** pwnpilot/agent/executor.py, pwnpilot/agent/planner.py, pwnpilot/plugins/runner.py
- **Problem:** After execution errors or low-value outcomes, the loop can progress without corrective retry logic, leading to repeated no-findings cycles.
- **Fix Applied:**
  1. Executor now keeps/increments nonproductive streak for failed/low-value outcomes and only resets on productive success.
  2. Planner suppression/cooldown now considers execution failure reasons.
  3. `execution_error` is part of low-value hint classification.
  4. Repeated-state churn deterministically routes to report (`force_report`) with terminal reason.
- **Status:** ✅ Fixed (2026-04-14)

---

## Validation

- Unit test suite: `629 passed`, coverage `80.53%` (threshold met).
- Adapter contract tests: `93 passed`.
