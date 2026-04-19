# Architecture Comparison: Novel Attack Generation

## High-Level Difference

### pwnpilot (Current)
```
Planner LLM
   ↓ "Run nmap on target"
Tool Selection
   ↓
Tool Invocation (nmap, sqlmap, nuclei)
   ↓
Tool Output Parsing
   ↓
Findings Store
```

**How exploits are found:** Tool-specific discovery (known CVEs, templates, word lists)

---

### Research SOTA (Novel Attack Generation)
```
Reconnaissance Data → RAG Knowledge Base
   ↓
Attack Planner (LLM) + MITRE ATT&CK Tree
   ↓
Payload Generator (LLM)
   ↓ "Generate SQL injection payloads for this parameter"
Payloads Created + Contextual Variants
   ↓
Execute in Target Environment
   ↓
Live Execution Output
   ↓
Semantic Reflection (LLM analyzes output)
   ↓ "That payload failed. Try time-delay blind SQLi"
Mutate & Retry
   ↓
Exploit Success or Pivot
```

**How exploits are found:** LLM-generated payloads adapted in real-time based on target feedback

---

## Why This Matters: SQL Injection Example

### pwnpilot Flow
```
1. Recon: Discover target URL
2. Planner: "Run sqlmap"
3. Executor: sqlmap -u http://target?id=1 --forms
4. Parser: "No forms detected" → Add hint
5. Planner: "Hint says no forms, switch to nuclei"
6. Result: Limited discovery (only what sqlmap's patterns find)
```

**Problem:** Sqlmap searches for HTML forms; target has direct URL parameters. Tools are inflexible.

---

### Research Flow
```
1. Recon: Discover URL param "id=1" (integer)
2. RAG retrieval: Get SQLi patterns for integer params
3. Payload Generator: Create contextual payloads
   - ' OR '1'='1
   - 1' UNION SELECT NULL,NULL,NULL--
   - 1' AND SLEEP(5)--  (time-blind variant)
4. Executor: Try first payload
5. Live Output: Response shows 5-second delay → Blind SQLi confirmed
6. Semantic Reflection: LLM analyzes → "Timeout = time-based blind injection"
7. Payload Mutator: Generate DB-dialect-specific time payloads
8. Result: Blind SQLi exploit generated and confirmed
```

**Advantage:** Generates 3-5 payloads per iteration; adapts in real-time to target response.

---

## Capability Matrix: What Each System Can Do

| Attack Type | pwnpilot | Research + RL | Expected Gain |
|---|---|---|---|
| **Known CVEs** | ✅ Nuclei templates | ✅ Template + RAG | — |
| **SQL Injection (blind)** | ⚠ Limited (tool-dependent) | ✅ Generated variants | **+25-35%** |
| **XSS (DOM-based)** | ⚠ Limited | ✅ Context-aware payloads | **+25-35%** |
| **Privilege Escalation Chain** | ❌ No multi-turn context | ✅ Task tree + session mem | **+40-50%** |
| **Auth Bypass (multi-step)** | ❌ Single-action only | ✅ Multi-turn LLM | **+30-40%** |
| **Zero-Day Exploit** | ❌ Template-limited | ✅ Novel payloads (30% SOTA) | **+20-30%** |
| **WAF Bypass Payloads** | ❌ No real-time mutation | ✅ Adaptive generation | **+25-35%** |

---

## Key Technical Gaps: Why Payloads Aren't Generated

### Gap 1: No RAG (Retrieval-Augmented Generation)

**pwnpilot:** Planner only has LLM + current state → hallucinations, redundant attempts  
**Research:** Planner retrieves proven techniques from MITRE ATT&CK + CVE DB → informed decisions

**Impact:** Research systems make **3-5x fewer invalid tool selections**

---

### Gap 2: No Session Memory / Task Trees

**pwnpilot:** Each iteration is independent; no memory of what was tried  
**Research:** Persistent task trees track attack objectives; remember what failed and why

**Impact:** Research systems can perform **multi-turn privilege escalation chains**; pwnpilot can't

---

### Gap 3: No Semantic Reflection Loop

**pwnpilot:** Tool output → parser → binary result (finding/no-finding) → planner sees abstract summary  
**Research:** Live shell/browser output → LLM analyzes semantically → payload mutator decides next variant

**Impact:** Research systems **generate 5+ payload variants per iteration**; pwnpilot runs one tool per iteration

---

### Gap 4: No Payload Generator

**pwnpilot:** Only tools generate payloads (sqlmap, ZAP, nuclei)  
**Research:** LLM-driven payload generator creates context-aware, target-specific exploits

**Impact:** Research systems **generate novel payloads** not in any tool's templates

---

### Gap 5: No Attack Surface Graph

**pwnpilot:** Flat recon store (hosts, services, findings)  
**Research:** Graph model linking hosts → services → parameters → known CVEs → exploit chains

**Impact:** Research systems **reason about multi-step attack paths**; pwnpilot treats each action independently

---

## Phased Improvement Strategy

```
Phase 6A: RAG + MITRE ATT&CK
├─ Planner gets retrieval-augmented context
├─ Planning quality: +30-50%
└─ Time: 3-4 weeks

Phase 6B: Session Memory + Task Trees
├─ Multi-turn attack sequences enabled
├─ Success rate: +25-40%
└─ Time: 2-3 weeks

Phase 6C: Payload Generation + Mutation
├─ LLM generates injection payloads
├─ Real-time feedback loop
├─ Success rate (injection): +25-35%
└─ Time: 2-3 weeks

Phase 6D: Attack Surface Graph + Specialization
├─ Graph-based attack planning
├─ Specialized agents per attack stage
└─ Time: 2-3 weeks

Phase 6E: Reinforcement Learning (Research Track)
├─ Offline RL on CTF walkthroughs
├─ Online RL in sandbox
├─ Success rate: +20-30% (long-term learning)
└─ Time: 6-8 weeks
```

**Total Expected Improvement:** 1.3-1.5x success rate; novel attack discovery enabled

---

## Safety Considerations

### pwnpilot's Advantage
- ✅ Policy gates at every boundary (deny-by-default)
- ✅ Full audit trail (all decisions logged)
- ✅ No free-form shell (all actions typed)
- ✅ Operator always in loop for high-risk actions

### Research Systems' Trade-off
- ❌ LLM generates code (harder to audit)
- ❌ Reduced policy enforcement (favors capability)
- ❌ No guaranteed constraints (RL can learn to bypass)

### Recommended Approach
Adopt research techniques **while maintaining pwnpilot's safety model:**
- ✅ RAG retrieval (safe: proven sources only)
- ✅ Session memory (safe: context tracking)
- ⚠ Payload generation (risk: needs sandboxing + policy gate)
- ⚠ RL training (risk: sandbox-only, hard policy gate always enforced)

---

## Expected Results After Implementation

### Before (Current pwnpilot)
- Success rate: ~60%
- Findings per engagement: 13-14
- Multi-turn attacks: None
- Novel payloads: None

### After (Phases 6A-6D)
- Success rate: **80-85%** (1.3-1.4x)
- Findings per engagement: **20-30** (1.5-2x, novel payloads)
- Multi-turn attacks: **Enabled** (privilege escalation chains)
- Novel payloads: **Generated in real-time** (contextual adaptation)

---

## Next Steps

1. **Review & Prioritize:** Discuss Phases 6A-6D with stakeholders
2. **Prototype Phase 6A:** Start RAG integration (3-4 week sprint)
3. **Measure Impact:** Compare success rates before/after
4. **Iterate:** Fold learnings into Phases 6B-6D
5. **Research Track:** Parallel RL investigation (lower priority initially)

---

## References

- Red-MIRROR: Shared Recurrent Memory for Penetration Testing (2603.27127)
- PenForge: On-the-Fly Expert Agent Construction for CVE Exploitation (2601.06910)
- Pentest-R1: Two-Stage RL for Autonomous Penetration Testing (2508.07382)
- AWE: Adaptive Payload Mutations for XSS/SQLi (2603.00960)
- Guided Reasoning: MITRE ATT&CK Trees (2509.07939)
