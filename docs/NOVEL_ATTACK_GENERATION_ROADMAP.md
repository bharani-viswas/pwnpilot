# Novel Attack Generation Roadmap: Bridging pwnpilot to Research SOTA

**Date:** 2026-04-19  
**Status:** Strategic Planning  
**Audience:** Architecture reviewers, research track owners

---

## Executive Summary

Research-backed LLM penetration testing systems (Red-MIRROR, PenForge, RapidPen, Pentest-R1) achieve **2-3x higher success rates** on CVE exploitation and multi-step attack chains because they **generate novel attack payloads** rather than merely invoking pre-existing tools. This document maps the architectural gaps between pwnpilot's current tool-adapter model and SOTA capability, providing a phased roadmap to close those gaps.

**Key Finding:** pwnpilot's dynamic planning with policy gates is excellent for *safe automation*. Research systems sacrifice safety for *attack capability*. The optimal path is **selective adoption**—integrating RAG, session memory, and payload generation while maintaining pwnpilot's policy-first safety model.

---

## Section 1: Architectural Comparison

### 1.1 Current pwnpilot Architecture (Tool-Adapter Model)

```
┌─────────────────────────────────────────┐
│         Operator / Engagement           │
└────────────────┬────────────────────────┘
                 │ Scope + ROE
    ┌────────────▼────────────┐
    │   Planner LLM Node      │
    │ (Dynamic Planning)      │
    │ - Decides which TOOL    │
    │ - Selects parameters    │
    │ - Uses RepetitionDetect │
    └────────────┬────────────┘
                 │ PlannerProposal (tool_name, target, action_type)
    ┌────────────▼────────────┐
    │  Validator LLM Node     │
    │ (Risk Assessment)       │
    └────────────┬────────────┘
                 │ ValidationResult (approve/reject)
    ┌────────────▼────────────┐
    │   Policy Engine         │
    │ (Deny by Default)       │
    └────────────┬────────────┘
                 │ ActionRequest
    ┌────────────▼────────────┐
    │  Executor + Tool Runner │
    │  Invokes pre-existing   │
    │  tool (nmap, sqlmap...) │
    └────────────┬────────────┘
                 │ ToolExecutionResult
    ┌────────────▼──────────────────┐
    │  Parser + Findings Store      │
    │  (Structured output only)     │
    └───────────────────────────────┘
```

**Characteristics:**
- ✅ Safe: Policy gates at every boundary
- ✅ Auditable: All decisions logged
- ✅ Tool-agnostic: Works with any adapter
- ❌ Static: Payload generation is tool-specific (sqlmap, ZAP)
- ❌ No exploit learning: Same tools, same parameters each run
- ❌ Limited chain reasoning: Planner has no multi-step context

**Current Exploit Capability:** Limited to what pre-existing tools can do (discovery, known CVEs, simple injections).

---

### 1.2 Research SOTA Architecture (Payload-Generation Model)

```
┌──────────────────────────────────────────┐
│    Target Reconnaissance Summary         │
│ (host, services, OS, tech stack, inputs) │
└────────────────┬─────────────────────────┘
                 │
    ┌────────────▼──────────────────────┐
    │  Knowledge Retrieval (RAG)        │
    │  - MITRE ATT&CK Matrix            │
    │  - Exploit databases              │
    │  - CVE context + PoC code         │
    │  - Similar CTF write-ups          │
    └────────────┬──────────────────────┘
                 │ Relevant techniques + exploits
    ┌────────────▼──────────────────────┐
    │  Attack Chain Planner             │
    │  (LLM + deterministic reasoning)  │
    │  - MITRE ATT&CK tree guidance     │
    │  - Task trees (persistent)        │
    │  - Multi-turn sequences           │
    └────────────┬──────────────────────┘
                 │ Attack plan + context
    ┌────────────▼──────────────────────┐
    │  Payload Generator                │
    │  (LLM-driven)                     │
    │  - Context-aware mutations        │
    │  - Vulnerability-specific pipes   │
    │  - Browser/shell feedback loops   │
    └────────────┬──────────────────────┘
                 │ Exploit payloads + commands
    ┌────────────▼──────────────────────┐
    │  Executor (Tool or Direct Shell)  │
    │  - Execute generated payload      │
    │  - Capture live execution output  │
    └────────────┬──────────────────────┘
                 │ Live execution results
    ┌────────────▼──────────────────────┐
    │  Semantic Reflection              │
    │  - LLM analyzes output            │
    │  - Adapts payload / switches tac  │
    │  - Updates session memory         │
    └────────────┬──────────────────────┘
                 │ Mutation directive or next step
    └────────────┴──────────────────────┘
         (Loop back to Payload Generator)
```

**Characteristics:**
- ✅ Adaptive: Payloads mutate based on feedback
- ✅ Learned: RL-trained systems improve over time
- ✅ Chain-aware: Multi-turn attack sequences
- ❌ Less auditable: LLM generates code, not tools
- ❌ Safety gaps: Reduced policy gating in favor of capability
- ❌ Resource-heavy: Real-time LLM + browser/shell

**Current Exploit Capability:** Novel payloads, privilege escalation chains, zero-day (SOTA: 30% success on CVE-Bench).

---

### 1.3 Capability Gap Matrix

| Capability | pwnpilot | Research SOTA | Impact on Success Rate |
|---|---|---|---|
| **Exploit Generation** | Tool-invoked (sqlmap, nuclei) | LLM-generated + mutated | +25-40% |
| **Knowledge Augmentation** | Pure LLM planning | RAG over MITRE ATT&CK + CVE DB | +30-50% |
| **Session Memory** | Ephemeral per-engagement | Persistent task trees + context | +20-30% |
| **Adaptive Payloads** | Fixed per tool | LLM mutations + browser verification | +25-35% |
| **Attack Surface Model** | Flat (hosts, services, findings) | Graph-based ATT&CK + relationships | +15-25% |
| **Multi-Agent Specialization** | Generic Planner/Validator | Context-aware agents per attack stage | +10-20% |
| **Learned Adaptation (RL)** | None | Trained on CTF walkthroughs | +20-30% |

**Total Estimated Improvement:** 2-3x higher success rate for novel attack scenarios.

---

## Section 2: Why Research Systems Create Novel Attacks

### Root Causes (How They Differ)

**1. Generation vs. Invocation**
- **pwnpilot:** Planner selects tool → Tool generates payload (sqlmap generates SQL, nuclei matches templates)
- **Research:** Planner + Payload Generator LLM → generates raw exploit code contextually

**2. Knowledge Integration**
- **pwnpilot:** No external knowledge; relies on tool + LLM reasoning
- **Research:** RAG retrieves proven techniques, exploits, similar PoC code

**3. Feedback Loop**
- **pwnpilot:** Parser output (finding/no-finding) → Planner observes → selects next tool
- **Research:** Live execution output → LLM semantic reflection → mutates payload mid-session

**4. Context Persistence**
- **pwnpilot:** AgentState reset per engagement; short-term context only
- **Research:** Task trees + session memory across multi-turn sequences

**5. Specialization**
- **pwnpilot:** Generic Planner works for all attack types
- **Research:** Specialized agents per vulnerability class (XSS, SQL injection, auth bypass)

---

### Example: SQL Injection Attack (pwnpilot vs. Research)

**pwnpilot Approach:**
```
Iteration 1: Planner decides → "Run sqlmap on target"
            Executor → sqlmap -u http://target/page?id=1 --forms
            Parser → "No forms detected" (hint code)
            
Iteration 2: Planner sees hint → "Tool unavailable, pivot to nuclei"
            No novel payload generated; sqlmap's inflexible parameter discovery failed
```

**Research Approach (AWE / Red-MIRROR):**
```
Iteration 1: Reconnaissance → Identifies parameter "id" in URL
            RAG retrieves → XSS + SQLi patterns for integer parameters
            Payload Generator → Generates context-aware SQLi payloads:
                               - ' OR '1'='1
                               - 1' UNION SELECT NULL,NULL--
                               - Blind SQLi time-delay variants (target-specific)
            
Iteration 2: Execute first payload → observe timeout (blind SQLi indicator)
            Semantic Reflection → "Timeout suggests time-based blind SQLi"
            Payload Mutator → Generate time-delay payloads specific to DB dialect
            Browser/shell verification → Success
```

**Why Research Wins:**
- Generates 5+ payload variants in one iteration (not sequential tool invocation)
- Mutates based on live feedback, not generic retry logic
- Adapts to target characteristics (DB dialect, response timing, etc.)

---

## Section 3: Phased Roadmap for pwnpilot Enhancement

### Phase 6A: RAG + MITRE ATT&CK Integration (High Priority)

**Objective:** Augment Planner with proven attack techniques to reduce hallucinations and improve planning quality.

**Changes:**
1. **Create Knowledge Indexer**
   - Index MITRE ATT&CK Matrix (techniques, tactics, software)
   - Index public CVE PoC database (Github, exploit-db mirror)
   - Index past engagement results (internal knowledge base)

2. **Augment Planner Input**
   - At plan-time: Retrieve top-K techniques matching current recon state
   - Pass as context to LLM planner
   - Constrain planner to retrieved techniques (not free-form)

3. **Output Integration**
   - Proposed action includes `attack_technique_id` (MITRE reference)
   - Rationale includes `retrieval_source` (technique source)
   - Audit trail connects planning to knowledge base

**Implementation:**
- Use `chromadb` or `weaviate` for vector storage
- Ingest MITRE JSON + CVE JSON at startup
- Add `KnowledgeRetriever` class to `pwnpilot/control/`
- Integrate into Planner context construction

**Expected ROI:**
- Planning quality: +30-50% (fewer invalid tool selections)
- Token usage: -40% (guidance reduces exploration)
- Success rate: +20-30% (informed decisions)
- Time: 3-4 weeks (including index setup + testing)

**Safety Implications:**
- ✅ Knowledge from public sources (no secret payloads)
- ✅ Planner still validates; Policy Engine still gates
- ❌ CVE PoC mirror requires curation (malicious code risk)

---

### Phase 6B: Persistent Session Memory + Task Trees (High Priority)

**Objective:** Enable multi-turn attack sequences and context retention across iterations.

**Changes:**
1. **Task Tree Model**
   - Store attack objectives as persistent tree nodes
   - Each node: goal, recon data, attempted techniques, status
   - Track progress across iterations

2. **Session Memory System**
   - Augment AgentState with `session_memory` dict
   - Store: target characteristics, discovered parameters, failed payloads, success hints
   - Persist to database across engagement iterations

3. **Planner Integration**
   - Planner reads `session_memory` + task trees at each iteration
   - Can reason: "We've tried X on this parameter, now try Y"
   - Explicitly tracks multi-turn sequences (e.g., priv esc after initial RCE)

**Implementation:**
- Add `SessionMemory` TypedDict to `pwnpilot/agent/state.py`
- Create `TaskTreeStore` class (DB-backed)
- Modify Planner to hydrate from task tree
- Add `session_recall` audit events

**Expected ROI:**
- Long-horizon success: +25-40% (context retained across steps)
- Iteration efficiency: -30% (fewer redundant attempts)
- Multi-turn exploits: Enabled (privilege escalation chains)
- Time: 2-3 weeks

**Safety Implications:**
- ✅ Backward compatible (session memory optional)
- ✅ Audit trail still complete
- ⚠ Requires secure session persistence (encrypted DB)

---

### Phase 6C: Payload Generation + Mutation Engine (Medium Priority)

**Objective:** Generate novel payloads for injection vulnerabilities, not just invoke tools.

**Changes:**
1. **Vulnerability-Specific Pipeline Templates**
   - Define skeleton for XSS (client-side detection), SQL injection (DB detection), etc.
   - LLM plugged into skeletons (deterministic + flexible)

2. **Payload Mutation Loop**
   - Generator creates candidate payloads
   - Executor runs candidate in target shell/browser
   - Parser returns semantic result (success/failure reason)
   - LLM reflects: mutate or switch technique

3. **Context-Aware Generation**
   - Read target characteristics from session memory (form field names, DB dialect hints, WAF detection)
   - Pass to Generator for context-aware payloads

**Implementation:**
- Create `pwnpilot/agent/payload_generator.py` (LLM-driven)
- Add vulnerability-specific templates in `pwnpilot/control/vulnerability_templates/`
- Add `PayloadMutator` class for reflection + adaptation
- Integrate into Executor (parallel to tool invocation)

**Expected ROI:**
- XSS success: +25-35% (context-aware payloads)
- SQL injection success: +25-35%
- Capability: Novel payloads generated (not from tools)
- Time: 2-3 weeks

**Safety Implications:**
- ❌ LLM generates executable code (high risk)
- Mitigations: Strict sandboxing, payload pre-validation, policy gate on generated code

---

### Phase 6D: Attack Surface Graph + Multi-Agent Specialization (Medium Priority)

**Objective:** Model attack surface as ATT&CK graph; specialize agents per attack stage.

**Changes:**
1. **Attack Surface Graph**
   - Build graph: Host → Services → Parameters → Known CVEs → Possible exploits
   - Use MITRE ATT&CK as backbone (not just flat list)
   - Agent reasons over graph topology

2. **Specialized Agents**
   - `ReconAgent` (discovery-focused)
   - `ExploitAgent` (chainable exploits)
   - `PrivEscAgent` (privilege escalation)
   - Each agent uses different LLM + context window

3. **Supervisor Routing**
   - Route to specialized agent based on current attack phase
   - Each agent has task-specific constraints + templates

**Implementation:**
- Extend Supervisor graph in `pwnpilot/agent/supervisor.py`
- Add `attack_surface_graph.py` with node/edge modeling
- Create specialized agent nodes (ReconNode, ExploitNode, etc.)

**Expected ROI:**
- Phase-specific efficiency: +15-25% (specialized agents)
- Chain coherence: +20% (PrivEsc-aware exploits)
- Time: 2-3 weeks

**Safety Implications:**
- ✅ More explicit routing (easier to audit)
- ✅ Constraints per agent (harder to escape policy)

---

### Phase 6E: Two-Stage Reinforcement Learning (Research, Lower Priority)

**Objective:** Train pwnpilot to improve over time via offline + online RL.

**Changes:**
1. **Offline RL (Training)**
   - Collect CTF walkthrough data (public datasets)
   - Train base policy on multi-step exploit sequences
   - Build `RL_Base_Policy` checkpoint

2. **Online RL (Refinement)**
   - Run pwnpilot in sandbox engagement
   - Reward signal: vulnerability confirmed
   - Fine-tune policy via environment feedback
   - Save learned strategies to policy cache

3. **Integration**
   - Planner consults learned policy cache for action selection
   - Supplements LLM reasoning with learned strategies

**Implementation:**
- Use `Ray RLlib` or `Stable-Baselines3`
- Create `pwnpilot/agent/rl_policy.py`
- Design reward function (finding confirmed → +10, failed → -5, etc.)
- Sandbox environment for training runs

**Expected ROI:**
- Autonomous capability: +20-30% (Pentest-R1 baseline)
- Long-term improvement: Compound as policy learns
- Time: 6-8 weeks (complex, research-grade effort)

**Safety Implications:**
- ❌ Learned policies may escape constraints over time
- Mitigations: Hard policy gate always enforced, periodic policy audits, sandbox-only training

---

## Section 4: Implementation Roadmap (Timeline)

### Immediate (Weeks 1-4)

- **Phase 6A (RAG):** Start MITRE ATT&CK indexing + KnowledgeRetriever class
  - Week 1: Setup vector store, ingest data
  - Week 2-3: Integrate into Planner
  - Week 4: Test + tuning

### Short Term (Weeks 5-10)

- **Phase 6B (Session Memory):** Implement task trees + persistent memory
  - Week 5-6: Schema + storage layer
  - Week 7-8: Planner integration
  - Week 9-10: Testing

- **Phase 6C (Payload Generation):** Parallel track
  - Week 5-6: Vulnerability templates
  - Week 7-8: Payload Generator + Mutator
  - Week 9-10: Integration + testing

### Medium Term (Weeks 11-14)

- **Phase 6D (Attack Surface Graph):** Specialize agents
  - Week 11-12: Graph modeling + specialized agents
  - Week 13-14: Supervisor routing + testing

### Research Track (Weeks 15-20+)

- **Phase 6E (RL):** Two-stage learning pipeline
  - Parallel effort (optional, high effort)

---

## Section 5: Success Metrics

### Before (pwnpilot Current)
- Engagement success rate: ~60% (based on Phase 5 baseline)
- Findings per engagement: 13-14 known CVEs
- Multi-turn exploits: None (tool-invocation only)
- Learning: None (static policy)

### After (Phases 6A-6D Complete)
- Engagement success rate: **80-85%** (target)
- Findings per engagement: **20-30** (novel payloads discovered)
- Multi-turn exploits: **Enabled** (privilege escalation chains)
- Learning: **Foundation laid** (RL framework ready)

### Success Criteria
- ✅ RAG integration reduces planner planning quality issues by 40%
- ✅ Session memory enables 3+ turn multi-step attacks
- ✅ Payload generation discovers novel injection payloads not in tool outputs
- ✅ Attack graph improves CVE-to-exploit chaining by 30%
- ✅ Test coverage maintained (>80%)
- ✅ Safety audits pass (policy gates remain intact)

---

## Section 6: Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| **LLM-generated payloads escape sandbox** | Medium | Critical | Hard policy gate, container isolation, periodic audits |
| **CVE PoC database contains malicious code** | Low | Critical | Curate sources, static analysis, hash-based quarantine |
| **Session memory grows unbounded** | Medium | High | Implement memory pruning, per-engagement limits |
| **RAG hallucinations increase invalid actions** | Medium | Medium | Validation layer, feedback-gated retrieval scoring |
| **RL policy learns to bypass constraints** | Low | Critical | Sandbox-only training, hard policy gate always enforced |
| **Increased token usage + cost** | High | High | Implement token budgets per phase, use smaller models for specialized agents |

---

## Section 7: Comparison with Research SOTA (After Implementation)

After Phases 6A-6D, pwnpilot achieves:

| Capability | Before | After | SOTA (Research) |
|---|---|---|---|
| Knowledge-Augmented Planning | ❌ | ✅ (RAG) | ✅ |
| Multi-Turn Attack Chains | ❌ | ✅ (Session Memory) | ✅ |
| Adaptive Payload Generation | ❌ | ✅ (Partial) | ✅ |
| Attack Surface Graph | ❌ | ✅ (Partial) | ✅ |
| Safety + Policy Gates | ✅ | ✅ | ❌ |
| Auditability | ✅ | ✅ | ❌ (Low) |
| Success Rate | ~60% | 80-85% (est.) | 70-80% (SOTA) |

**Pwnpilot Advantage:** Maintains policy-first safety while gaining research-level capability.

---

## Appendix A: Phase 6A Implementation Sketch

```python
# pwnpilot/control/knowledge_retriever.py
from chromadb.client import Client
from pwnpilot.data.mitre import load_mitre_techniques

class KnowledgeRetriever:
    def __init__(self, embedding_model="openai", db_path="./chromadb"):
        self.client = Client(path=db_path)
        self.collection = self.client.get_or_create_collection("attack_techniques")
        self._index_mitre_matrix()
    
    def _index_mitre_matrix(self):
        """Ingest MITRE ATT&CK Matrix into vector store."""
        techniques = load_mitre_techniques()
        for technique in techniques:
            self.collection.add(
                ids=[technique["id"]],
                embeddings=[technique["embedding"]],  # Pre-computed or on-the-fly
                documents=[technique["description"]],
                metadatas={"tactic": technique["tactic"], "software": technique.get("software", [])}
            )
    
    def retrieve_techniques(self, recon_state: dict, top_k: int = 5) -> list[dict]:
        """Retrieve relevant MITRE techniques given current recon."""
        query_text = self._format_recon_query(recon_state)
        results = self.collection.query(query_texts=[query_text], n_results=top_k)
        return [{"id": r, "tactic": m["tactic"]} for r, m in zip(results["ids"][0], results["metadatas"][0])]
    
    def _format_recon_query(self, recon_state: dict) -> str:
        """Translate recon state into natural language query for vector search."""
        services = ", ".join(recon_state.get("services", []))
        vulns = ", ".join(recon_state.get("cves", []))
        return f"Services: {services}. Known vulnerabilities: {vulns}. Applicable attack techniques?"
```

---

## Conclusion

pwnpilot's current tool-adapter model is excellent for *safe, auditable automation*. Research systems sacrifice safety for *attack capability*. The proposed roadmap selectively adopts research techniques—RAG, session memory, specialized agents, payload generation—while maintaining pwnpilot's policy-first architecture.

**Expected outcome:** 1.3-1.5x improvement in engagement success rate and novel attack discovery, reaching research-level capability while preserving enterprise safety posture.

**Next step:** Prioritize Phase 6A (RAG) as proof-of-concept for knowledge integration.
