# Implementation Plan: Research-Grounded Upgrade for Novel Attack Generation

Updated: 2026-04-19
Scope: Deep implementation blueprint for Phase 6A to Phase 6E

## 1. Goal

Enable pwnpilot to move from tool-invocation-led pentesting to research-grade adaptive attack generation while preserving policy-first safety, auditability, and ROE control.

Target outcome:
- Improve guided engagement effectiveness on complex targets.
- Reduce low-value action churn (NoActionableOutput / ParserDegraded cycles).
- Add controlled support for multi-step, context-aware exploit generation.

## 2. Research Baseline Used

Primary external references considered for implementation strategy:
- PentestAgent (arXiv:2411.05185): RAG + multi-agent collaboration for intelligence gathering and exploitation.
- RapidPen (arXiv:2502.16730): ReAct loop + retrieval of prior success-case exploit knowledge, IP-to-shell automation.
- Pentest-R1 (arXiv:2508.07382): two-stage RL (offline walkthrough data + online CTF feedback), improved autonomous reasoning.
- Guided Reasoning with Structured Attack Trees (arXiv:2509.07939): deterministic attack-tree constraints over LLM planning, major subtask completion and query-efficiency gains.
- PenForge (arXiv:2601.06910): on-the-fly expert agent construction from discovered attack surface.
- AWE (arXiv:2603.00960): vulnerability-specific deterministic pipelines + adaptive payload mutation + persistent memory + browser verification.
- Red-MIRROR (arXiv:2603.27127): RAG + shared recurrent memory + dual-phase reflective verification.
- MITRE ATT&CK STIX data (attack-stix-data): machine-readable ATT&CK ingestion model for tactic-technique grounding.

Design implication from literature:
- Architecture, memory model, and feedback loops matter as much as base model quality.
- Best results come from hybrid pipelines: deterministic scaffolding + LLM adaptation.

## 3. Current State and Gap

Current pwnpilot strengths:
- Strong policy and approval gates.
- Typed tool invocation path.
- Good audit/event traceability.
- Invocation compilation boundary already introduced in prior phases.

Current limitations versus SOTA:
- No ATT&CK-grounded retrieval layer at planning time.
- No durable task-tree memory for long-horizon exploit chains.
- No dedicated payload generation/mutation subsystem.
- Limited semantic reflection loop after failed exploit attempts.
- No learned policy layer from historical pentest trajectories.

## 4. Global Implementation Principles for 6A-6E

1. Safety invariants remain mandatory
- Policy engine remains final enforcement point.
- Generated payloads must pass preflight checks before execution.
- High-risk actions remain approval-gated.

2. Deterministic shell around stochastic reasoning
- Use deterministic schemas for plan, retrieval, memory updates, and execution outcomes.
- Keep LLM flexible only inside bounded interfaces.

3. Add capabilities in layered sequence
- First improve planning quality (6A), then memory (6B), then generation (6C), then orchestration (6D), then learning (6E).

4. Ship with hard evaluation gates
- No phase promoted without objective pass/fail thresholds.

## 5. Phase 6A: ATT&CK-Grounded RAG Planning

Status: Planned
Priority: P0
Estimated duration: 3 to 4 weeks

### 6A.1 Objective
Inject high-quality, machine-readable attack knowledge into planning so tool/action proposals are constrained by proven tactics and techniques.

### 6A.2 Recommended Architecture
- Add Knowledge Retriever in control plane:
	- Inputs: recon summary, discovered stack, known findings, prior failures.
	- Sources:
		- MITRE ATT&CK STIX 2.1 datasets.
		- Curated exploit knowledge index (approved sources only).
		- Internal prior successful action traces.
	- Outputs:
		- top-k techniques with confidence scores.
		- evidence source metadata for audit.
- Planner prompt/context receives structured retrieval pack, not raw long text.
- Planner proposal extended with:
	- attack_technique_ids
	- retrieval_confidence
	- retrieval_sources

### 6A.3 Best-Practice Implementation Choices
- Data format:
	- Ingest ATT&CK via STIX collections and pin version per run.
	- Store normalized technique graph locally for deterministic reproducibility.
- Retrieval stack:
	- Hybrid retrieval (dense + metadata filters) instead of pure vector similarity.
	- Mandatory metadata filters by platform, tactic family, and observed tech stack.
- Grounding policy:
	- If retrieval confidence is low, planner falls back to conservative recon tactics.
	- Prevent speculative exploit steps without supporting technique evidence.

### 6A.4 Work Breakdown
1. Build ingestion pipeline for ATT&CK STIX + local curation manifest.
2. Create normalized tables/index:
	 - techniques, tactics, software, procedure examples, version metadata.
3. Implement retrieval API for planner with strict response schema.
4. Extend planner context contract and proposal schema.
5. Add audit fields linking each proposed action to retrieved evidence.
6. Add fail-safe behavior when retrieval unavailable or stale.

### 6A.5 Validation
- Unit:
	- ATT&CK ingest parser fidelity.
	- Retrieval filtering by platform/tactic.
- Integration:
	- Planner consumes retrieval pack and outputs technique-linked rationale.
- E2E:
	- Compare against baseline on guided engagements.

### 6A.6 Success Criteria
- At least 90 percent of active-scan and exploit proposals include traceable retrieval evidence.
- At least 25 percent reduction in invalid or low-value tool proposals.
- No policy regression and no increase in out-of-scope attempts.

### 6A.7 Risks and Controls
- Risk: noisy or malicious external exploit snippets.
	- Control: allowlist sources + static sanitizer + provenance logging.
- Risk: over-constrained planner misses creative pivots.
	- Control: controlled fallback mode with capped exploration budget.

## 6. Phase 6B: Persistent Session Memory and Task Trees

Status: Planned
Priority: P0
Estimated duration: 2 to 3 weeks

### 6B.1 Objective
Enable long-horizon attack chains by persisting exploitable context, failed attempts, and objective progress as structured memory.

### 6B.2 Recommended Architecture
- Introduce two memory tiers:
	- Tactical session memory: recent execution facts, payload outcomes, environmental hints.
	- Strategic task tree memory: objective decomposition and completion state.
- Task tree node schema:
	- objective_id, parent_id, tactic, target_asset, current_hypothesis, status, confidence, evidence_refs.
- Add memory lifecycle policy:
	- append on each action,
	- summarize at interval,
	- prune low-value noise using deterministic rules.

### 6B.3 Best-Practice Implementation Choices
- Use event-sourced updates to avoid hidden memory mutation.
- Keep memory writes deterministic and schema-validated.
- Separate raw transcript evidence from summarized planner memory.
- Apply bounded context windows and rolling summaries to avoid prompt bloat.

### 6B.4 Work Breakdown
1. Extend agent state contracts for session memory references.
2. Build task-tree store and APIs: create_node, advance_node, invalidate_node.
3. Implement memory summarizer with explicit confidence tags.
4. Integrate memory read/write at planner and executor boundaries.
5. Add stale-memory invalidation when environment shifts.

### 6B.5 Validation
- Unit:
	- task tree transitions and invariants.
	- summarization idempotence.
- Integration:
	- planner behavior continuity across 10+ iterations.
- E2E:
	- reduced duplicate actions and improved objective completion pathing.

### 6B.6 Success Criteria
- At least 30 percent reduction in repeated-state loops.
- At least 20 percent reduction in redundant tool retries.
- Improved subtask progression continuity on long engagements.

### 6B.7 Risks and Controls
- Risk: memory drift or hallucinated memory facts.
	- Control: store confidence + source references; block high-impact decisions on low-confidence memory.
- Risk: uncontrolled storage growth.
	- Control: retention policy and deterministic pruning thresholds.

## 7. Phase 6C: Payload Generation and Adaptive Mutation Engine

Status: Planned
Priority: P0
Estimated duration: 2 to 3 weeks

### 6C.1 Objective
Add bounded, vulnerability-aware payload generation that adapts from live feedback while remaining policy-compliant.

### 6C.2 Recommended Architecture
- New component: Payload Compiler
	- Inputs: vulnerability hypothesis, target context, task-tree node, previous payload outcomes.
	- Outputs: ranked payload candidates with rationale and risk tags.
- New component: Reflection Evaluator
	- Interprets execution responses and classifies outcome classes:
		- likely_success
		- likely_blocked_by_waf
		- syntax_mismatch
		- no_attack_surface
		- uncertain
- Mutation loop:
	- generate -> preflight validate -> execute -> reflect -> mutate/pivot.

### 6C.3 Best-Practice Implementation Choices
- Use vulnerability-specific deterministic templates with LLM slots, not free-form command generation.
- Enforce strict payload safety policy:
	- deny dangerous classes outside ROE.
	- cap mutation rounds and payload entropy.
- Couple with browser-backed or protocol-aware verification where relevant.
- Keep parser + semantic reflection both available; treat disagreement as low confidence.

### 6C.4 Work Breakdown
1. Implement payload DSL/schema per vulnerability class (initially XSS and SQLi).
2. Create payload preflight validator (syntax, scope, policy compatibility).
3. Build reflection evaluator and canonical outcome taxonomy.
4. Integrate mutation policy with attempt budgets and cooldowns.
5. Add deterministic fallback to tool-based scans when confidence remains low.

### 6C.5 Validation
- Unit:
	- payload schema validation and policy preflight.
	- reflection outcome classification.
- Integration:
	- mutation loop convergence behavior.
- E2E:
	- injection-focused benchmarks and internal labs.

### 6C.6 Success Criteria
- At least 25 percent improvement in injection-class exploit confirmation against baseline.
- At least 20 percent reduction in repetitive no-actionable-output cycles for exploit attempts.
- Zero policy bypass incidents in generated payload path.

### 6C.7 Risks and Controls
- Risk: unsafe generated payloads.
	- Control: mandatory policy preflight and sandboxed execution context.
- Risk: high token/runtime cost.
	- Control: early stopping and bounded candidate set.

## 8. Phase 6D: Dynamic Specialist Agents and Attack-Surface Graph

Status: Planned
Priority: P1
Estimated duration: 2 to 3 weeks

### 6D.1 Objective
Improve attack-chain quality by routing tasks to dynamically selected specialist agents over a shared attack-surface graph.

### 6D.2 Recommended Architecture
- Build attack-surface graph entities:
	- assets, interfaces, parameters, identities, trust edges, findings, hypotheses.
- Add specialist agent profiles:
	- Recon Specialist
	- Injection Specialist
	- Auth/Session Specialist
	- Lateral Movement Specialist (future)
- Introduce dynamic router:
	- chooses specialist based on graph state + unresolved objectives + confidence.

### 6D.3 Best-Practice Implementation Choices
- Reuse common shared memory substrate; specialists differ by policy and prompting profile, not by isolated state silos.
- Keep per-specialist action budget and performance telemetry.
- Add deterministic arbitration when specialists disagree.

### 6D.4 Work Breakdown
1. Implement graph storage + typed edge model.
2. Build specialist planner profiles and selection heuristics.
3. Add router node in supervisor/orchestrator.
4. Implement specialist-level cooldowns and confidence tracking.
5. Extend reporting to include specialist contribution traces.

### 6D.5 Validation
- Unit:
	- graph integrity and route-selection logic.
- Integration:
	- specialist switching behavior under changing evidence.
- E2E:
	- compare chain depth and exploit progression quality.

### 6D.6 Success Criteria
- At least 20 percent increase in successful multi-step progression events.
- At least 15 percent reduction in cross-objective context loss.
- Clear auditability of why specialist routing decisions were made.

### 6D.7 Risks and Controls
- Risk: orchestration complexity and instability.
	- Control: phased rollout with feature flags and canary engagements.
- Risk: conflicting specialist recommendations.
	- Control: deterministic tie-break policy and validator escalation.

## 9. Phase 6E: Two-Stage Reinforcement Learning for Policy Improvement

Status: Planned (Research Track)
Priority: P2
Estimated duration: 6 to 8+ weeks

### 6E.1 Objective
Introduce a learning layer that improves planning and recovery behavior over time using offline trajectories plus online sandbox feedback.

### 6E.2 Recommended Architecture
- Stage 1: Offline learning
	- Train from curated historical pentest trajectories and walkthroughs.
	- Focus on action sequencing, recovery decisions, and pivot timing.
- Stage 2: Online sandbox learning
	- Fine-tune policy using controlled vulnerable environments with reward shaping.
- Deployment model:
	- learned policy provides ranking prior, not hard override.
	- policy engine and validator remain mandatory.

### 6E.3 Best-Practice Implementation Choices
- Treat RL policy as advisory score in early rollout.
- Design reward function with strong penalties for policy violations, dead loops, and unsafe actions.
- Use reproducible environment packs (for example, curated Vulhub sets and internal labs).
- Train and evaluate in isolated infra; do not train on production engagements.

### 6E.4 Work Breakdown
1. Build trajectory dataset format and quality filters.
2. Implement offline behavior learning pipeline.
3. Define sandbox environments and reward signals.
4. Train online policy and compare to heuristic baseline.
5. Integrate advisory scoring into planner candidate ranking.
6. Add rollback switch and policy version pinning.

### 6E.5 Validation
- Offline:
	- held-out trajectory quality metrics.
- Online:
	- sandbox success rate and stability.
- Safety:
	- no increase in policy denial rate or unsafe attempt rate.

### 6E.6 Success Criteria
- At least 15 percent improvement in benchmarked autonomous task completion.
- At least 20 percent improvement in recovery from failed exploit attempts.
- No safety-policy regressions.

### 6E.7 Risks and Controls
- Risk: reward hacking or unsafe optimization.
	- Control: constrained action space + hard policy penalties + human-offline review.
- Risk: overfitting to synthetic labs.
	- Control: diverse benchmark suite and periodic domain-shift tests.

## 10. Cross-Phase Data Contracts to Add

Minimum schema extensions required:
- Planner proposal:
	- attack_technique_ids
	- retrieval_sources
	- retrieval_confidence
	- specialist_profile
	- policy_prior_score
- Execution result:
	- semantic_outcome_code
	- reflection_summary
	- payload_generation_mode
	- mutation_round
	- memory_write_refs
- Task tree:
	- node_state, confidence, supporting_evidence_ids, invalidation_reason

## 11. Rollout Strategy

1. Ship 6A and 6B behind feature flags first.
2. Run shadow-mode comparisons against existing planner on same targets.
3. Promote 6C in narrow vulnerability classes (XSS/SQLi) only.
4. Add 6D specialization after memory and payload loop stability.
5. Keep 6E in research branch until stable safety and reproducibility thresholds are met.

## 12. Evaluation Matrix

Primary runtime KPIs:
- degraded_actions per engagement
- no_actionable_output rate
- parser_degraded and semantic_outcome disagreement rate
- exploit confirmation count by class
- objective completion depth
- planner query volume and token cost

Safety KPIs:
- policy-denied action rate
- out-of-scope proposal rate
- high-risk action approval correctness
- generated payload rejection rate (preflight)

Learning KPIs (Phase 6E):
- policy ranking lift over heuristic baseline
- recovery efficiency after failed attempts
- benchmark success rate stability across target sets

## 13. Definition of Done for Phase 6 Program

Program done when:
- 6A to 6D are productionized with pass thresholds met.
- 6E demonstrates reliable gains in sandbox and remains policy-safe.
- End-to-end engagements show meaningful uplift without sacrificing compliance and auditability.

## 14. Immediate Next Execution Steps

1. Implement 6A ingestion and retrieval interfaces with pinned ATT&CK versioning.
2. Define 6B task-tree schemas and migration scripts.
3. Draft 6C payload DSL for SQLi and XSS plus policy preflight rules.
4. Set benchmark harness and KPI dashboards before rollout.

## 15. Phase 6A RAG Next Tasks (Sprint-Ready)

Status: Ready for execution
Sprint window: 2 weeks (execution slice of full 6A)

### 15.1 Deliverables for the next sprint

1. ATT&CK ingestion foundation
- Add `pwnpilot/control/attack_knowledge.py` with:
	- ATT&CK STIX loader
	- normalized in-memory/domain model
	- version pin + checksum capture for reproducibility
- Add ingestion tests for STIX parsing and version pin behavior.

2. Retrieval abstraction layer
- Add `pwnpilot/control/rag_retriever.py` with a strict return schema:
	- `technique_id`
	- `tactic`
	- `confidence`
	- `source`
	- `rationale_excerpt`
- Implement dual-mode retrieval:
	- mode A: lexical baseline (existing TF-IDF retrieval behavior)
	- mode B: embedding-backed retrieval (using `embedding_router`)
- Gate mode B behind config feature flag for safe rollout.

3. Planner context integration (minimal-risk)
- Inject retrieval output into planner context as `rag_context` (read-only signal).
- Do not hard-require planner schema changes in this sprint.
- Add fallback behavior: if retriever errors or empty response, continue existing planner flow.

4. Config and runtime wiring for RAG
- Add `rag` config section (new) with:
	- `enabled`
	- `mode` (`lexical` | `embedding` | `hybrid`)
	- `top_k`
	- `min_confidence`
	- `attack_stix_path`
	- `enable_internal_history`
- Wire RAG retriever construction in runtime and pass to planner node.

5. Observability and audit
- Emit events:
	- `rag.retrieve.started`
	- `rag.retrieve.completed`
	- `rag.retrieve.fallback`
	- `rag.retrieve.error`
- Include retrieval metadata in planner audit payloads.

### 15.2 File-level execution map

- `pwnpilot/control/attack_knowledge.py` (new)
- `pwnpilot/control/rag_retriever.py` (new)
- `pwnpilot/config.py` (add `RAGConfig`)
- `pwnpilot/runtime.py` (build and inject retriever)
- `pwnpilot/agent/planner.py` (consume `rag_context`)
- `config.example.yaml` (add `rag` section)
- `tests/unit/test_attack_knowledge.py` (new)
- `tests/unit/test_rag_retriever.py` (new)
- `tests/unit/test_planner_rag_integration.py` (new)

### 15.3 Acceptance criteria for this sprint slice

- RAG lexical mode is functional and covered by unit tests.
- Embedding mode is feature-flagged and non-breaking when disabled.
- Planner receives retrieval context without increasing reject-loop churn.
- No policy regressions in guided engagement runs.

## 16. Repository Consistency Check (Plan vs Current Code)

The following inconsistencies were identified and should be treated as plan updates or implementation deltas:

1. Embedding infrastructure exists but is not yet used by retrieval
- Current code has `EmbeddingRouter` and runtime wiring.
- Current retrieval path in `RetrievalStore` is TF-IDF lexical only.
- Plan should explicitly state this as the transition baseline for 6A execution.

2. Planner proposal schema extensions listed in plan are not implemented yet
- Plan references fields like `attack_technique_ids`, `retrieval_sources`, `retrieval_confidence`.
- Current `PlannerProposal` model does not include these fields.
- Action: stage these as Phase 6A.2+ schema migrations (not immediate sprint blocker).

3. Plan implies ATT&CK retrieval; repository currently has no ATT&CK ingestion module
- No `attack_knowledge`/STIX ingestion implementation exists yet.
- Action: implement ingestion before enabling ATT&CK-grounded retrieval claims.

4. Existing retrieval context key differs from planned naming
- Planner currently uses `memory_context.retrieved_context`.
- This plan introduces `rag_context` for explicit retrieval semantics.
- Action: standardize naming to avoid ambiguous planner prompts.

5. Documentation drift risk
- `IMPLEMENTATION_PLAN.md` now includes RAG/embedding strategy, but runtime behavior remains mostly lexical retrieval.
- Action: only mark 6A as in-progress after retriever wiring lands and tests pass.

## 17. Updated Near-Term Priority Order

1. Ship 6A lexical + ATT&CK ingestion foundation.
2. Integrate embedding-backed retrieval behind feature flag.
3. Add planner schema extensions for retrieval traceability.
4. Run guided benchmark and compare to current lexical baseline.

## 18. Second-Pass Assessment Findings (Additional Misses)

The following additional inconsistencies were found in a second repository pass:

1. Major documentation drift in config schema examples
- Multiple docs still use legacy keys (`provider`, `local_model`, `local_url`, `validator_model`) that do not match current `LLMConfig` (`model_name`, `api_key`, `api_base_url`, fallback fields).
- Affected docs include `docs/README.md`, `docs/INSTALLATION.md`, `docs/DEPLOYMENT.md`, and `docs/ARCHITECTURE.md` canonical schema examples.

2. Environment variable documentation drift
- Docs mention provider-specific env vars (`PWNPILOT_OPENAI_API_KEY`, `PWNPILOT_ANTHROPIC_API_KEY`) and old key styles that are not part of the current config load path.
- Current runtime/config logic uses section/key override pattern (`PWNPILOT_LLM__...`, `PWNPILOT_EMBEDDING__...`).

3. Embedding path lacks end-to-end integration tasking in the near-term plan
- `EmbeddingRouter` exists and is wired in runtime, but retrieval/query components do not consume it yet.
- Existing retrieval remains lexical TF-IDF in `RetrievalStore`.

4. RAG plan currently assumes new context key, while planner still consumes legacy memory key
- Planner currently uses `memory_context.retrieved_context`; RAG tasks introduce `rag_context`.
- A migration/compatibility strategy is needed to avoid prompt regression.

### 18.1 Remediation tasks added to near-term execution

1. Documentation alignment patch set (must run before marking 6A in-progress)
- Update all config examples to current schema:
	- `llm.model_name`, `llm.api_key`, `llm.api_base_url`, fallback fields.
	- `embedding.model_name` and related embedding fields.
- Replace legacy env var docs with `PWNPILOT_<SECTION>__<KEY>` examples.

2. Retrieval integration task split
- 6A.1: keep lexical retrieval baseline as default.
- 6A.2: add embedding-backed retrieval in retriever abstraction and route via feature flag.

3. Planner context migration task
- Introduce dual-read compatibility (`rag_context` preferred, fallback to `memory_context.retrieved_context`).
- Add deprecation note and removal target milestone.

4. Test coverage expansion for consistency
- Add tests for:
	- docs/config examples parse sanity (spot-check fixtures),
	- rag context compatibility behavior,
	- embedding retrieval fallback to lexical mode.

