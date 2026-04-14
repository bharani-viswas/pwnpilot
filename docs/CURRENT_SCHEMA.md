# Current Database Schema

## Overview
This document describes the current state of the pwnpilot database schema as of the latest migration (8f2a1c3b4d5e_add_roe_tables.py). The schema is managed using Alembic migrations.

## Migration History
1. **6dcea77ab8f0_initial_schema** - Initial core schema
2. **7c9029fd340a_add_approval_tickets** - Approval workflow and ticketing
3. **8f2a1c3b4d5e_add_roe_tables** - ROE management and compliance

---

## Tables

### 1. audit_events (Migration 1)
**Purpose**: Immutable audit trail of all engagement events with cryptographic integrity.

| Column | Type | Constraints | Notes |
|--------|------|-----------|-------|
| id | Integer | PK, AutoIncrement | Internal ID |
| event_id | String(36) | Unique | UUID for the event |
| engagement_id | String(36) | FK → engagements | References engagement |
| timestamp | DateTime | TZ-aware | When event occurred |
| actor | String(255) | - | User/system that triggered event |
| event_type | String(255) | - | Type of event (e.g., ACTION_EXECUTED) |
| payload_json | Text | - | Event details as JSON |
| payload_hash | String(64) | - | SHA-256 hash of payload (integrity) |
| prev_event_hash | String(64) | - | Hash of previous event (chain of custody) |
| decision_context_json | Text | Nullable | Policy decision context |
| schema_version | String(16) | - | Schema version for this event |
| sequence | Integer | - | Sequence within engagement |

**Indexes**:
- `ix_audit_events_engagement_id` (engagement_id)
- `ix_audit_events_event_id` (event_id, unique)

**Constraints**:
- `uq_engagement_sequence` - Unique (engagement_id, sequence) - ensures sequencing

---

### 2. evidence_index (Migration 1)
**Purpose**: Track evidence files collected during engagement with integrity hashes.

| Column | Type | Constraints | Notes |
|--------|------|-----------|-------|
| id | Integer | PK, AutoIncrement | Internal ID |
| evidence_id | String(36) | Unique | UUID for evidence |
| action_id | String(36) | - | Related action |
| engagement_id | String(36) | FK → engagements | References engagement |
| file_path | String(512) | - | Path to evidence file |
| sha256_hash | String(64) | - | SHA-256 hash of file content |
| size_bytes | Integer | - | File size in bytes |
| timestamp | DateTime | TZ-aware | When evidence was captured |
| truncated | Boolean | - | Whether file was truncated |

**Indexes**:
- `ix_evidence_index_evidence_id` (evidence_id, unique)
- `ix_evidence_index_engagement_id` (engagement_id)
- `ix_evidence_index_action_id` (action_id)

---

### 3. findings (Migration 1)
**Purpose**: Security findings from tools with deduplicated fingerprints per engagement.

| Column | Type | Constraints | Notes |
|--------|------|-----------|-------|
| id | Integer | PK, AutoIncrement | Internal ID |
| finding_id | String(36) | Unique | UUID for finding |
| engagement_id | String(36) | FK → engagements | References engagement |
| fingerprint | String(64) | - | Deduplication key |
| asset_ref | String(512) | - | Target system/asset |
| title | String(512) | - | Finding title |
| vuln_ref | String(256) | - | CVE/vulnerability reference |
| tool_name | String(128) | - | Tool that found it (e.g., nmap) |
| severity | String(32) | - | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| confidence | Float | - | 0.0-1.0 confidence score |
| exploitability | String(32) | - | Exploitability rating |
| cvss_score | Float | Nullable | CVSS v3.1 score |
| cvss_vector | String(256) | Nullable | CVSS vector string |
| risk_score | Float | - | Computed risk (severity × confidence) |
| evidence_ids_json | Text | - | Array of related evidence IDs |
| remediation | Text | - | Remediation guidance |
| status | String(32) | - | open, mitigated, false_positive |
| created_at | DateTime | TZ-aware | When finding was created |
| updated_at | DateTime | TZ-aware | Last update timestamp |

**Indexes**:
- `ix_findings_finding_id` (finding_id, unique)
- `ix_findings_engagement_id` (engagement_id)
- `ix_findings_fingerprint` (fingerprint)

**Constraints**:
- `uq_eng_fingerprint` - Unique (engagement_id, fingerprint) - one finding per type per engagement

---

### 4. recon_hosts (Migration 1)
**Purpose**: Discovered hosts during recon phase.

| Column | Type | Constraints | Notes |
|--------|------|-----------|-------|
| id | Integer | PK, AutoIncrement | Internal ID |
| host_id | String(36) | - | UUID for host |
| engagement_id | String(36) | FK → engagements | References engagement |
| ip_address | String(45) | - | IPv4 or IPv6 address |
| hostname | String(255) | Nullable | DNS hostname if resolved |
| os_guess | String(255) | Nullable | Detected OS |
| status | String(32) | - | up, down, unknown |
| first_seen | DateTime | TZ-aware | When discovered |
| last_seen | DateTime | TZ-aware | Last seen alive |

**Indexes**:
- `ix_recon_hosts_engagement_id` (engagement_id)
- `ix_recon_hosts_host_id` (host_id, unique)

**Constraints**:
- `uq_eng_ip` - Unique (engagement_id, ip_address)

---

### 5. approval_tickets (Migration 2)
**Purpose**: High-risk action approval workflow tickets.

| Column | Type | Constraints | Notes |
|--------|------|-----------|-------|
| ticket_id | String(36) | PK | UUID for ticket |
| engagement_id | String(36) | FK → engagements | References engagement |
| action_id | String(36) | - | Related action |
| action_type | String(64) | - | Type of action (e.g., MODIFY_DATA) |
| tool_name | String(128) | - | Tool that needs approval |
| risk_level | String(32) | - | CRITICAL, HIGH, MEDIUM |
| rationale | Text | - | Why approval is needed |
| impact_preview | Text | - | Preview of potential impact |
| status | String(32) | - | pending, approved, denied |
| resolved_by | String(255) | Nullable | User who resolved ticket |
| resolution_reason | Text | Nullable | Approval/denial reason |
| created_at | DateTime | TZ-aware | When ticket was created |
| expires_at | DateTime | Nullable | Ticket expiration time |
| resolved_at | DateTime | Nullable | When ticket was resolved |

**Indexes**:
- `ix_approval_tickets_engagement_id` (engagement_id)
- `ix_approval_tickets_action_id` (action_id)

---

### 6. roe_files (Migration 3)
**Purpose**: Immutable storage of uploaded ROE (Rules of Engagement) YAML files.

| Column | Type | Constraints | Notes |
|--------|------|-----------|-------|
| roe_id | String(36) | PK | UUID for ROE file |
| filename | String(255) | - | Original filename |
| content_hash | String(64) | - | SHA-256 hash of YAML content |
| content_yaml | Text | - | Full YAML content |
| uploaded_by | String(255) | - | User email who uploaded |
| uploaded_at | DateTime | TZ-aware | When ROE was uploaded |
| version | Integer | Default: 1 | Version number |
| is_active | Boolean | Default: true | Whether ROE is active |

**Indexes**:
- `ix_roe_files_content_hash` (content_hash)
- `ix_roe_files_uploaded_at` (uploaded_at)
- `ix_roe_files_is_active` (is_active)

---

### 7. engagement_policies (Migration 3)
**Purpose**: Interpreted and extracted policies from ROE for specific engagements.

| Column | Type | Constraints | Notes |
|--------|------|-----------|-------|
| policy_id | String(36) | PK | UUID for policy |
| engagement_id | String(36) | FK → engagements | References engagement |
| roe_id | String(36) | FK → roe_files | References ROE file |
| scope_cidrs | Text | - | JSON array of CIDR blocks |
| scope_domains | Text | - | JSON array of domains |
| scope_urls | Text | - | JSON array of URLs |
| excluded_ips | Text | - | JSON array of excluded IPs |
| restricted_actions | Text | - | JSON array of allowed actions |
| max_iterations | Integer | - | Maximum loop iterations |
| max_retries | Integer | - | Maximum retry attempts |
| cloud_allowed | Boolean | - | Allow cloud LLM fallback |
| confidence_score | Float | - | AI interpretation confidence (0-1) |
| created_at | DateTime | TZ-aware | When policy was extracted |

**Indexes**:
- `ix_engagement_policies_engagement_id` (engagement_id)
- `ix_engagement_policies_roe_id` (roe_id)
- `ix_engagement_policies_created_at` (created_at)

---

### 8. roe_approval_records (Migration 3)
**Purpose**: Immutable audit trail of ROE approvals with cryptographic verification.

| Column | Type | Constraints | Notes |
|--------|------|-----------|-------|
| approval_id | String(36) | PK | UUID for approval record |
| engagement_id | String(36) | FK → engagements | References engagement |
| roe_id | String(36) | FK → roe_files | References ROE file |
| approved_by | String(255) | - | User email who approved |
| approved_at | DateTime | TZ-aware | When ROE was approved |
| password_verified | Boolean | - | Sudo password verified |
| session_id | String(255) | - | Approval session ID |
| nonce_token_hash | String(64) | - | SHA-256 of approval token |

**Indexes**:
- `ix_roe_approval_records_engagement_id` (engagement_id)
- `ix_roe_approval_records_roe_id` (roe_id)
- `ix_roe_approval_records_approved_at` (approved_at)
- `ix_roe_approval_records_approved_by` (approved_by)

---

## Key Design Patterns

### 1. Immutable Audit Trail
- `audit_events` uses cryptographic hashing (`payload_hash`, `prev_event_hash`) for chain-of-custody
- All timestamps are timezone-aware
- Sequence numbers ensure strict ordering per engagement

### 2. Deduplication
- `findings` uses fingerprints to deduplicate similar findings
- Unique constraint (engagement_id, fingerprint) prevents duplicates

### 3. ROE Compliance
- `roe_files` stores immutable ROE documents
- `engagement_policies` contains AI-extracted policies
- `roe_approval_records` tracks approval chain with password verification

### 4. High-Risk Action Control
- `approval_tickets` gates risky operations
- Tickets have expiration and resolution tracking

### 5. Indexing Strategy
- Foreign key relationships indexed for join performance
- Timestamps indexed to support timeline queries
- Unique constraints on deduplication keys
- Hash fields indexed for fast lookups

---

## Foreign Key Relationships
All foreign keys reference a base `engagements` table (defined in pwnpilot data models):
- `audit_events.engagement_id` → engagements.engagement_id
- `evidence_index.engagement_id` → engagements.engagement_id
- `findings.engagement_id` → engagements.engagement_id
- `recon_hosts.engagement_id` → engagements.engagement_id
- `approval_tickets.engagement_id` → engagements.engagement_id
- `engagement_policies.engagement_id` → engagements.engagement_id
- `engagement_policies.roe_id` → roe_files.roe_id
- `roe_approval_records.engagement_id` → engagements.engagement_id
- `roe_approval_records.roe_id` → roe_files.roe_id

---

## JSON Storage Fields
The following columns store structured data as JSON strings:
- `audit_events.payload_json` - Event details
- `audit_events.decision_context_json` - Policy context
- `findings.evidence_ids_json` - Array of evidence IDs
- `engagement_policies.scope_cidrs` - Array of CIDR blocks
- `engagement_policies.scope_domains` - Array of domains
- `engagement_policies.scope_urls` - Array of URLs
- `engagement_policies.excluded_ips` - Array of IPs
- `engagement_policies.restricted_actions` - Array of allowed actions

---

**Last Updated**: April 12, 2026
**Schema Version**: 8f2a1c3b4d5e (add_roe_tables migration)
