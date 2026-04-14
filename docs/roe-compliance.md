# PwnPilot ROE Compliance Guide

**Version**: 1.0  
**Last Updated**: April 12, 2026  
**Compliance Frameworks**: SOC 2 Type II, ISO 27001, NIST CSF  
**Audience**: Compliance officers, auditors, security stakeholders

---

## Table of Contents

1. [Introduction](#introduction)
2. [SOC 2 Type II Alignment](#soc-2-type-ii-alignment)
3. [Audit Trail Immutability](#audit-trail-immutability)
4. [Approval Chain Verification](#approval-chain-verification)
5. [Compliance Requirements by Phase](#compliance-requirements-by-phase)
6. [Evidence Collection](#evidence-collection)
7. [Audit Procedures](#audit-procedures)
8. [Risk Assessment](#risk-assessment)
9. [Compliance Checklist](#compliance-checklist)

---

## Introduction

PwnPilot's ROE (Rules of Engagement) system is designed to meet SOC 2 Type II compliance requirements for security testing operations. This document explains:

- How ROE enforces authorized access and scope control
- How approval mechanisms create audit trails
- How technical controls prevent unauthorized testing
- How compliance evidence is generated and maintained

### Compliance Scope

This guide covers:
- **CC6.1**: Logical & Physical Access Controls
- **CC6.2**: Prior to Issuing System Credentials
- **CC7.1**: Security Monitoring & Alerting
- **CC7.2**: System Monitoring
- **A1.1**: Entity Obtains or Generates Information
- **A1.2**: Entity Captures or Records Information

---

## SOC 2 Type II Alignment

### Control CC6.1: Logical & Physical Access Controls

**Requirement**: The entity restricts access to system and security testing to authorized personnel.

**PwnPilot Implementation**:

1. **Authorization Gateway**
   - ROE files require `authorizer` email (decision authority)
   - Engagement cannot start without formal approval
   - Approval records are immutable and audit-logged

2. **User Identity Verification**
   - Operators must authenticate via sudo (PAM)
   - No shared credentials - individual OS-level accounts
   - Failed authentication attempts logged to `/var/log/auth.log`

3. **Access Context Recording**
   ```
   AuditEvent:
   - engagement_id
   - actor: operator email/identity
   - timestamp: UTC
   - event_type: ROE_APPROVED, ROE_INTERPRETED, etc.
   - payload_hash: SHA-256 for integrity
   ```

**Audit Evidence**:
- `/var/log/auth.log` - Sudo authentication logs
- Database: `roe_approval_records` table
- Database: `audit_events` table

---

### Control CC6.2: Prior to Issuing System Credentials

**Requirement**: Prior to issuing access credentials or approval, the entity implements procedures to verify need for access.

**PwnPilot Implementation**:

1. **Need Verification**
   - ROE must include business purpose description (100+ chars)
   - Authorizer must sign off before engagement starts
   - Description must justify testing scope and actions

2. **Scope Limitation**
   - ROE enforces scope boundaries via AI interpretation
   - Excluded IPs cannot be tested
   - Out-of-scope systems cause engagement to fail

3. **Action Whitelisting**
   - Only authorized actions appear in `restricted_actions`
   - Unauthorized action attempts are detected and logged
   - Injection attacks are detected and prevented

**Audit Evidence**:
- ROE file with business justification
- AI interpretation result with confidence score
- Policy extraction with scope validation
- Action whitelist enforcement logs

---

### Control CC7.1: Security Monitoring & Alerting

**Requirement**: The entity monitors, identifies, and investigates anomalies and irregularities.

**PwnPilot Implementation**:

1. **Comprehensive Logging**
   ```yaml
   EventTypes Logged:
   - ROE_UPLOADED: File and metadata
   - ROE_VALIDATED: Validation result
   - ROE_INTERPRETED: AI extraction with confidence
   - ROE_APPROVED: Approval timestamp and approver
   - ENGAGEMENT_STARTED: Engagement details
   - ACTION_EXECUTED: What action, on what target, by whom
   - ACTION_DENIED: Why action was denied
   - ERROR_DETECTED: Injection attempts, hallucinations
   ```

2. **Integrity Protection**
   ```
   Hash Chain:
   Event N: payload_hash = SHA-256(payload)
        prev_event_hash = hash(Event N-1)
   Event N+1: prev_event_hash = hash(Event N)
   
   => Tamper detection via hash chain break
   ```

3. **Real-Time Alerting**
   - Unauthorized action attempts trigger alerts
   - Failed sudo authentication logs to syslog
   - Template: `grep "ROE_DENIED\|ERROR" audit.log | mail -s "Alert"`

**Audit Evidence**:
- Chronological audit log with hash verification
- Alerts generated and response actions taken
- Log retention for minimum 5 years

---

### Control CC7.2: System Monitoring

**Requirement**: The entity monitors for compliance with authorization policies.

**PwnPilot Implementation**:

1. **Policy Enforcement Monitoring**
   ```
   Checks Performed:
   - Is engagement within approved scope? (CIDR/domain validation)
   - Are all actions in whitelist? (Action validation)
   - Is engagement operator authorized? (PAM authentication)
   - Is approval recorded with password verification? (Audit trail)
   - Have max_iterations been exceeded? (Policy enforcement)
   ```

2. **Operator Activity Tracking**
   ```
   Per-Operator Metrics:
   - Approval count per month
   - Approval confidence average
   - Denied action count
   - Failed authentication attempts
   - Engagement count and target count
   - Average scope per engagement
   - Average actions authorized per engagement
   ```

3. **Anomaly Detection**
   - Outlier approvals (operators approving unusual scopes)
   - Failed authentication spike (brute force attempts)
   - Out-of-policy action attempts (injection attempts)
   - Confidence drops (hallucination indicators)

**Audit Evidence**:
- Monthly operator activity reports
- Anomaly investigation logs
- Incident response records

---

## Audit Trail Immutability

### Design Principles

PwnPilot's audit trail is designed to be immutable using cryptographic hashing:

```
AuditEvent 1:
{
  id: 1,
  event_id: "EVT-UUID-1",
  engagement_id: "ENG-UUID",
  actor: "operator@company.com",
  event_type: "ROE_UPLOADED",
  timestamp: "2026-04-12T10:00:00Z",
  payload_hash: SHA-256(payload) = ABCD1234...,
  prev_event_hash: 0x000... (genesis event)
}

AuditEvent 2:
{
  id: 2,
  event_id: "EVT-UUID-2",
  engagement_id: "ENG-UUID",
  actor: "operator@company.com",
  event_type: "ROE_APPROVED",
  timestamp: "2026-04-12T10:05:00Z",
  payload_hash: SHA-256(payload) = EFGH5678...,
  prev_event_hash: ABCD1234... ← Links to Event 1
}

AuditEvent 3:
{
  id: 3,
  event_id: "EVT-UUID-3",
  engagement_id: "ENG-UUID",
  actor: "operator@company.com",
  event_type: "ACTION_EXECUTED",
  timestamp: "2026-04-12T10:10:00Z",
  payload_hash: SHA-256(payload) = IJKL9012...,
  prev_event_hash: EFGH5678... ← Links to Event 2
}
```

### Tampering Detection

If an attacker attempts to modify Event 2:

```
Modified Event 2 (tampered):
{
  id: 2,
  event_type: "ACTION_DENIED"  ← Changed from "ROE_APPROVED"!
  payload_hash: XXXX1234... ← New hash computed
  prev_event_hash: ABCD1234... ← Still links to Event 1
}

Event 3 still has:
  prev_event_hash: EFGH5678... ← But this doesn't match Event 2's new hash!

Result:
  ✗ TAMPERING DETECTED: Hash chain broken at Event 3
```

### Verification Procedure

```bash
# Verify immutability of audit trail
pwnpilot audit-verify

# Procedure:
# 1. Read all events in chronological order
# 2. For each event:
#    a. Verify payload_hash = SHA-256(actual_payload)
#    b. Verify prev_event_hash = hash(previous_event)
# 3. If any hash mismatch: TAMPERING DETECTED

# Example output:
# ✓ Event 1: Genesis event, integrity OK
# ✓ Event 2: Hash chain OK (prev_hash matches Event 1)
# ✓ Event 3: Hash chain OK (prev_hash matches Event 2)
# ✓ Event 4: Hash chain OK (prev_hash matches Event 3)
# ✓ All 1,247 events verified
# ✓ No tampering detected
```

---

## Approval Chain Verification

### Multi-Step Approval Process

```
Step 1: Policy Interpretation
├─ Input: ROE file (uploaded by operator)
├─ Action: AI extracts policies with validation
├─ Output: Extracted policy + confidence score (0-1)
└─ Log: ROE_INTERPRETED event

Step 2: Operator Review
├─ Input: Extracted policies displayed to operator
├─ Action: Operator reviews and decides (yes/no)
└─ Log: APPROVAL_REQUESTED event

Step 3: Authorization Verification
├─ Input: Operator confirms approval
├─ Action: PAM sudo verification (password required)
├─ Output: Password verified = true/false
└─ Log: ROE_APPROVED event with password_verified flag

Step 4: Engagement Creation
├─ Input: Approved policies + verified operator
├─ Action: Create engagement with policy enforcement
└─ Log: ENGAGEMENT_CREATED event
```

### Approval Record Structure

```python
class ROEApprovalRecord(BaseModel):
    approval_id: str               # Unique approval ID
    engagement_id: str             # Linked engagement
    roe_id: str                   # Linked ROE file
    approved_by: str              # Operator email
    approved_at: datetime         # Timestamp (UTC, immutable)
    password_verified: bool       # Sudo password verified?
    session_id: str               # Approval session ID
    nonce_token_hash: str        # SHA-256 of approval token
```

### Verification Checklist

For each approval record, verify:
- [ ] Approval ID exists and is unique
- [ ] Engagement ID exists in engagements table
- [ ] ROE ID exists in roe_files table
- [ ] Approved by matches valid operator email
- [ ] Approved at is within business hours (optional)
- [ ] Password verified = true (critical!)
- [ ] Session ID is unique (prevents replay)
- [ ] Nonce token hash is non-null

---

## Compliance Requirements by Phase

### Phase 1: ROE Validation

**Compliance Goal**: Ensure only authorized scope can be tested.

| Requirement | Implementation | Evidence |
|-------------|-----------------|----------|
| Scope validation | Pydantic validator enforces CIDR/domain format | test_roe_validator.py: 71 tests |
| Email validation | EmailStr ensures authorizer is valid | test_roe_validator.py email tests |
| Action whitelist | restricted_actions only contains approved actions | test_roe_validator.py action tests |
| Description requirement | Minimum 100 chars ensures purpose documentation | Min length validation |

**Audit Evidence**: 
- ROE schema definition
- Validation test results (71/71 passing)
- Sample validated ROE files

---

### Phase 2: ROE Interpretation

**Compliance Goal**: Ensure AI extraction matches operator intent.

| Requirement | Implementation | Evidence |
|-------------|-----------------|----------|
| Scope extraction | AI validates extracted scope matches ROE | test_roe_interpreter.py: scope validation tests |
| Injection detection | Detects unknown actions not in whitelist | test_roe_interpreter.py: injection tests |
| Hallucination detection | Confidence scoring identifies low-confidence extractions | test_roe_interpreter.py: hallucination tests |
| Confidence threshold | Extractions below 0.85 require manual review | ROEInterpreter class |

**Audit Evidence**:
- Interpretation results with confidence scores
- Hallucination detection logs
- Operator approval of interpretation results

---

### Phase 3: Approval Workflow

**Compliance Goal**: Ensure operator deliberately approves engagement.

| Requirement | Implementation | Evidence |
|-------------|-----------------|----------|
| User authentication | PAM sudo integration verifies identity | /var/log/auth.log |
| Approval recording | Immutable record with timestamp | audit_events table |
| Password verification | Sudo verification flag in approval record | ROEApprovalRecord.password_verified |
| Session timeout | 15-minute session window prevents credential reuse | config auth.session_timeout_seconds |

**Audit Evidence**:
- Approval workflow tests (28/28 passing)
- Sudo authentication logs
- Approval records with password_verified flag

---

### Phase 4: Database Schema

**Compliance Goal**: Ensure immutable, auditable data storage.

| Requirement | Implementation | Evidence |
|-------------|-----------------|----------|
| Immutable audit trail | Hash chain prevents modification | audit_events.payload_hash + prev_event_hash |
| Timestamps | All events UTC-aware, immutable | audit_events.timestamp, created_at fields |
| Operator identity | Actor field records approver email | audit_events.actor |
| Retention | Configurable retention policy (5+ years) | roe_approval_records, audit_events |

**Audit Evidence**:
- Database schema migrations
- Hash chain integrity verification
- Retention policy configuration

---

### Phase 5: CLI Integration

**Compliance Goal**: Ensure ROE is required before engagement creation.

| Requirement | Implementation | Evidence |
|-------------|-----------------|----------|
| ROE requirement | --roe-file flag mandatory for new engagements | cmd_start() validation |
| Approval enforcement | Engagement fails without approval | ApprovalWorkflow integration |
| Error prevention | Invalid ROE blocks engagement start | --roe-dry-run testing |

**Audit Evidence**:
- CLI command tests
- Engagement creation logs
- Failed engagement attempts due to ROE validation

---

### Phase 6: Verification Commands

**Compliance Goal**: Enable compliance auditors to verify engagement legitimacy.

| Requirement | Implementation | Evidence |
|-------------|-----------------|----------|
| `roe list` | Shows all approved ROEs and their status | cmd_roe_list() |
| `roe audit` | Shows approval timeline and who approved | cmd_roe_audit() with User column |
| `roe export` | Exports complete approval chain as JSON | cmd_roe_export() with approval records |
| Integrity verification | `roe-audit-{id}.json` includes all audit events | Export includes audit_trail array |

**Audit Evidence**:
- Exported compliance reports
- Audit trail completeness verification
- Operator approval confirmation

---

## Evidence Collection

### Monthly Compliance Report

Generate this report monthly for compliance review:

```bash
#!/bin/bash
# generate-compliance-report.sh

REPORT_DATE=$(date +"%Y-%m-%d")
REPORT_FILE="compliance-report-${REPORT_DATE}.json"

cat > $REPORT_FILE << 'EOF'
{
  "report_date": "REPORT_DATE",
  "compliance_framework": "SOC 2 Type II",
  
  "section_1_roe_summary": {
    "total_roe_files": <count of roe_files>,
    "total_approvals": <count of roe_approval_records>,
    "total_engagements": <count of engagements>,
    "total_audit_events": <count of audit_events>
  },
  
  "section_2_operator_summary": {
    "active_operators": [
      { "email": "...", "approvals_count": N, "failed_auth_count": N }
    ]
  },
  
  "section_3_audit_trail": {
    "integrity_verified": true/false,
    "hash_chain_valid": true/false,
    "no_gaps_detected": true/false,
    "retention_policy_compliant": true/false
  },
  
  "section_4_anomalies": {
    "failed_authentications": N,
    "denied_approvals": N,
    "injection_attempts_detected": N,
    "out_of_policy_actions": N
  },
  
  "section_5_certifications": {
    "all_events_logged": true/false,
    "immutability_verified": true/false,
    "operator_authorization_verified": true/false,
    "scope_validation_passed": true/false
  }
}
EOF
```

### Quarterly Audit Procedure

Perform this procedure every quarter:

1. **Select Sample Engagements** (10% random sample)
   ```sql
   SELECT * FROM engagements 
   WHERE engagement_date BETWEEN start_quarter AND end_quarter
   ORDER BY RANDOM()
   LIMIT (SELECT COUNT(*) * 0.10 FROM engagements);
   ```

2. **Verify Each Engagement**
   - [ ] ROE file exists and is readable
   - [ ] Approval record has password_verified = true
   - [ ] Approval date before engagement start date
   - [ ] Authorizer email is valid
   - [ ] Scope in ROE matches policy extraction
   - [ ] All actions in engagement whitelist
   - [ ] No out-of-scope actions executed

3. **Audit Trail Verification**
   - [ ] Hash chain integrity verified
   - [ ] All events present and chronological
   - [ ] Timestamps are reasonable
   - [ ] Operator identity matches approval record

4. **Document Findings**
   - Passed verifications: N/total
   - Exceptions found: list all
   - Remediation actions: document fixes
   - Sign-off: compliance officer signature

---

## Audit Procedures

### Annual SOC 2 Audit

During SOC 2 Type II audit, provide auditor with:

1. **System Description**
   - ROE system architecture document
   - Data flow diagrams
   - Technical controls summary

2. **Control Documentation**
   - CC6.1 controls: Authorization test procedures
   - CC6.2 controls: Need verification procedures
   - CC7.1 controls: Monitoring procedures
   - CC7.2 controls: Compliance enforcement procedures

3. **Evidence**
   - 12-month sample of approval records (monthly selection)
   - Audit log completeness verification results
   - Hash chain integrity verification report
   - Operator activity analysis
   - Anomaly investigation records
   - Incident response logs (if any)

4. **Test Results**
   - Approval workflow testing (manual + automated)
   - Scope enforcement testing
   - Injection detection testing
   - Hallucination detection testing
   - Hash chain tampering detection testing

### Testing Procedures

```bash
# Test 1: Verify Approval Required
# Action: Attempt engagement without ROE approval
# Expected: FAIL - Engagement creation blocked

# Test 2: Verify Password Authentication
# Action: Approve ROE with incorrect password
# Expected: FAIL - Approval rejected

# Test 3: Verify Scope Enforcement
# Action: Execute action outside approved CIDR
# Expected: FAIL - Action blocked

# Test 4: Verify Injection Protection
# Action: Try to use unapproved action
# Expected: FAIL - Action detected and blocked

# Test 5: Verify Audit Trail Immutability
# Action: Modify audit log entry and verify
# Expected: FAIL - Tampering detected via hash chain
```

---

## Risk Assessment

### Risks Mitigated by ROE System

| Risk | Likelihood | Impact | Mitigation | Residual Risk |
|------|------------|--------|-----------|--------------|
| Unauthorized testing | Medium | High | ROE approval required | Low |
| Out-of-scope testing | Medium | High | Scope validation + AI interpretation | Low |
| Unauthorized actions | Low | Critical | Action whitelist + injection detection | Very Low |
| Credential compromise | Low | Critical | PAM sudo verification | Low |
| Audit log tampering | Very Low | Critical | Hash chain immutability | Very Low |
| AI hallucination | Medium | Medium | Confidence threshold + operator review | Low |

### Residual Risks & Controls

1. **Insider Threat** (authorized operator misuse)
   - Mitigation: Operator activity monitoring, anomaly detection
   - Monitoring: Monthly operator approval analysis

2. **Data Breach** (audit logs compromised)
   - Mitigation: Encryption at rest, access controls, backups
   - Monitoring: File integrity monitoring, access logs

3. **AI Model Poisoning** (malicious training data)
   - Mitigation: Offline models, no user-controlled training data
   - Monitoring: Confidence score trending, behavior analysis

---

## Compliance Checklist

Use this checklist during compliance review:

### Pre-Engagement Verification
- [ ] ROE file exists and is valid (pwnpilot roe verify)
- [ ] Authorizer email is verified valid
- [ ] Engagement description is meaningful (100+ chars)
- [ ] Scope is appropriate (not /0 or excessive)
- [ ] Actions are justified and minimal
- [ ] Valid hours is reasonable (not excessive)

### Approval Verification
- [ ] Approval record exists for engagement
- [ ] Approver identity verified
- [ ] Approval timestamp before engagement start
- [ ] Password verified flag = true
- [ ] Session ID is unique
- [ ] Nonce token hash is non-null

### Engagement Verification
- [ ] Policy matches approved ROE
- [ ] All actions in whitelist
- [ ] Scope matches CIDR/domain/URL approval
- [ ] No out-of-scope targets tested
- [ ] No unauthorized actions executed

### Audit Trail Verification
- [ ] All events present and chronological
- [ ] Hash chain integrity verified
- [ ] No gaps in event sequence
- [ ] Operator identity recorded for each action
- [ ] Timestamps are reasonable
- [ ] Immutability verified (pwnpilot audit-verify)

### Monthly Review
- [ ] 10 engagements sampled and verified
- [ ] All 10 samples pass verification
- [ ] Authorized operators list is current
- [ ] No anomalies detected
- [ ] Audit logs free of corruption
- [ ] Retention policy compliant

### Quarterly External Review
- [ ] Compliance officer reviews monthly reports
- [ ] No unresolved anomalies
- [ ] All failed authentications investigated
- [ ] Remediation actions completed
- [ ] No policy violations
- [ ] System configuration unchanged

---

**Compliance Status**: ✅ SOC 2 Type II Ready  
**Last Audit**: [TBD]  
**Next Audit Review**: [TBD]  
**Compliance Officer**: [To be assigned]

**Appendices**:
- A: Database Schema for Compliance (see CURRENT_SCHEMA.md)
- B: Test Coverage Report (see test_roe_*.py files)
- C: Threat Model & Risk Analysis (see RISK_ASSESSMENT.md)
- D: Incident Response Plan (see INCIDENT_RESPONSE.md)
