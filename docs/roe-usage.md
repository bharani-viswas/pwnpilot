# PwnPilot ROE User Guide

**Version**: 1.0  
**Last Updated**: April 12, 2026  
**Audience**: Penetration testers, security engineers, authorized operators

---

## Table of Contents

1. [Introduction](#introduction)
2. [ROE Concepts](#roe-concepts)
3. [Creating ROE Files](#creating-roe-files)
4. [Field Reference](#field-reference)
5. [Examples](#examples)
6. [Best Practices](#best-practices)
7. [Common Mistakes](#common-mistakes)
8. [Troubleshooting](#troubleshooting)

---

## Introduction

A **Rules of Engagement (ROE)** file is a YAML document that formally defines the scope, approved actions, and operational constraints for a penetration testing engagement. ROE files serve as the single source of truth for:

- **What systems** can be tested (CIDRs, domains, URLs)
- **What actions** are permitted (modify data, delete data, etc.)
- **Operational limits** (max iterations, timeouts, resource usage)
- **Approval chain** and operator identity verification

PwnPilot uses ROE files to:
1. **Validate scope** - Ensure generated tests stay within approved boundaries
2. **Enforce policy** - Prevent unauthorized actions via AI policy extraction
3. **Audit compliance** - Maintain immutable records for SOC 2 Type II
4. **Enable approval** - Require operator authorization before engagement

---

## ROE Concepts

### Scope
The **scope** section defines what systems can be tested. PwnPilot supports three scope methods:

- **CIDR Blocks**: Network ranges (e.g., `192.168.0.0/24`) - use for internal networks
- **Domains**: FQDN targets (e.g., `example.com`, `app.prod.example.com`) - use for web applications
- **URLs**: Specific entry points (e.g., `https://api.example.com/login`) - use for precise targeting

At least one scope type must be specified.

### Actions
The **restricted_actions** section whitelists which actions the agent can execute. Valid actions are:

| Action | Description | Risk Level | Typical Use |
|--------|-------------|-----------|-------------|
| `MODIFY_DATA` | Change data in databases or files | HIGH | Testing data validation, persistence |
| `DELETE_DATA` | Remove data from systems | CRITICAL | Data integrity testing (use cautiously) |
| `ENCRYPT_DATA` | Encrypt or obfuscate data | MEDIUM | Ransomware simulation, defense testing |
| `STOP_SERVICES` | Disable running services | HIGH | Availability testing, resilience |
| `MODIFY_CREDENTIALS` | Create, change, or reset credentials | HIGH | Access control testing |
| `EXFILTRATE_DATA` | Copy sensitive data to external locations | CRITICAL | Data leakage detection (restricted) |

### Policy
The **policy** section defines operational parameters:

| Parameter | Range | Default | Description |
|-----------|-------|---------|-------------|
| `max_iterations` | 1-1000 | 50 | Maximum agent loop iterations (higher = more thorough) |
| `max_retries` | 1-10 | 3 | Retry attempts per LLM call (for transient errors) |
| `timeout_seconds` | 300+ | 3600 | Engagement timeout in seconds (5 min minimum) |
| `cloud_allowed` | true/false | false | Allow cloud LLM fallback (may incur costs) |

---

## Creating ROE Files

### Step 1: Define Engagement Metadata

Every ROE file requires engagement metadata:

```yaml
engagement:
  name: "Internal Network Pentest - Q2 2026"
  authorizer: "security-lead@company.com"  # Email address required
  description: |
    Comprehensive penetration test of internal network infrastructure
    including firewalls, switches, and server endpoints across all
    data centers to assess security posture.
  valid_hours: 24
```

**Field Explanations**:
- `name`: 8-64 characters, descriptive engagement identifier
- `authorizer`: Email of person authorizing this ROE (for audit trail)
- `description`: 100+ characters explaining the engagement purpose and scope
- `valid_hours`: How long the engagement is authorized (1-8760 hours = up to 1 year)

### Step 2: Define Scope

Choose the most specific scope method appropriate for your targets:

**Option A: CIDR Blocks** (Network ranges)
```yaml
scope:
  cidrs: "192.168.1.0/24,10.0.0.0/8"
  domains: ""
  urls: ""
  excluded_ips: "192.168.1.1,192.168.1.254"
  restricted_actions: ""
```

**Option B: Domains** (Web applications)
```yaml
scope:
  cidrs: ""
  domains: "example.com,app.example.com,api.prod.example.com"
  urls: ""
  excluded_ips: ""
  restricted_actions: ""
```

**Option C: URLs** (Specific endpoints)
```yaml
scope:
  cidrs: ""
  domains: ""
  urls: "https://api.example.com/v1,https://auth.example.com"
  excluded_ips: ""
  restricted_actions: ""
```

**Option D: Mixed** (Combine scope types)
```yaml
scope:
  cidrs: "192.168.1.0/24,10.0.0.0/8"
  domains: "prod.example.com"
  urls: "https://backup.company.local/admin"
  excluded_ips: "192.168.1.253"
  restricted_actions: ""
```

**Exclusions**: List IPs or ranges to never test, even if in scope CIDR:
```yaml
excluded_ips: "192.168.1.100,192.168.1.200-192.168.1.250"
```

### Step 3: Specify Allowed Actions

```yaml
scope:
  restricted_actions: "MODIFY_DATA,DELETE_DATA"
```

This whitelists which actions the agent can execute. If an action isn't listed, it cannot be used.

### Step 4: Define Policy Parameters

```yaml
policy:
  max_iterations: 50
  max_retries: 3
  timeout_seconds: 3600
  cloud_allowed: false
```

### Complete Example

```yaml
engagement:
  name: "Web App Security Audit 2026"
  authorizer: "ciso@company.com"
  description: |
    Security audit of customer-facing web application stack including
    authentication, API, and database layers. Testing for OWASP Top 10
    vulnerabilities. This is a comprehensive assessment.
  valid_hours: 48

scope:
  cidrs: ""
  domains: "api.myapp.com,web.myapp.com"
  urls: ""
  excluded_ips: ""
  restricted_actions: "MODIFY_DATA"

policy:
  max_iterations: 75
  max_retries: 5
  timeout_seconds: 7200
  cloud_allowed: false
```

---

## Field Reference

### Engagement Metadata

#### `engagement.name`
- **Type**: String (8-64 characters)
- **Required**: Yes
- **Example**: `"Q2 2026 Internal Network Pentest"`
- **Validation**: Must be alphanumeric with spaces, underscores, hyphens allowed
- **Purpose**: Unique identifier for the engagement in audit logs and reports

#### `engagement.authorizer`
- **Type**: Email address (RFC 5322)
- **Required**: Yes
- **Example**: `"security-lead@company.com"`
- **Validation**: Must be valid email format
- **Purpose**: Identifies who authorized this engagement for accountability

#### `engagement.description`
- **Type**: String (100+ characters)
- **Required**: Yes
- **Example**: See "Creating ROE Files" section above
- **Validation**: Minimum 100 characters to prevent vague authorizations
- **Purpose**: Clear business justification for the engagement

#### `engagement.valid_hours`
- **Type**: Integer (1-8760)
- **Required**: No (default: 24)
- **Example**: `48`
- **Validation**: Between 1 hour and 1 year
- **Purpose**: Authorization window (automatically expires after this time)

### Scope Fields

#### `scope.cidrs`
- **Type**: Comma-separated IPv4 CIDR blocks
- **Required**: No (but at least one scope type required)
- **Example**: `"192.168.0.0/24,10.0.0.0/8,172.16.0.0/12"`
- **Validation**: Valid CIDR notation, no smaller than /24 recommended 
- **Purpose**: Network ranges to include in testing

#### `scope.domains`
- **Type**: Comma-separated domain names (FQDNs)
- **Required**: No (but at least one scope type required)
- **Example**: `"example.com,prod.example.com,api.example.com"`
- **Validation**: Valid FQDN format, no wildcards in scope (wildcards ok in exclusions)
- **Purpose**: Domain-based targets (typical for web applications)

#### `scope.urls`
- **Type**: Comma-separated full URLs (http/https)
- **Required**: No
- **Example**: `"https://api.example.com,https://auth.example.org:8443"`
- **Validation**: Must include protocol (http:// or https://), valid URL format
- **Purpose**: Specific entry points when precise targeting needed

#### `scope.excluded_ips`
- **Type**: Comma-separated IPs or IP ranges
- **Required**: No
- **Example**: `"192.168.1.1,192.168.1.100-192.168.1.110"`
- **Validation**: Valid IPv4 addresses or ranges; must be within scope CIDR if specified
- **Purpose**: Critical systems to skip (firewalls, load balancers, etc.)

#### `scope.restricted_actions`
- **Type**: Comma-separated action names
- **Required**: No (default: no actions permitted)
- **Example**: `"MODIFY_DATA,DELETE_DATA"`
- **Validation**: Must be from approved action list
- **Purpose**: Whitelist of permitted agent actions

### Policy Fields

#### `policy.max_iterations`
- **Type**: Integer (1-1000)
- **Required**: No (default: 50)
- **Example**: `100`
- **Validation**: \> 0, \< 1001. Warning if < 20 (typical: 50-100)
- **Purpose**: Agent loop limit (balances thoroughness vs. time/cost)

#### `policy.max_retries`
- **Type**: Integer (1-10)
- **Required**: No (default: 3)
- **Example**: `5`
- **Validation**: Between 1-10
- **Purpose**: Retry limit for failed LLM calls (handles transient errors)

#### `policy.timeout_seconds`
- **Type**: Integer (300+)
- **Required**: No (default: 3600)
- **Example**: `7200`
- **Validation**: Minimum 300 seconds (5 minutes)
- **Purpose**: Engagement timeout (prevents long-running/stuck processes)

#### `policy.cloud_allowed`
- **Type**: Boolean (true/false)
- **Required**: No (default: false)
- **Example**: `true`
- **Validation**: true or false only
- **Purpose**: Allow cloud LLM fallback (may incur AWS costs) - request higher-cost more capable models

---

## Examples

### Example 1: Internal Network Assessment

```yaml
engagement:
  name: "Internal Network Assessment Q2"
  authorizer: "infra-security@company.com"
  description: |
    Quarterly assessment of internal network security including
    vulnerability scanning, privilege escalation attempts, and
    lateral movement testing across all three data centers.
  valid_hours: 72

scope:
  cidrs: "192.168.0.0/16,10.20.0.0/16,172.31.0.0/16"
  domains: ""
  urls: ""
  excluded_ips: "192.168.0.1,10.20.0.1,172.31.0.1"
  restricted_actions: "MODIFY_DATA"

policy:
  max_iterations: 100
  max_retries: 5
  timeout_seconds: 14400
  cloud_allowed: false
```

### Example 2: Web Application Penetration Test

```yaml
engagement:
  name: "WebApp Pentest - Production"
  authorizer: "appsec@company.com"
  description: |
    Annual security assessment of customer-facing web application
    infrastructure including OWASP Top 10 vulnerability testing,
    authentication/authorization analysis, and API endpoint analysis.
  valid_hours: 48

scope:
  cidrs: ""
  domains: "api.prod.company.com,portal.prod.company.com"
  urls: ""
  excluded_ips: ""
  restricted_actions: "MODIFY_DATA,DELETE_DATA"

policy:
  max_iterations: 75
  max_retries: 3
  timeout_seconds: 7200
  cloud_allowed: false
```

### Example 3: Red Team Engagement (High Permission)

```yaml
engagement:
  name: "Red Team Exercise 2026"
  authorizer: "ciso@company.com"
  description: |
    Authorized red team engagement for annual security exercise.
    Full scope internal and external testing with comprehensive
    post-engagement reporting and findings.
  valid_hours: 168

scope:
  cidrs: "0.0.0.0/0"
  domains: ""
  urls: ""
  excluded_ips: "203.0.113.100"
  restricted_actions: "MODIFY_DATA,DELETE_DATA,ENCRYPT_DATA,STOP_SERVICES,MODIFY_CREDENTIALS"

policy:
  max_iterations: 200
  max_retries: 5
  timeout_seconds: 28800
  cloud_allowed: true
```

---

## Best Practices

### 1. Be Specific with Scope
- ✅ **Good**: `scope.cidrs: "192.168.1.0/24"` - precise, limited impact
- ❌ **Bad**: `scope.cidrs: "0.0.0.0/0"` - tests everything on internet (unapproved!)

### 2. Start Conservative with Actions
- ✅ **Good**: Start with no actions, add only what's needed
- ❌ **Bad**: Enable all actions by default, then restrict later

### 3. Document the Purpose
- ✅ **Good**: 200+ character description explaining security goal
- ❌ **Bad**: "Annual pentest" (too vague, doesn't justify scope)

### 4. Set Realistic Iterations
- ✅ **Good**: 50-100 for thorough testing, 200+ for red team
- ❌ **Bad**: 1-5 iterations (won't find many issues)

### 5. Use Exclusions Wisely
- ✅ **Good**: Exclude IPs known to be critical (primary firewall, DNS, etc.)
- ❌ **Bad**: Exclude so many IPs that scope becomes meaningless

### 6. Require Approval from Authority
- ✅ **Good**: Authorizer is security lead or CISO (decision authority)
- ❌ **Bad**: Authorizer is engineer doing the test (conflict of interest)

### 7. Set Appropriate Timeouts
- ✅ **Good**: 1-2 hours for typical web app, 4+ hours for network pentest
- ❌ **Bad**: 300 seconds (5 min - insufficient for real testing)

### 8. Validate Before Execution
```bash
pwnpilot roe verify my-roe.yaml  # Always validate first!
```

---

## Common Mistakes

### Mistake 1: Invalid Email in Authorizer
```yaml
# ❌ WRONG
authorizer: "john.doe"  # Not an email

# ✅ CORRECT
authorizer: "john.doe@company.com"
```

### Mistake 2: Insufficient Description
```yaml
# ❌ WRONG - Only 15 characters
description: "Web app test"

# ✅ CORRECT - 120+ characters
description: |
  Comprehensive security assessment of customer-facing web application
  to identify vulnerabilities and validate security controls.
```

### Mistake 3: Using Overlapping Scope Methods
```yaml
# ⚠️ RISKY - Overlapping and unclear
scope:
  cidrs: "192.168.0.0/16"
  domains: "app.company.intern"  # What IP is this?
  urls: "https://10.20.30.40"    # Already in CIDR?
```

### Mistake 4: No Exclusions for Critical Systems
```yaml
# ❌ RISKY - No exclusions
scope:
  cidrs: "192.168.0.0/24"
  excluded_ips: ""

# ✅ SAFER - Exclude firewalls, DNS, critical servers
scope:
  cidrs: "192.168.0.0/24"
  excluded_ips: "192.168.0.1,192.168.0.2,192.168.0.253-254"
```

### Mistake 5: Allowing All Actions Without Justification
```yaml
# ❌ DANGEROUS
restricted_actions: "MODIFY_DATA,DELETE_DATA,STOP_SERVICES,EXFILTRATE_DATA"

# ✅ JUSTIFIED - Only what's needed
restricted_actions: "MODIFY_DATA"
```

### Mistake 6: Overly Broad CIDR Blocks
```yaml
# ❌ TOO BROAD
cidrs: "0.0.0.0/0"  # Everything!
cidrs: "10.0.0.0/8"  # 65k+ systems!

# ✅ APPROPRIATE
cidrs: "192.168.1.0/24"     # ~250 systems
cidrs: "10.20.5.0/25,10.20.5.128/25"  # Two specific subnets
```

---

## Troubleshooting

### Issue: "ROE validation failed"

**Cause**: ROE file has schema errors

**Solution**:
```bash
pwnpilot roe verify my-roe.yaml
# Check error messages for specific field issues
```

**Common causes**:
- Email not valid format
- Description < 100 characters
- CIDR block in incorrect format
- Unknown action name

### Issue: "String should have at least 100 characters"

**Cause**: Description field too short

**Solution**: Expand description to provide business context:
```yaml
description: |
  This engagement conducts comprehensive security assessment of
  critical production infrastructure to validate controls.
  Testing includes vulnerability scanning, privilege escalation
  attempts, and lateral movement analysis across all systems.
```

### Issue: "Invalid CIDR '192.168.1.0/33'"

**Cause**: Invalid CIDR notation (must be /0 to /32)

**Solution**: Use valid CIDR notation:
- `/8` = 65,536 hosts
- `/16` = 65,536 hosts in subnet
- `/24` = 254 hosts (typical)
- `/32` = 1 single host

### Issue: "Field required" for engagement.authorizer

**Cause**: Authorizer email missing

**Solution**: Add valid email:
```yaml
engagement:
  authorizer: "security-lead@company.com"
```

### Issue: "At least one of cidrs, domains, or urls must be specified"

**Cause**: Scope is completely empty

**Solution**: Specify at least one scope type:
```yaml
scope:
  cidrs: "192.168.1.0/24"  # Add your targets here
  domains: ""
  urls: ""
```

---

## Next Steps

After creating your ROE file:

1. **Validate**: `pwnpilot roe verify my-roe.yaml`
2. **Review**: Have security lead review and sign off
3. **Execute**: `pwnpilot start --name "Engagement Name" --roe-file my-roe.yaml`
4. **Approve**: Provide sudo password when prompted
5. **Monitor**: Check logs and findings in real-time
6. **Export**: `pwnpilot roe export <engagement-id>` for compliance archives

---

**Need Help?** Contact your security operations team or refer to [roe-admin.md](roe-admin.md) for administrator guidance.
