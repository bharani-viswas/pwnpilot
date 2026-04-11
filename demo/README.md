# PwnPilot Demo Artifacts

This folder contains all generated demo artifacts from the OWASP Juice Shop security assessment.

## 📁 Folder Structure

```
demo/
├── README.md                          (this file)
├── config/                            Configuration files
│   ├── demo_roe.md                   Rules of Engagement document
│   └── demo_config.yaml              PwnPilot configuration
├── reports/                           Findings and reports
│   ├── VULNERABILITY_FINDINGS.md     Summary of 6 vulnerabilities
│   ├── DEMO_ASSESSMENT_REPORT.md     Detailed technical analysis
│   ├── nikto_report.txt              Raw Nikto scanner output
│   └── report_*.json                 PwnPilot engagement bundles
└── guides/                            How-to documentation
    ├── DEMO_SETUP.md                 Complete setup instructions
    └── TESTING_GUIDE.md              Step-by-step testing guide
```

## 📋 Files Overview

### Configuration (`config/`)

**demo_roe.md** (1.2 KB)
- Rules of Engagement document
- Defines scope and authorization
- Required for PwnPilot engagement
- Used to generate engagement ID hash

**demo_config.yaml** (771 B)
- PwnPilot framework configuration
- Database settings
- LLM configuration
- Policy enforcement rules
- Audit trail settings

### Reports (`reports/`)

**VULNERABILITY_FINDINGS.md** (2.8 KB)
- Executive summary of 6 findings
- Severity classification
- Quick reference
- Remediation tips

**DEMO_ASSESSMENT_REPORT.md** (5.8 KB)
- Full technical analysis
- Detailed vulnerability descriptions
- Impact assessment
- Security recommendations
- Tools used summary

**nikto_report.txt**
- Raw output from Nikto web server scanner
- 11 security findings
- HTTP header analysis
- Directory enumeration results

**report_*.json**
- PwnPilot engagement bundles
- Machine-readable format
- Can be verified with `pwnpilot verify-report`

### Guides (`guides/`)

**DEMO_SETUP.md** (5.3 KB)
- Complete demo setup instructions
- Quick-start commands
- Services status
- Troubleshooting tips

**TESTING_GUIDE.md** (5.0 KB)
- How to run PwnPilot tests
- Step-by-step workflow
- Tool examples
- Environment variables

## 🚀 Quick Start

### View Findings
```bash
cat reports/VULNERABILITY_FINDINGS.md
cat reports/DEMO_ASSESSMENT_REPORT.md
```

### Run a Test
```bash
# Activate PwnPilot
cd ../
source .pwnpilot-activate.sh

# Generate ROE hash
ROE_HASH=$(sha256sum demo/config/demo_roe.md | cut -d' ' -f1)

# Run test
pwnpilot start \
  --name "MyTest" \
  --url "http://localhost:3000" \
  --roe-hash "$ROE_HASH" \
  --authoriser "TestTeam" \
  --config demo/config/demo_config.yaml \
  --dry-run
```

### View Detailed Report
```bash
cat demo/guides/DEMO_SETUP.md
cat demo/guides/TESTING_GUIDE.md
```

## 📊 Findings Summary

**Total Vulnerabilities**: 6
- 🔴 High: 1 (CORS misconfiguration)
- 🟠 Medium: 4 (HTTP methods, exposed dirs, missing headers, robots.txt)
- 🟡 Low: 1 (ETag disclosure)

**Tools Executed**: 6/6 (100% success)
- nmap, nikto, whatweb, sqlmap, whois, dig

**Scan Time**: ~45 seconds

## 🔄 Next Steps

1. **Review Findings**
   - Start with `reports/VULNERABILITY_FINDINGS.md`
   - Then read `reports/DEMO_ASSESSMENT_REPORT.md`

2. **Understand the Tools**
   - Check `reports/nikto_report.txt` for raw output
   - Review `guides/TESTING_GUIDE.md` for tool examples

3. **Run Your Own Test**
   - Follow steps in `guides/DEMO_SETUP.md`
   - Use configuration from `config/demo_config.yaml`

4. **Deploy to Production**
   - See main README.md for production setup
   - Configure Rules of Engagement (copy from config/)
   - Set up persistent database and audit trail

## 📂 Reference

| Path | Purpose |
|------|---------|
| ../README.md | Main PwnPilot documentation |
| ../ARCHITECTURE.md | Framework architecture |
| ../INSTALLATION.md | Installation guide |
| ../VULNERABILITY_FINDINGS.md | Quick findings ref |
| guides/TESTING_GUIDE.md | Testing workflow |
| guides/DEMO_SETUP.md | Demo instructions |
| config/demo_roe.md | Authorization document |
| config/demo_config.yaml | Configuration template |
| reports/ | All findings and reports |

## ✅ Demo Status

- ✓ OWASP Juice Shop running (port 3000)
- ✓ All tools configured and tested
- ✓ 6 vulnerabilities identified
- ✓ Reports generated
- ✓ Documentation complete

---

**Created**: 2026-04-09  
**Status**: Complete and organized  
**Next**: Read VULNERABILITY_FINDINGS.md or follow guides/DEMO_SETUP.md
