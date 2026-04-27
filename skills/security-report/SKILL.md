---
name: security-report
description: "Use this skill to generate structured, professional security assessment reports in JSON format."
license: MIT
metadata:
  author: absoluteappsec
  version: "1.0"
---

# Security Report Generation Skill

## Overview
This skill ensures consistent, professional output format for security findings.

## Instructions

Structure your final output as a JSON security report with the following format:

```json
{
    "summary": {
        "application": "Application name",
        "assessment_type": "Static Analysis",
        "total_findings": 5,
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 1
    },
    "findings": [
        {
            "id": "FINDING-001",
            "title": "SQL Injection in user search",
            "severity": "Critical",
            "category": "A03:2021 - Injection",
            "file": "views.py",
            "line": 45,
            "code_snippet": "cursor.execute('SELECT * FROM users WHERE name = ' + name)",
            "description": "User input is directly concatenated into SQL query without sanitization",
            "impact": "Attacker can extract, modify, or delete database contents. May lead to full database compromise.",
            "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = %s', [name])",
            "references": [
                "https://owasp.org/Top10/A03_2021-Injection/"
            ]
        }
    ],
    "recommendations": [
        "Implement input validation middleware for all user inputs",
        "Harden defaults and add defense-in-depth controls across entrypoints",
        "Add automated SAST scanning to CI/CD pipeline",
        "Conduct security training for development team"
    ]
}
```

## Severity Ratings

Use these criteria for consistent severity ratings:

### Critical
- Direct path to data breach or system compromise
- No authentication required to exploit
- Automated exploitation possible
- Examples: Unauthenticated SQLi, RCE, authentication bypass

### High
- Significant security impact
- Exploitable with some effort or requires authentication
- Examples: Authenticated SQLi, stored XSS, IDOR on sensitive data

### Medium
- Security weakness that requires specific conditions
- Limited impact or harder to exploit
- Examples: Reflected XSS, information disclosure, missing security headers

### Low
- Minor issue or defense-in-depth recommendation
- Best practice violations without direct exploit path
- Examples: Verbose errors, missing CSRF on non-sensitive forms

## Report Quality Guidelines

1. **Be specific** - Include exact file paths and line numbers
2. **Show evidence** - Include code snippets demonstrating the vulnerability
3. **Explain impact** - Describe what an attacker could achieve
4. **Provide remediation** - Give concrete fix recommendations with code examples
5. **Avoid false positives** - Only report confirmed vulnerabilities
6. **Prioritize** - Order findings by severity (Critical first)
