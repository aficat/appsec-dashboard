---
name: owasp-top10
description: "Use this skill when analyzing code for OWASP Top 10 vulnerabilities. Provides structured guidance for identifying common web application security risks."
license: MIT
metadata:
  author: absoluteappsec
  version: "1.0"
---

# OWASP Top 10 Analysis Skill

## Overview
This skill provides structured guidance for analyzing code against the OWASP Top 10 2021 vulnerability categories.

## Instructions

When performing security analysis, check for these vulnerability categories:

### A01:2021 - Broken Access Control
- Missing authorization checks on sensitive operations
- IDOR (Insecure Direct Object References)
- Path traversal vulnerabilities
- Missing function-level access control

### A02:2021 - Cryptographic Failures
- Weak encryption algorithms (MD5, SHA1 for passwords)
- Hardcoded secrets or API keys
- Sensitive data transmitted in cleartext
- Missing encryption for sensitive data at rest

### A03:2021 - Injection
- SQL Injection (raw queries, string concatenation)
- Command Injection (os.system, subprocess with shell=True)
- Template Injection
- LDAP Injection
- XPath Injection

### A04:2021 - Insecure Design
- Missing rate limiting
- Lack of input validation
- Trust boundary violations
- Missing security controls in business logic

### A05:2021 - Security Misconfiguration
- DEBUG=True in production
- Default credentials
- Verbose error messages exposing internals
- Unnecessary features enabled

### A06:2021 - Vulnerable Components
- Outdated dependencies
- Known vulnerable libraries
- Unpatched frameworks

### A07:2021 - Authentication Failures
- Weak password policies
- Missing brute-force protection
- Session fixation
- Credential stuffing vulnerabilities

### A08:2021 - Data Integrity Failures
- Insecure deserialization
- Missing integrity checks
- Unsigned updates

### A09:2021 - Security Logging Failures
- Missing audit logs for sensitive operations
- Logging sensitive data (passwords, tokens)
- Insufficient monitoring

### A10:2021 - SSRF
- User-controlled URLs in server-side requests
- Missing URL validation
- Internal network exposure

## Output Format

For each finding, provide:
- Vulnerability category (A01-A10)
- File and line number
- Code snippet demonstrating the issue
- Risk rating (Critical/High/Medium/Low)
- Remediation recommendation
