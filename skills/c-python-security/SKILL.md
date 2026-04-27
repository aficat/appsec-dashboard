---
name: c-python-security
description: "Use this skill when reviewing mixed C and Python codebases for common vulnerability classes, secure patterns, and exploitability."
license: MIT
metadata:
  author: absoluteappsec
  version: "1.0"
---

# C + Python Security Analysis Skill

## Overview
This skill provides reusable guidance for security reviews of mixed C and Python repositories (native components + Python services/tools).

## Instructions

When analyzing a codebase that includes both C and Python, prioritize issues by exploitability and impact. Focus on trust boundaries (file/network input, IPC, environment variables, config, database, and serialization).

### 1) C / Native Code Risks (Memory Safety & Low-Level Bugs)

Look for:
- **Memory corruption**: stack/heap buffer overflows, out-of-bounds read/write, use-after-free, double-free.
- **Integer issues**: signed/unsigned confusion, overflow/underflow when computing lengths/offsets/allocation sizes.
- **Format string bugs**: user-controlled strings passed as format specifiers (e.g. `printf(user)`).
- **Unsafe string APIs**: `strcpy`, `strcat`, `sprintf`, `gets`, unchecked `memcpy`/`memmove` sizes.
- **Untrusted parsing**: custom parsers for network/file protocols (length-prefixed fields, delimiters, base64/hex decoding).
- **Path handling**: directory traversal, symlink attacks, TOCTOU (`stat` then `open`), unsafe temp files.
- **Cryptography misuse**: custom crypto, weak randomness, missing authentication/integrity (MAC/AEAD), key material in logs.
- **Command execution**: `system`, `popen`, `exec*` with user-influenced arguments or PATH searching.

Good review questions:
- What input is attacker-controlled? How is it length-checked and validated?
- Is any pointer arithmetic derived from untrusted lengths?
- Are allocations checked for failure and size correctness?
- Are error paths safe (no leaks, no use-after-free, no partial initialization hazards)?

### 2) Python Risks (Injection, Deserialization, SSRF, Supply Chain)

Look for:
- **Command injection**: `subprocess.*` with `shell=True`, string concatenation of args, or unsafe PATH usage.
- **Unsafe deserialization**: `pickle`, `dill`, `marshal`, `yaml.load` (without safe loader), `eval`/`exec`.
- **SSRF**: server-side HTTP requests that accept user-controlled URLs/hosts (e.g. `requests.get(user_url)`).
- **Path traversal / file write**: joining user input into filesystem paths; missing normalization / base-dir enforcement.
- **Template/code injection**: Jinja2 with untrusted templates, dynamic imports, `getattr` on untrusted values.
- **TLS issues**: `verify=False`, disabled hostname verification, custom certificate handling.
- **Secrets exposure**: printing tokens/keys, `.env` in repo, debug logs containing credentials.

Good review questions:
- Where does untrusted input enter (CLI args, HTTP handlers, env vars, config files, RPC)?
- Are outbound network calls constrained (allowlist, timeouts, redirects disabled, DNS rebinding considerations)?
- Are subprocess calls fully argument-vectorized with safe quoting (no shell)?

### 3) Cross-Cutting Issues (AuthZ, Storage, Logging, Config)

Look for:
- **Authorization gaps / IDOR**: operations on resources without ownership/ACL checks.
- **Insecure defaults**: debug flags, overly permissive bind addresses, weak permissions on files/dirs.
- **Error handling**: verbose errors leaking paths, stack traces, or secrets.
- **Logging**: logs that contain plaintext secrets or sensitive user content.
- **Dependency hygiene**: pinned versions, known-vuln dependencies, unverified downloads.

### Common Vulnerable Patterns (Illustrative)

```c
// BAD: format string
printf(user_input);

// GOOD: fixed format
printf("%s", user_input);

// BAD: unchecked copy
strcpy(dst, src);
```

```python
# BAD: shell injection risk
subprocess.run(f"tar -xf {user_path}", shell=True)

# GOOD: argv-based call
subprocess.run(["tar", "-xf", user_path], check=True)

# BAD: unsafe deserialization
obj = pickle.loads(user_bytes)
```

## Output Format

For each finding, provide:
- **Evidence**: exact file path(s), function name(s), and the relevant code snippet
- **Attack scenario**: how an attacker controls the input and what they gain
- **Impact**: data exposure, RCE, privilege escalation, integrity loss, availability impact
- **Remediation**: concrete fix with safer APIs/patterns (C and/or Python)
