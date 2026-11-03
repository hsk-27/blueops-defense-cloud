# Security Policy

## 1. Supported Versions

We provide security updates and patches for the following versions of BlueOps:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| < 1.1.0 | :x:                |

---

## 2. Reporting a Vulnerability

The BlueOps team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose findings.

### Where to Report
**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities via:
- **Private Vulnerability Reporting:** Use GitHub's [Security Advisories](https://github.com/your-org/blueops/security/advisories/new) feature on this repository.
- **Email:** Send details to `security@blueops.lab` (or maintainers).

### What to Include
To help us triage and investigate the issue quickly, please include:
1. **Description:** Clear description of the vulnerability, including attack vector and potential impact.
2. **Component:** Affected service (Backend, Frontend, Response Agent, OpenSearch/Fluent Bit, Detection Rules).
3. **Reproduction Steps:** Step-by-step instructions or proof-of-concept (PoC) payload.
4. **Environment:** Operating system, Java/Node versions, and environment configurations.
5. **Mitigation:** Any proposed fix or remediation, if identified.

### Response Timeline
- **Initial Response:** Within 48 hours of report submission.
- **Triage & Assessment:** Within 5 business days.
- **Remediation & Advisory:** Coordinated release and CVE disclosure timeline agreed upon with the reporter.

---

## 3. Security Design Principles

BlueOps enforces strict architectural controls:
- **Role-Based Access Control:** Defense-in-depth via Spring Security HTTP filter chain rules and `@PreAuthorize` method annotations.
- **HMAC-SHA256 Response Authenticity:** Cryptographically signed response action payloads with 60-second anti-replay windows and nonce tracking.
- **Input Sanitization:** Response agent parameter validation preventing shell injection.
- **Audit Trails:** Immutable database logging of all administrative and operational state modifications.
