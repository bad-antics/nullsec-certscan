# NullSec CertScan

**TLS Certificate Scanner**

A comprehensive TLS certificate analysis tool written in D, demonstrating systems programming with high-level features for security-focused certificate inspection.

![D](https://img.shields.io/badge/D-B03931?style=for-the-badge&logo=d&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🎯 Overview

NullSec CertScan analyzes TLS certificates for security weaknesses, expired certs, weak cryptography, and configuration issues. It provides actionable findings with MITRE ATT&CK technique mapping.

## ✨ Features

- **Expiration Detection** - Identify expired and soon-to-expire certificates
- **Key Strength Analysis** - Detect weak RSA/EC key sizes
- **Signature Algorithm Check** - Flag MD5/SHA1 signatures
- **Self-Signed Detection** - Identify untrusted certificates
- **Wildcard Analysis** - Review wildcard certificate usage
- **Security Scoring** - 0-100 score per certificate

## 🔍 Security Checks

| Check | Severity | MITRE |
|-------|----------|-------|
| Expired Certificate | Critical | T1588.004 |
| MD5 Signature | Critical | T1557 |
| RSA < 2048 bits | Critical | T1557 |
| SHA-1 Signature | High | T1557 |
| Expiring < 30 days | High | - |
| Self-Signed | Medium | T1587.003 |
| Wildcard Certificate | Low | - |

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-certscan
cd nullsec-certscan

# Compile with DMD
dmd -O -release certscan.d -of=certscan

# Or with LDC
ldc2 -O2 certscan.d -of=certscan

# Run directly
rdmd certscan.d
```

## 🚀 Usage

```bash
# Scan a host
./certscan example.com:443

# Show certificate chain
./certscan -c google.com

# Analyze certificate file
./certscan cert.pem

# JSON output
./certscan -j host.com

# Run demo mode
./certscan
```

## 💻 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║            NullSec CertScan - TLS Certificate Scanner            ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Analyzing sample certificates...

  Certificate: CN=expired.example.com
    Issuer:    CN=Demo CA
    Serial:    ABC123
    Valid:     2023-Jan-01 to 2024-Jan-01
    Key:       RSA 2048-bit
    Signature: sha256WithRSA
    SANs:      expired.example.com, www.expired.example.com
    Score:     60/100

    Findings:
      [CRITICAL] Expired Certificate
        Certificate expired 180 days ago
        → Replace with valid certificate immediately
        MITRE: T1588.004

  Certificate: CN=weak.example.com
    Issuer:    CN=Demo CA
    Serial:    DEF456
    Valid:     2024-Jan-01 to 2026-Jan-01
    Key:       RSA 1024-bit
    Signature: sha1WithRSA
    SANs:      weak.example.com
    Score:     35/100

    Findings:
      [CRITICAL] Weak Key Size
        RSA key is only 1024 bits (minimum 2048 recommended)
        → Generate new certificate with 2048+ bit RSA key
        MITRE: T1557
      [HIGH] Weak Signature
        Certificate uses SHA-1 signature (deprecated)
        → Replace certificate with SHA-256 signed certificate
        MITRE: T1557

═══════════════════════════════════════════

  Summary:
    Certificates Analyzed: 5
    Critical:              3
    High:                  1
    Medium:                1
    Low:                   2
    Average Score:         66/100
```

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Certificate Input                       │
│        TLS Connection | PEM File | DER File              │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│              Certificate Parser                           │
│  Subject | Issuer | Validity | Key | Signature | SANs    │
└──────────────────────────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
    ┌──────────┐   ┌──────────┐   ┌──────────┐
    │Expiration│   │Key Check │   │Signature │
    │  Check   │   │RSA/EC    │   │ Check    │
    └──────────┘   └──────────┘   └──────────┘
          │               │               │
          └───────────────┼───────────────┘
                          ▼
                  ┌──────────────┐
                  │CertAnalysis  │
                  │Score + Finds │
                  └──────────────┘
```

## 🔧 D Language Features

- **Enums with Methods** - `Severity`, `KeyType`, `SignatureAlgo`
- **Structs** - `Certificate`, `Finding`, `CertAnalysis`
- **Ranges & Algorithms** - `map`, `filter`, `sum`
- **String Mixins** - Compile-time code generation
- **Final Switch** - Exhaustive enum matching
- **UFCS** - Uniform Function Call Syntax
- **Built-in Unit Tests** - `unittest` blocks

## 📊 Certificate Structure

```d
struct Certificate {
    string subject;
    string issuer;
    string serialNumber;
    Date notBefore;
    Date notAfter;
    KeyType keyType;
    int keySize;
    SignatureAlgo signatureAlgo;
    string[] subjectAltNames;
    bool isSelfSigned;
    bool isCA;
    int chainPosition;
}
```

## 🛡️ Security Use Cases

- **Certificate Audit** - Scan all certificates in environment
- **Compliance Check** - Verify crypto standards compliance
- **Vulnerability Assessment** - Find weak certificate configs
- **Monitoring** - Alert on expiring certificates
- **Incident Response** - Identify rogue certificates

## ⚠️ Legal Disclaimer

This tool is intended for:
- ✅ Authorized security assessments
- ✅ Certificate management
- ✅ Compliance auditing
- ✅ Educational purposes

**Only scan systems you're authorized to test.**

## 🔗 Links

- **Portal**: [bad-antics.github.io](https://bad-antics.github.io)
- **Discord**: [discord.gg/killers](https://discord.gg/killers)
- **GitHub**: [github.com/bad-antics](https://github.com/bad-antics)

## 📄 License

MIT License - See LICENSE file for details.

## 🏷️ Version History

- **v1.0.0** - Initial release with certificate analysis and scoring

---

*Part of the NullSec Security Toolkit*
