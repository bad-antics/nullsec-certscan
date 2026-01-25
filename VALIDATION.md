# Certificate Scanning Guide

## Overview
SSL/TLS certificate scanning and validation techniques.

## Certificate Fields

### Subject Information
- Common Name (CN)
- Organization (O)
- Organizational Unit (OU)
- Country (C)

### Validity Period
- Not Before date
- Not After date
- Remaining lifetime
- Expiration alerts

### Extensions
- Subject Alternative Names
- Key Usage
- Extended Key Usage
- Basic Constraints

## Scanning Techniques

### Mass Scanning
- Port 443 enumeration
- SNI probing
- Certificate extraction
- Chain collection

### Analysis Points
- Self-signed detection
- Expired certificates
- Weak key sizes
- SHA-1 signatures

## Security Checks

### Chain Validation
- Root CA trust
- Intermediate verification
- OCSP status
- CRL checking

### Vulnerability Indicators
- Wildcard abuse
- Multi-domain certs
- Revocation status
- CT log presence

## Reporting
- JSON export
- CSV output
- Dashboard integration
- Alert automation

## Legal Notice
For authorized security scanning.
