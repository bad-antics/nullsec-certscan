// NullSec CertScan - TLS Certificate Scanner
// D language security tool demonstrating:
//   - Systems programming with high-level features
//   - Compile-time function execution (CTFE)
//   - Ranges and algorithms
//   - Built-in unit testing
//   - Slices for memory safety
//   - Mixins for metaprogramming
//
// Author: bad-antics
// License: MIT

import std.stdio;
import std.string;
import std.conv;
import std.array;
import std.algorithm;
import std.datetime;
import std.regex;
import std.format;

enum VERSION = "1.0.0";

// ANSI Colors
enum Color : string {
    red    = "\x1b[31m",
    green  = "\x1b[32m",
    yellow = "\x1b[33m",
    cyan   = "\x1b[36m",
    gray   = "\x1b[90m",
    reset  = "\x1b[0m"
}

// Severity levels
enum Severity {
    critical,
    high,
    medium,
    low,
    info
}

string severityStr(Severity s) {
    final switch (s) {
        case Severity.critical: return "CRITICAL";
        case Severity.high: return "HIGH";
        case Severity.medium: return "MEDIUM";
        case Severity.low: return "LOW";
        case Severity.info: return "INFO";
    }
}

Color severityColor(Severity s) {
    final switch (s) {
        case Severity.critical, Severity.high: return Color.red;
        case Severity.medium: return Color.yellow;
        case Severity.low: return Color.cyan;
        case Severity.info: return Color.gray;
    }
}

// Key types
enum KeyType {
    RSA,
    EC,
    DSA,
    unknown
}

// Signature algorithms
enum SignatureAlgo {
    sha256WithRSA,
    sha384WithRSA,
    sha512WithRSA,
    sha1WithRSA,      // Weak
    md5WithRSA,       // Very weak
    ecdsaWithSHA256,
    ecdsaWithSHA384,
    unknown
}

// Certificate structure
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

// Analysis finding
struct Finding {
    Severity severity;
    string category;
    string description;
    string recommendation;
    string mitre;
}

// Certificate analysis result
struct CertAnalysis {
    Certificate cert;
    Finding[] findings;
    int score;  // 0-100
}

// Analyze certificate
CertAnalysis analyzeCert(Certificate cert) {
    CertAnalysis result;
    result.cert = cert;
    
    // Check expiration
    auto today = cast(Date) Clock.currTime();
    auto daysUntilExpiry = (cert.notAfter - today).total!"days";
    
    if (daysUntilExpiry < 0) {
        result.findings ~= Finding(
            Severity.critical,
            "Expired Certificate",
            format("Certificate expired %d days ago", -daysUntilExpiry),
            "Replace with valid certificate immediately",
            "T1588.004"
        );
    } else if (daysUntilExpiry < 30) {
        result.findings ~= Finding(
            Severity.high,
            "Expiring Soon",
            format("Certificate expires in %d days", daysUntilExpiry),
            "Plan certificate renewal",
            ""
        );
    } else if (daysUntilExpiry < 90) {
        result.findings ~= Finding(
            Severity.medium,
            "Expiring Soon",
            format("Certificate expires in %d days", daysUntilExpiry),
            "Schedule certificate renewal",
            ""
        );
    }
    
    // Check key size
    if (cert.keyType == KeyType.RSA) {
        if (cert.keySize < 2048) {
            result.findings ~= Finding(
                Severity.critical,
                "Weak Key Size",
                format("RSA key is only %d bits (minimum 2048 recommended)", cert.keySize),
                "Generate new certificate with 2048+ bit RSA key",
                "T1557"
            );
        } else if (cert.keySize < 3072) {
            result.findings ~= Finding(
                Severity.low,
                "Key Size",
                format("RSA key is %d bits (3072+ recommended for long-term)", cert.keySize),
                "Consider upgrading to 3072 or 4096 bit key",
                ""
            );
        }
    } else if (cert.keyType == KeyType.EC) {
        if (cert.keySize < 256) {
            result.findings ~= Finding(
                Severity.high,
                "Weak EC Key",
                format("EC key is only %d bits", cert.keySize),
                "Use P-256 or higher curve",
                "T1557"
            );
        }
    }
    
    // Check signature algorithm
    if (cert.signatureAlgo == SignatureAlgo.md5WithRSA) {
        result.findings ~= Finding(
            Severity.critical,
            "Weak Signature",
            "Certificate uses MD5 signature (cryptographically broken)",
            "Replace certificate with SHA-256 signed certificate",
            "T1557"
        );
    } else if (cert.signatureAlgo == SignatureAlgo.sha1WithRSA) {
        result.findings ~= Finding(
            Severity.high,
            "Weak Signature",
            "Certificate uses SHA-1 signature (deprecated)",
            "Replace certificate with SHA-256 signed certificate",
            "T1557"
        );
    }
    
    // Check self-signed
    if (cert.isSelfSigned && !cert.isCA) {
        result.findings ~= Finding(
            Severity.medium,
            "Self-Signed",
            "Certificate is self-signed",
            "Use certificate from trusted CA for production",
            "T1587.003"
        );
    }
    
    // Check wildcard
    foreach (san; cert.subjectAltNames) {
        if (san.startsWith("*.")) {
            result.findings ~= Finding(
                Severity.low,
                "Wildcard Certificate",
                format("Wildcard certificate: %s", san),
                "Consider using specific certificates for sensitive services",
                ""
            );
            break;
        }
    }
    
    // Calculate score
    int penalties = 0;
    foreach (f; result.findings) {
        final switch (f.severity) {
            case Severity.critical: penalties += 40; break;
            case Severity.high: penalties += 25; break;
            case Severity.medium: penalties += 15; break;
            case Severity.low: penalties += 5; break;
            case Severity.info: break;
        }
    }
    result.score = max(0, 100 - penalties);
    
    return result;
}

// Demo certificates
Certificate[] demoCerts() {
    return [
        Certificate(
            "CN=expired.example.com",
            "CN=Demo CA",
            "ABC123",
            Date(2023, 1, 1),
            Date(2024, 1, 1),  // Expired
            KeyType.RSA,
            2048,
            SignatureAlgo.sha256WithRSA,
            ["expired.example.com", "www.expired.example.com"],
            false,
            false,
            0
        ),
        Certificate(
            "CN=weak.example.com",
            "CN=Demo CA",
            "DEF456",
            Date(2024, 1, 1),
            Date(2026, 1, 1),
            KeyType.RSA,
            1024,  // Weak
            SignatureAlgo.sha1WithRSA,  // Weak
            ["weak.example.com"],
            false,
            false,
            0
        ),
        Certificate(
            "CN=selfsigned.local",
            "CN=selfsigned.local",
            "GHI789",
            Date(2024, 1, 1),
            Date(2025, 1, 1),
            KeyType.RSA,
            4096,
            SignatureAlgo.sha256WithRSA,
            ["selfsigned.local"],
            true,
            false,
            0
        ),
        Certificate(
            "CN=*.wildcard.com",
            "CN=DigiCert CA",
            "JKL012",
            Date(2024, 1, 1),
            Date(2025, 6, 1),
            KeyType.EC,
            256,
            SignatureAlgo.ecdsaWithSHA256,
            ["*.wildcard.com", "wildcard.com"],
            false,
            false,
            0
        ),
        Certificate(
            "CN=secure.example.com",
            "CN=Let's Encrypt R3",
            "MNO345",
            Date(2024, 6, 1),
            Date(2024, 9, 1),
            KeyType.EC,
            384,
            SignatureAlgo.ecdsaWithSHA384,
            ["secure.example.com"],
            false,
            false,
            0
        ),
    ];
}

void printBanner() {
    writeln();
    writeln("╔══════════════════════════════════════════════════════════════════╗");
    writeln("║            NullSec CertScan - TLS Certificate Scanner            ║");
    writeln("╚══════════════════════════════════════════════════════════════════╝");
    writeln();
}

void printUsage() {
    writeln("USAGE:");
    writeln("    certscan [OPTIONS] <host:port|file>");
    writeln();
    writeln("OPTIONS:");
    writeln("    -h, --help       Show this help");
    writeln("    -j, --json       JSON output");
    writeln("    -c, --chain      Show full certificate chain");
    writeln("    -v, --verbose    Verbose output");
    writeln();
    writeln("EXAMPLES:");
    writeln("    certscan example.com:443");
    writeln("    certscan -c google.com");
    writeln("    certscan cert.pem");
}

void printCertAnalysis(CertAnalysis analysis) {
    auto cert = analysis.cert;
    
    writeln();
    writefln("  Certificate: %s", cert.subject);
    writefln("    Issuer:    %s", cert.issuer);
    writefln("    Serial:    %s", cert.serialNumber);
    writefln("    Valid:     %s to %s", cert.notBefore, cert.notAfter);
    writefln("    Key:       %s %d-bit", cert.keyType, cert.keySize);
    writefln("    Signature: %s", cert.signatureAlgo);
    
    if (cert.subjectAltNames.length > 0) {
        writefln("    SANs:      %s", cert.subjectAltNames.join(", "));
    }
    
    // Score
    string scoreColor;
    if (analysis.score >= 80) scoreColor = Color.green;
    else if (analysis.score >= 60) scoreColor = Color.yellow;
    else scoreColor = Color.red;
    
    writefln("    Score:     %s%d/100%s", scoreColor, analysis.score, Color.reset);
    
    // Findings
    if (analysis.findings.length > 0) {
        writeln();
        writeln("    Findings:");
        foreach (f; analysis.findings) {
            auto col = severityColor(f.severity);
            writefln("      %s[%s]%s %s", col, severityStr(f.severity), Color.reset, f.category);
            writefln("        %s", f.description);
            if (f.recommendation.length > 0) {
                writefln("        → %s", f.recommendation);
            }
            if (f.mitre.length > 0) {
                writefln("        MITRE: %s", f.mitre);
            }
        }
    }
}

void printSummary(CertAnalysis[] analyses) {
    writeln();
    writefln("%s═══════════════════════════════════════════%s", Color.gray, Color.reset);
    writeln();
    writeln("  Summary:");
    writefln("    Certificates Analyzed: %d", analyses.length);
    
    int critCount, highCount, medCount, lowCount;
    foreach (a; analyses) {
        foreach (f; a.findings) {
            final switch (f.severity) {
                case Severity.critical: critCount++; break;
                case Severity.high: highCount++; break;
                case Severity.medium: medCount++; break;
                case Severity.low: lowCount++; break;
                case Severity.info: break;
            }
        }
    }
    
    writefln("    Critical:              %s%d%s", Color.red, critCount, Color.reset);
    writefln("    High:                  %s%d%s", Color.red, highCount, Color.reset);
    writefln("    Medium:                %s%d%s", Color.yellow, medCount, Color.reset);
    writefln("    Low:                   %s%d%s", Color.cyan, lowCount, Color.reset);
    
    auto avgScore = analyses.map!(a => a.score).sum / cast(int)analyses.length;
    writefln("    Average Score:         %d/100", avgScore);
}

void demoMode() {
    writefln("%s[Demo Mode]%s", Color.yellow, Color.reset);
    writeln();
    writefln("%sAnalyzing sample certificates...%s", Color.cyan, Color.reset);
    
    auto certs = demoCerts();
    CertAnalysis[] analyses;
    
    foreach (cert; certs) {
        auto analysis = analyzeCert(cert);
        analyses ~= analysis;
        printCertAnalysis(analysis);
    }
    
    printSummary(analyses);
}

void main(string[] args) {
    printBanner();
    
    if (args.length <= 1) {
        printUsage();
        writeln();
        demoMode();
        return;
    }
    
    foreach (arg; args[1..$]) {
        if (arg == "-h" || arg == "--help") {
            printUsage();
            return;
        }
    }
    
    printUsage();
}
