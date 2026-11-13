# Security Policy (`sonaraim-protocol`)

## 1. Supported Versions

Security updates and vulnerability patches are actively provided for the following releases:

| Version | Supported | Security Policy |
| :--- | :--- | :--- |
| `develop` | :white_check_mark: Yes | Bleeding edge; security fixes land here first |
| `0.1.x` | :white_check_mark: Yes | Current minor release series |
| `< 0.1.0` | :x: No | Unsupported pre-release builds |

---

## 2. Reporting a Vulnerability

The Sonaraim engineering team takes security vulnerabilities seriously. We ask that all security-sensitive issues be disclosed responsibly.

### Reporting Procedure

- **Email**: Send vulnerability reports directly to [security@sonaraim.org](mailto:security@sonaraim.org).
- **PGP Encryption**: For sensitive proof-of-concept exploits, encrypt your message using the Sonaraim Security PGP Key (fingerprint available at `https://sonaraim.org/security.asc`).
- **Required Information**:
  - Clear description of the vulnerability and its potential impact.
  - Affected components, functions, or wire format versions.
  - Minimal, reproducible test case or proof-of-concept.
  - Any proposed remediations or mitigation strategies.

### Response SLAs

- **Initial Acknowledgment**: Within **24 hours** of receipt.
- **Triage & Severity Assessment**: Within **48 hours** with an assigned tracking identifier.
- **Remediation & Patch Target**: Critical severity issues are patched within **7 days**; high severity issues within **14 days**.
- **Coordinated Disclosure**: We request a **90-day embargo** from the date of initial disclosure before public publication.

---

## 3. Cryptographic & Zero-Trust Scope

`sonaraim-protocol` provides the mathematical foundation and wire contracts for Sonaraim's end-to-end security model.

### 3.1 End-to-End Encryption Boundaries

- **Messaging Layer Security (MLS 1.0 / RFC 9420)**: Group ratcheting, forward secrecy, and post-compromise security. Relay nodes never have access to group ratchet trees or decryption keys.
- **Sealed Sender Outer Envelope**: Outer routing metadata contains only an anonymous `mailbox_id` and ephemeral 32-byte X25519 public key. Relay nodes cannot identify the sender or correlate traffic without compromising recipient private keys.
- **Authenticated Encryption (AEAD)**: All envelope payloads use ChaCha20-Poly1305 or AES-256-GCM AEAD ciphers with mandatory authentication tags.

### 3.2 Key Transparency & Identity Attestation

- **Merkle Tree Inclusion Proofs**: All public identity keys (`did:web` and `did:sonaraim`) are registered in an append-only Key Transparency Merkle log.
- **Equivocation Detection**: Federated nodes gossip Signed Tree Heads (STH) over UDP/QUIC to cryptographically detect split-view or key-substitution attacks.
- **Ed25519 Signatures**: Merchant identity and card action proofs must be signed with valid Ed25519 keys bound to verified DID documents.

### 3.3 Zero-HTML & Declarative Card Safety

- **Strict Schema Enforcement**: Sonaraim Cards strictly reject raw HTML tags (`<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`).
- **URI Scheme Sanitization**: Card action and media URLs must strictly use `https://` or `sonaraim://` schemes. Unsafe schemes (`javascript:`, `data:`, `file:`, `vbscript:`) are rejected at the protocol boundary.
- **No Remote Code Execution**: Cards are purely declarative data structures rendered exclusively by native platform UI widgets.

### 3.4 Contact Discovery (Private Set Intersection)

- **Blinded Hashes**: Contact discovery uses blinded cryptographic token hashing (`psi.rs`). The server evaluates intersection sets without observing unhashed phone numbers, address books, or social graphs.

---

## 4. Out-of-Scope Vulnerabilities

The following are outside the threat model of `sonaraim-protocol`:

- Physical or root compromise of the user's host operating system or device hardware.
- Denial of service attacks against local testing binaries without network amplification.
- Social engineering or phishing attacks targeting out-of-band communication channels.
