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

- **Sonaraim Group Ratchet (MLS-inspired, not OpenMLS/RFC 9420 — OpenMLS explicitly deferred)**: Symmetric group ratcheting with HKDF-SHA256 rotation, forward secrecy via epoch-key zeroization, and post-compromise recovery ratchets. Relay nodes never have access to group ratchet keys.
- **Sealed Sender Outer Envelope**: Outer routing metadata contains only an anonymous `mailbox_id` and a fresh random ephemeral 32-byte X25519 public key per envelope (ephemeral-static ECDH with HKDF-SHA256, not HPKE). Relay nodes cannot identify the sender or correlate traffic without compromising recipient private keys.
- **Authenticated Encryption (AEAD)**: All envelope payloads use ChaCha20-Poly1305 (IETF, `chacha20poly1305` crate, `nonce || ciphertext || 16-byte tag`) AEAD with mandatory authentication tags.

### 3.2 Key Transparency & Identity Attestation

Roadmap (not yet implemented — do not build on these as present features):

- **Key Transparency Merkle log**: Planned append-only registration of public identity keys (`did:web` and `did:sonaraim`) with Merkle inclusion proofs.
- **Equivocation Detection**: Planned gossip of Signed Tree Heads (STH) to detect split-view or key-substitution attacks.
- **Implemented today**: Real Ed25519 merchant signatures (`ed25519-dalek`, RFC 8032) bound to verified DID documents.

### 3.3 Zero-HTML & Declarative Card Safety

- **Strict Schema Enforcement**: Sonaraim Cards strictly reject raw HTML tags (`<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`).
- **URI Scheme Sanitization**: Card action and media URLs must strictly use `https://` or `sonaraim://` schemes. Unsafe schemes (`javascript:`, `data:`, `file:`, `vbscript:`) are rejected at the protocol boundary.
- **No Remote Code Execution**: Cards are purely declarative data structures rendered exclusively by native platform UI widgets.

### 3.4 Contact Discovery (Private Set Intersection)

- **Blinded Hashes**: Contact discovery uses an honest DH-blinded match (`psi.rs`): the client blinds with a per-session salt, the server returns keyed tokens plus directory commitments, and matching runs entirely on the client — `server_secret` never leaves the server. Verifiable OPRF security against a malicious server is deferred follow-up work.

---

## 4. Out-of-Scope Vulnerabilities

The following are outside the threat model of `sonaraim-protocol`:

- Physical or root compromise of the user's host operating system or device hardware.
- Denial of service attacks against local testing binaries without network amplification.
- Social engineering or phishing attacks targeting out-of-band communication channels.
