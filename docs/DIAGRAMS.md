# Protocol Diagrams — sonaraim-protocol

> Mermaid sequence, state, and class diagrams for the Sonaraim protocol layer.

## 1. Sealed Sender Delivery & Card Verification Sequence

```mermaid
sequenceDiagram
    autonumber
    participant M as Merchant B2B Gateway
    participant P as sonaraim-protocol Validator
    participant R as Blinded Relay Node
    participant C as Recipient Client

    M->>P: validate_card(SonaraimCard)
    P-->>M: Ok(()) (DID + Ed25519 + Safe Components)
    M->>M: Encrypt card inside MLS Group Frame
    M->>P: validate_envelope(SealedEnvelope)
    P-->>M: Ok(()) (32B X25519 + Mailbox + TTL)
    M->>R: Dispatch SealedEnvelope(mailbox_id)
    R->>C: Deliver SealedEnvelope to anonymous mailbox
    C->>C: Unseal outer HPKE layer + Decrypt MLS ciphertext
    C->>P: validate_card(SonaraimCard)
    P-->>C: Ok(()) -> Render Native UI Components
```

## 2. Card Validation State Machine

```mermaid
stateDiagram-v2
    [*] --> CheckMetadata
    CheckMetadata --> CheckComponents: card_id & title valid
    CheckMetadata --> Rejected: empty or HTML tags detected
    CheckComponents --> CheckSignature: 1..=16 valid components & safe HTTPS/sonaraim URIs
    CheckComponents --> Rejected: raw HTML / script / unsafe URI scheme
    CheckSignature --> Accepted: did:web or did:sonaraim + Ed25519 + 64B hex sig
    CheckSignature --> Rejected: invalid DID, algorithm, or signature hex
    Accepted --> [*]
    Rejected --> [*]
```
