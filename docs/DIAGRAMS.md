# Protocol Diagrams — `sonaraim-protocol`

> Mermaid sequence, state, and class diagrams for the Sonaraim protocol layer.

---

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

---

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

---

## 3. MLS Group Epoch Ratcheting Sequence

```mermaid
sequenceDiagram
    autonumber
    participant G as Group Creator (Alice)
    participant B as Bob (Invitee)
    participant S as MlsGroupSession State
    participant R as ReplayWindow

    G->>S: create_group(group_id, alice_did)
    S-->>G: Epoch 0 initialized, transcript hash T0
    G->>S: add_member(bob_did, bob_key_package)
    S->>S: advance_epoch() -> Epoch 1
    S->>S: Ratchet HKDF secret, purge Epoch 0 secrets
    S-->>B: Welcome frame with Epoch 1 state
    B->>R: record_envelope(env_id, epoch=1)
    R-->>B: Accepted (unique envelope, valid epoch)
    B->>R: record_envelope(env_id, epoch=1)
    R-->>B: Error (DuplicateEnvelope)
```

---

## 4. Sealed Sender Envelope Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Draft: Sender generates payload
    Draft --> Sealed: HPKE seal with recipient ephemeral X25519
    Sealed --> InTransit: Dispatched to relay mailbox_id
    InTransit --> Queued: Offline recipient (TTL active)
    InTransit --> Delivered: Recipient connects & fetches
    Queued --> Delivered: Drain active queue
    Queued --> Expired: TTL exceeded (purged by relay)
    Delivered --> Verified: Anti-replay check & AEAD unseal
    Verified --> [*]
    Expired --> [*]
```

---

## 5. Private Set Intersection (PSI) Protocol

```mermaid
sequenceDiagram
    autonumber
    participant App as sonaraim-app Client
    participant Node as sonaraim-node (PSI Engine)

    App->>App: Normalize contacts to E.164
    App->>App: Blind phone numbers with random secret r
    App->>Node: POST /v1/contacts/psi (blinded_tokens)
    Node->>Node: Evaluate blinded tokens against registered phone index
    Node-->>App: Matching blind evaluation receipts
    App->>App: Unblind receipts with r^-1
    App->>App: Intersect with local contact list -> Discovered DIDs
```
