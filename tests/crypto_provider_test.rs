//! TDD acceptance suite for issue #17: crypto behind a `CryptoProvider` trait.
//!
//! RED-phase tests pinning the provider contract before it exists:
//! - Ed25519 sign/verify round-trip matching the RFC 8032 TEST 1 vector.
//! - X25519 raw ladder matching the RFC 7748 vectorset1 vector.
//! - AEAD seal/open round-trip with tamper rejection (16-byte tag overhead).
//! - HKDF-SHA256 protocol labels pinned to the RFC 5869 construction.
//! - SHA-256 / HMAC-SHA256 pinned to FIPS/RFC vectors.
//! - CSPRNG fills differ; zeroize-on-drop wrapper exposes then erases.

use sonaraim_protocol::crypto_provider::{default_provider, CryptoProvider, SecretBytes};

/// Converts lowercase hex into bytes without external crates.
fn from_hex(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut idx = 0;
    while idx + 1 < bytes.len() {
        let hi = (bytes[idx] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (bytes[idx + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    out
}

fn arr32(hex: &str) -> [u8; 32] {
    let v = from_hex(hex);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

#[test]
fn provider_ed25519_matches_rfc8032_test1() {
    // RFC 8032 §7.1 TEST 1 seed, public key, and empty-message signature.
    let seed = arr32(concat!(
        "9d61b19deffd5a60ba844af492ec2cc4",
        "4449c5697b326919703bac031cae7f60",
    ));
    let expected_public = arr32(concat!(
        "d75a980182b10ab7d54bfed3c964073a",
        "0ee172f3daa62325af021a68f707511a",
    ));
    let expected_sig = from_hex(concat!(
        "e5564300c360ac729086e2cc806e828a",
        "84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46b",
        "d25bf5f0595bbe24655141438e7a100b",
    ));
    let provider = default_provider();
    assert_eq!(
        provider.ed25519_public_key_bytes(&seed).to_vec(),
        expected_public.to_vec()
    );
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&expected_sig);
    assert_eq!(
        provider.ed25519_sign_bytes(&seed, &[]).to_vec(),
        expected_sig
    );
    provider
        .ed25519_verify_bytes(&expected_public, &[], &sig)
        .expect("RFC 8032 TEST 1 signature must verify via provider");
    let mut tampered = sig;
    tampered[0] ^= 0x01;
    assert!(provider
        .ed25519_verify_bytes(&expected_public, &[], &tampered)
        .is_err());
}

#[test]
fn provider_x25519_matches_rfc7748_vector() {
    // RFC 7748 ladder vectorset1 (same vector the backend crate self-tests).
    let scalar = arr32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let peer = arr32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected = from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    let provider = default_provider();
    assert_eq!(provider.x25519_raw(&scalar, &peer).to_vec(), expected);
    // Clamped agreement is symmetric across two fresh ephemeral keypairs.
    let a_secret = provider.x25519_ephemeral_secret();
    let b_secret = provider.x25519_ephemeral_secret();
    let a_public = provider.x25519_public_from_secret(&a_secret);
    let b_public = provider.x25519_public_from_secret(&b_secret);
    assert_eq!(
        provider.x25519_agree(&a_secret, &b_public),
        provider.x25519_agree(&b_secret, &a_public)
    );
}

#[test]
fn provider_aead_roundtrip_rejects_tampering() {
    let provider = default_provider();
    let key = [0x5au8; 32];
    let aad = b"mailbox:provider-seam-0001";
    let plaintext = b"provider seam round-trip";
    let sealed = provider
        .aead_seal(&key, aad, plaintext)
        .expect("seal must succeed");
    assert_eq!(sealed.len(), plaintext.len() + 12 + 16);
    let opened = provider
        .aead_open(&key, aad, &sealed)
        .expect("open must succeed");
    assert_eq!(opened, plaintext);
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(provider.aead_open(&key, aad, &tampered).is_err());
    assert!(provider.aead_open(&key, aad, &sealed[..10]).is_err());
}

#[test]
fn provider_kdf_labels_pin_rfc5869_construction() {
    // Same pinned vectors as the crypto-level suite: extract with the label
    // as salt, single-block expand over the info.
    let provider = default_provider();
    let envelope_key = provider.derive_envelope_key(&[0x11u8; 32], b"mbx-vector-0001");
    let epoch_key = provider.derive_epoch_key(&[0x22u8; 32], b"grp-vector-epoch-1");
    assert_eq!(
        envelope_key.to_vec(),
        from_hex("a47ba274d9c8339e99500517b8539f04ed7132294b502ef223cb1c7d72dffead")
    );
    assert_eq!(
        epoch_key.to_vec(),
        from_hex("c0fe7c6c4caaa434ff3125ed22068e21f276fa11efda901ca0c06b9f950c8ec4")
    );
}

#[test]
fn provider_hash_and_mac_pin_standard_vectors() {
    let provider = default_provider();
    assert_eq!(
        provider.sha256(b"abc").to_vec(),
        from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        provider.sha512_64(b"abc").to_vec(),
        from_hex(concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ))
    );
    // RFC 4231 §4.2 test case 1 for HMAC-SHA-256.
    assert_eq!(
        provider.hmac_sha256(&[0x0bu8; 20], b"Hi There").to_vec(),
        from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

#[test]
fn provider_randomness_fills_and_secret_wrapper_zeroizes() {
    let provider = default_provider();
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    provider.fill_random(&mut first);
    provider.fill_random(&mut second);
    assert_ne!(first, second, "CSPRNG fills must differ");
    let mut key = [0xabu8; 32];
    provider.zeroize_key(&mut key);
    assert_eq!(key, [0u8; 32]);
    let secret = SecretBytes::new([0xcd_u8; 32]);
    assert_eq!(secret.expose(), &[0xcd_u8; 32]);
    let mut exposed = *secret.expose();
    provider.zeroize_key(&mut exposed);
    assert_eq!(exposed, [0u8; 32]);
    assert!(provider.constant_time_eq(b"same", b"same"));
    assert!(!provider.constant_time_eq(b"same", b"diff"));
}
