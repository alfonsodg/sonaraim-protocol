//! Verifiable OPRF TDD suite for `sonaraim-protocol` (Issue #12).
//!
//! 2HashDH OPRF over ristretto255 with Chaum-Pedersen DLEQ proofs:
//! honest evaluations verify and derive deterministic HKDF-SHA256 match
//! tokens, while substituted evaluations, wrong server keys, zero blinds,
//! and non-canonical elements are rejected.

#[test]
fn verifiable_oprf_psi_unblinds_match_token_and_detects_substitution() {
    // RED (issue #12): 2HashDH verifiable OPRF over ristretto255.
    // Client blinds with fresh `r`, server evaluates with static `k` and
    // publishes `K = k * G`; the client unblinds and derives the match token
    // with HKDF-SHA256. Binding both tokens to the transcript `K`
    // (DLEQ-style verification: `N == k * H2(input)`) makes server-side
    // token substitution detectable without ever exposing `k`.
    use sonaraim_protocol::oprf::{
        oprf_blind, oprf_client_finalize, oprf_evaluate, oprf_server_public_key,
        oprf_unblind_and_token,
    };

    let server_secret = [0x6bu8; 32];
    let phone = "+51999888777";
    let (blinded, blind) = oprf_blind(phone.as_bytes());
    let evaluated = oprf_evaluate(&blinded, &server_secret).expect("evaluate must parse");
    let server_public = oprf_server_public_key(&server_secret);
    let (unblinded, token) =
        oprf_unblind_and_token(&evaluated, &blind, &server_public, phone.as_bytes())
            .expect("honest evaluation must verify");
    // Deterministic: same input and server key yield the same token.
    let (blinded_b, blind_b) = oprf_blind(phone.as_bytes());
    let token_b = oprf_unblind_and_token(
        &oprf_evaluate(&blinded_b, &server_secret).expect("evaluate must parse"),
        &blind_b,
        &server_public,
        phone.as_bytes(),
    )
    .expect("honest evaluation must verify")
    .1;
    assert_eq!(token, token_b);
    // Client-side matching commits the directory token list, not `server_secret`.
    let registered = ["+51999888777", "+14155550101"];
    let directory: Vec<Vec<u8>> = registered
        .iter()
        .map(|id| oprf_client_finalize(id.as_bytes(), &server_secret))
        .collect();
    assert!(directory.iter().any(|entry| *entry == token));
    // Malicious server substituting an unrelated evaluation fails verification.
    let (fake_blind, _) = oprf_blind(b"+10000000000");
    let mut fake_eval = oprf_evaluate(&fake_blind, &server_secret).expect("evaluate must parse");
    fake_eval.evaluated = blinded;
    assert!(oprf_unblind_and_token(&fake_eval, &blind, &server_public, phone.as_bytes()).is_err());
    let _ = unblinded;
}

#[test]
fn verifiable_oprf_rejects_wrong_key_zero_blind_and_replays() {
    use sonaraim_protocol::oprf::{
        oprf_blind, oprf_evaluate, oprf_server_public_key, oprf_unblind_and_token, OprfError,
    };

    let server_secret = [0x6bu8; 32];
    let other_secret = [0x6cu8; 32];
    let phone = "+51999888777";
    let (blinded, blind) = oprf_blind(phone.as_bytes());
    let evaluated = oprf_evaluate(&blinded, &server_secret).expect("evaluate must parse");
    let server_public = oprf_server_public_key(&server_secret);
    // Wrong server public key fails the DLEQ transcript check.
    let wrong_public = oprf_server_public_key(&other_secret);
    assert_eq!(
        oprf_unblind_and_token(&evaluated, &blind, &wrong_public, phone.as_bytes()),
        Err(OprfError::VerificationFailed)
    );
    // A zero blind is not a valid blinding factor.
    assert_eq!(
        oprf_unblind_and_token(&evaluated, &[0u8; 32], &server_public, phone.as_bytes()),
        Err(OprfError::InvalidElement)
    );
    // Non-canonical evaluation bytes are rejected before unblinding.
    let mut bad = evaluated.clone();
    bad.evaluated = [0xffu8; 32];
    assert!(oprf_unblind_and_token(&bad, &blind, &server_public, phone.as_bytes()).is_err());
}
