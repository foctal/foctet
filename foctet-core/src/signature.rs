//! Detached writer authentication for encrypted bodies, records, and archives.
//!
//! Encryption to a public key does not authenticate the writer. Sign the exact
//! ciphertext and a canonical application context, and verify with an externally
//! pinned writer identity BEFORE decrypting. Never trust a writer key supplied
//! by the storage server alongside the ciphertext. Include tenant, object ID,
//! expected version, and protocol purpose in the context. Sign a split archive's
//! manifest, which authenticates its parts, rather than an unordered part list.
//!
//! Signatures do not provide freshness, authorization, or confidentiality for
//! the signer identity. HTTP still needs protected context and replay checks.

use sha2::{Digest, Sha256};

use crate::{CoreError, HandshakeAuth, HandshakeSigner, PeerIdentity};

const DOMAIN: &[u8] = b"foctet ciphertext signature v1\0";

fn transcript(ciphertext: &[u8], context: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update((context.len() as u64).to_be_bytes());
    hash.update(context);
    hash.update((ciphertext.len() as u64).to_be_bytes());
    hash.update(ciphertext);
    hash.finalize().into()
}

/// Signs a domain-separated digest of the exact ciphertext and application context.
///
/// Store the detached 64-byte signature alongside the ciphertext. Context fields
/// must be unambiguously encoded and independently known to the verifier.
pub fn sign_ciphertext(
    ciphertext: &[u8],
    context: &[u8],
    signer: &dyn HandshakeSigner,
) -> [u8; 64] {
    signer.sign(&transcript(ciphertext, context))
}

/// Verifies the writer using an externally trusted identity, before decryption.
///
/// Rejects modified ciphertext/context, incorrect identities, and weak keys.
/// This is ordinary Ed25519 over a domain-separated SHA-256 digest, not Ed25519ph.
pub fn verify_ciphertext(
    ciphertext: &[u8],
    context: &[u8],
    signature: [u8; 64],
    writer: PeerIdentity,
) -> Result<(), CoreError> {
    HandshakeAuth {
        identity_public_key: writer.public_key,
        signature,
    }
    .verify(&transcript(ciphertext, context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKeyPair;

    #[test]
    fn writer_context_and_exact_ciphertext_are_required() {
        let writer = IdentityKeyPair::from_secret_key_bytes([42; 32]);
        let pin = PeerIdentity::new(writer.public_key());
        let signature = sign_ciphertext(b"sealed record", b"tenant/id/version", &writer);
        let encoded = signature
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            encoded,
            "6fcfecae3dbe4e1f21b7e66007bf4544f28925f977f4dddc2b0451861e920c1f8fcf0120e57db2bcfc45780f9882fd2d12ab31775248079a0f3b7f5dba62ef00"
        );
        verify_ciphertext(b"sealed record", b"tenant/id/version", signature, pin).unwrap();
        assert!(verify_ciphertext(b"replacement", b"tenant/id/version", signature, pin).is_err());
        assert!(verify_ciphertext(b"sealed record", b"tenant/id/old", signature, pin).is_err());
        let attacker = IdentityKeyPair::from_secret_key_bytes([43; 32]);
        let forged = sign_ciphertext(b"replacement", b"tenant/id/version", &attacker);
        assert!(verify_ciphertext(b"replacement", b"tenant/id/version", forged, pin).is_err());
        assert_ne!(transcript(b"bc", b"a"), transcript(b"c", b"ab"));
    }
}
