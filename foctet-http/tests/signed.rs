use foctet_core::{IdentityKeyPair, PeerIdentity};
use foctet_http::{
    http::{Request, Response},
    *,
};
use x25519_dalek::{PublicKey, StaticSecret};
#[tokio::test]
async fn signed_http_binds_writer_context_response_and_replay() {
    let secret = StaticSecret::from([8; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    let writer = IdentityKeyPair::from_secret_key_bytes([9; 32]);
    let pin = PeerIdentity::new(writer.public_key());
    let sealer = HttpSealer::new(HttpSealOptions::new(public, b"kid")).with_writer(writer.clone());
    let opener = HttpOpener::new(HttpOpenOptions::new(secret.to_bytes())).require_writer(pin);
    let store = InMemoryReplayStore::new();
    let binding = ContextBinding::default();
    let carrier = ContextCarrier::generate(100, 60);
    let id = carrier.message_id;
    let request = sealer
        .seal_request_with_context(
            Request::builder()
                .method("POST")
                .uri("/vault")
                .body(b"secret".to_vec())
                .unwrap(),
            carrier,
            binding,
        )
        .unwrap();
    let mut missing = request.clone();
    missing.headers_mut().remove(WRITER_SIGNATURE_HEADER);
    assert!(
        opener
            .open_request_with_context(missing, &store, 101, 5, binding)
            .is_err()
    );
    assert!(store.is_empty());
    let mut tampered = request.clone();
    tampered.body_mut()[20] ^= 1;
    assert!(
        opener
            .open_request_with_async_store(tampered, &store, 101, 5, binding)
            .await
            .is_err()
    );
    assert!(store.is_empty());
    assert_eq!(
        opener
            .open_request_with_context(request.clone(), &store, 101, 5, binding)
            .unwrap()
            .body(),
        b"secret"
    );
    assert!(matches!(
        opener
            .open_request_with_async_store(request, &store, 101, 5, binding)
            .await,
        Err(HttpError::Replayed)
    ));
    let response = sealer
        .seal_response_with_context(
            Response::new(b"answer".to_vec()),
            ContextCarrier::generate(101, 60).answering(id),
        )
        .unwrap();
    assert_eq!(
        opener
            .open_response_with_context(response, id, 102, 5)
            .unwrap()
            .body(),
        b"answer"
    );
    assert!(sealer.seal_body(b"unsigned").is_err());
    assert!(opener.open_body(b"unsigned").is_err());
}
#[test]
fn signed_http_stream_cannot_downgrade_or_populate_replay_before_writer_check() {
    let secret = StaticSecret::from([8; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    let writer = IdentityKeyPair::from_secret_key_bytes([9; 32]);
    let pin = PeerIdentity::new(writer.public_key());
    let limits = BodyEnvelopeLimits::default();
    let binding = ContextBinding::default();
    let (mut parts, ()) = Request::builder()
        .uri("/stream")
        .body(())
        .unwrap()
        .into_parts();
    let carrier = ContextCarrier::generate(100, 60);
    let (mut sealer, header) =
        HttpStreamSealer::for_request(&parts, &carrier, binding, public, b"kid", &limits).unwrap();
    carrier.apply_to_headers(&mut parts.headers).unwrap();
    let (chunk, sig) = sealer.seal_signed_chunk(b"data", true, &writer).unwrap();
    let store = InMemoryReplayStore::new();
    let mut opener = HttpStreamOpener::for_request(
        &parts,
        secret.to_bytes(),
        &header,
        &store,
        101,
        5,
        binding,
        &limits,
    )
    .unwrap()
    .require_writer(pin);
    assert!(opener.open_signed_chunk(&chunk, [0; 64]).is_err());
    assert!(store.is_empty());
    let mut opener = HttpStreamOpener::for_request(
        &parts,
        secret.to_bytes(),
        &header,
        &store,
        101,
        5,
        binding,
        &limits,
    )
    .unwrap()
    .require_writer(pin);
    assert_eq!(
        opener.open_signed_chunk(&chunk, sig).unwrap().plaintext,
        b"data"
    );
    assert!(opener.is_finished());
}

#[test]
fn missing_writer_pin_is_terminal_for_stream_opener() {
    let secret = StaticSecret::from([8; 32]);
    let public = PublicKey::from(&secret).to_bytes();
    let writer = IdentityKeyPair::from_secret_key_bytes([9; 32]);
    let limits = BodyEnvelopeLimits::default();
    let (mut parts, ()) = Request::new(()).into_parts();
    let carrier = ContextCarrier::generate(100, 60);
    let binding = ContextBinding::default();
    let (mut sealer, header) =
        HttpStreamSealer::for_request(&parts, &carrier, binding, public, b"kid", &limits).unwrap();
    carrier.apply_to_headers(&mut parts.headers).unwrap();
    let (chunk, signature) = sealer.seal_signed_chunk(b"secret", true, &writer).unwrap();
    let store = InMemoryReplayStore::new();
    let mut opener = HttpStreamOpener::for_request(
        &parts,
        secret.to_bytes(),
        &header,
        &store,
        101,
        5,
        binding,
        &limits,
    )
    .unwrap();
    assert!(opener.open_signed_chunk(&chunk, signature).is_err());
    assert!(matches!(
        opener.open_chunk(&chunk),
        Err(HttpError::StreamIncomplete)
    ));
    assert!(!opener.is_finished());
    assert!(store.is_empty());
}

#[test]
fn body_replacement_clears_old_framing_and_rejects_self_binding() {
    let secret = StaticSecret::from([8; 32]);
    let writer = IdentityKeyPair::from_secret_key_bytes([9; 32]);
    let pin = PeerIdentity::new(writer.public_key());
    let sealer = HttpSealer::new(HttpSealOptions::new(
        PublicKey::from(&secret).to_bytes(),
        b"kid",
    ))
    .with_writer(writer);
    let opener = HttpOpener::new(HttpOpenOptions::new(secret.to_bytes())).require_writer(pin);
    let request = Request::builder()
        .header("content-length", "3")
        .header("transfer-encoding", "chunked")
        .body(b"abc".to_vec())
        .unwrap();
    for headers in [
        &["X-Foctet-Writer-Signature"][..],
        &["content-length"][..],
        &["content-type"][..],
    ] {
        assert!(
            sealer
                .seal_request_with_context(
                    request.clone(),
                    ContextCarrier::generate(100, 60),
                    ContextBinding::default().with_bound_headers(headers)
                )
                .is_err()
        );
    }
    let mut sealed = sealer
        .seal_request_with_context(
            request,
            ContextCarrier::generate(100, 60),
            ContextBinding::default(),
        )
        .unwrap();
    assert!(!sealed.headers().contains_key("content-length"));
    assert!(!sealed.headers().contains_key("transfer-encoding"));
    let length = sealed.body().len().to_string();
    sealed
        .headers_mut()
        .insert("content-length", length.parse().unwrap());
    let opened = opener
        .open_request_with_context(
            sealed,
            &InMemoryReplayStore::new(),
            101,
            5,
            ContextBinding::default(),
        )
        .unwrap();
    assert!(!opened.headers().contains_key("content-length"));
    assert_eq!(opened.body(), b"abc");
    let id = [5; 16];
    let response = Response::builder()
        .header("content-length", "3")
        .body(b"abc".to_vec())
        .unwrap();
    let mut sealed = sealer
        .seal_response_with_context(response, ContextCarrier::generate(100, 60).answering(id))
        .unwrap();
    assert!(!sealed.headers().contains_key("content-length"));
    let length = sealed.body().len().to_string();
    sealed
        .headers_mut()
        .insert("content-length", length.parse().unwrap());
    let opened = opener
        .open_response_with_context(sealed, id, 101, 5)
        .unwrap();
    assert!(!opened.headers().contains_key("content-length"));
    assert_eq!(opened.body(), b"abc");
}
