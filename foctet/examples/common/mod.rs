//! Both loopback endpoints run in this process, so they can exchange pins and
//! handshake messages directly. A networked application provisions pins
//! independently and sends the hello messages over its reliable transport.
use foctet::core::{
    CoreError, IdentityKeyPair, PeerIdentity, ProductionSessionAuth, RekeyThresholds, Session,
};

pub fn session_pair() -> Result<(Session, Session), CoreError> {
    let client = IdentityKeyPair::generate();
    let server = IdentityKeyPair::generate();
    let client_pin = PeerIdentity::new(client.public_key());
    let server_pin = PeerIdentity::new(server.public_key());
    let (mut initiator, hello) = Session::new_production_initiator(
        RekeyThresholds::default(),
        ProductionSessionAuth::pinned_identity(client, server_pin),
    );
    let mut responder = Session::new_production_responder(
        RekeyThresholds::default(),
        ProductionSessionAuth::pinned_identity(server, client_pin),
    );
    let reply = responder
        .handle_control(&hello)?
        .ok_or(CoreError::UnexpectedControlMessage)?;
    initiator.handle_control(&reply)?;
    Ok((initiator, responder))
}
