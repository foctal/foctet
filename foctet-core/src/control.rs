use crate::CoreError;

const CONTROL_PREFIX: [u8; 4] = *b"FCTL";
const CONTROL_VERSION: u8 = 0;

/// Control message type discriminator for Draft v0 control payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlMessageKind {
    /// Initiator ephemeral key + session salt.
    ClientHello = 1,
    /// Responder ephemeral key.
    ServerHello = 2,
    /// Rekey notification carrying salt and key-id transition.
    Rekey = 3,
    /// Generic protocol error.
    Error = 255,
}

/// Control payload schema transported in encrypted control frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlMessage {
    /// First handshake message from initiator.
    ClientHello {
        /// Initiator ephemeral public key.
        eph_public: [u8; 32],
        /// Session salt used for initial key derivation.
        session_salt: [u8; 32],
        /// Transcript binding hash.
        transcript_binding: [u8; 32],
    },
    /// Handshake response from responder.
    ServerHello {
        /// Responder ephemeral public key.
        eph_public: [u8; 32],
        /// Transcript binding hash.
        transcript_binding: [u8; 32],
    },
    /// Rekey event message.
    Rekey {
        /// Previous key identifier.
        old_key_id: u8,
        /// New key identifier.
        new_key_id: u8,
        /// Salt value used for rekey derivation.
        rekey_salt: [u8; 32],
        /// Transcript binding hash.
        transcript_binding: [u8; 32],
    },
    /// Generic control error code.
    Error {
        /// Protocol-defined error code.
        code: u16,
    },
}

impl ControlMessage {
    /// Returns the message-kind discriminator.
    pub fn kind(&self) -> ControlMessageKind {
        match self {
            Self::ClientHello { .. } => ControlMessageKind::ClientHello,
            Self::ServerHello { .. } => ControlMessageKind::ServerHello,
            Self::Rekey { .. } => ControlMessageKind::Rekey,
            Self::Error { .. } => ControlMessageKind::Error,
        }
    }

    /// Encodes control payload into wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 1 + 128);
        out.extend_from_slice(&CONTROL_PREFIX);
        out.push(CONTROL_VERSION);
        out.push(self.kind() as u8);

        match self {
            Self::ClientHello {
                eph_public,
                session_salt,
                transcript_binding,
            } => {
                out.extend_from_slice(eph_public);
                out.extend_from_slice(session_salt);
                out.extend_from_slice(transcript_binding);
            }
            Self::ServerHello {
                eph_public,
                transcript_binding,
            } => {
                out.extend_from_slice(eph_public);
                out.extend_from_slice(transcript_binding);
            }
            Self::Rekey {
                old_key_id,
                new_key_id,
                rekey_salt,
                transcript_binding,
            } => {
                out.push(*old_key_id);
                out.push(*new_key_id);
                out.extend_from_slice(rekey_salt);
                out.extend_from_slice(transcript_binding);
            }
            Self::Error { code } => {
                out.extend_from_slice(&code.to_be_bytes());
            }
        }

        out
    }

    /// Decodes control payload from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < 6 {
            return Err(CoreError::InvalidControlMessage);
        }
        if bytes[0..4] != CONTROL_PREFIX {
            return Err(CoreError::InvalidControlMessage);
        }
        if bytes[4] != CONTROL_VERSION {
            return Err(CoreError::InvalidControlMessage);
        }

        let kind = bytes[5];
        let body = &bytes[6..];

        match kind {
            x if x == ControlMessageKind::ClientHello as u8 => {
                if body.len() != 96 {
                    return Err(CoreError::InvalidControlMessage);
                }
                let mut eph_public = [0u8; 32];
                eph_public.copy_from_slice(&body[0..32]);
                let mut session_salt = [0u8; 32];
                session_salt.copy_from_slice(&body[32..64]);
                let mut transcript_binding = [0u8; 32];
                transcript_binding.copy_from_slice(&body[64..96]);
                Ok(Self::ClientHello {
                    eph_public,
                    session_salt,
                    transcript_binding,
                })
            }
            x if x == ControlMessageKind::ServerHello as u8 => {
                if body.len() != 64 {
                    return Err(CoreError::InvalidControlMessage);
                }
                let mut eph_public = [0u8; 32];
                eph_public.copy_from_slice(&body[0..32]);
                let mut transcript_binding = [0u8; 32];
                transcript_binding.copy_from_slice(&body[32..64]);
                Ok(Self::ServerHello {
                    eph_public,
                    transcript_binding,
                })
            }
            x if x == ControlMessageKind::Rekey as u8 => {
                if body.len() != 66 {
                    return Err(CoreError::InvalidControlMessage);
                }
                let old_key_id = body[0];
                let new_key_id = body[1];
                let mut rekey_salt = [0u8; 32];
                rekey_salt.copy_from_slice(&body[2..34]);
                let mut transcript_binding = [0u8; 32];
                transcript_binding.copy_from_slice(&body[34..66]);
                Ok(Self::Rekey {
                    old_key_id,
                    new_key_id,
                    rekey_salt,
                    transcript_binding,
                })
            }
            x if x == ControlMessageKind::Error as u8 => {
                if body.len() != 2 {
                    return Err(CoreError::InvalidControlMessage);
                }
                let mut code_bytes = [0u8; 2];
                code_bytes.copy_from_slice(body);
                Ok(Self::Error {
                    code: u16::from_be_bytes(code_bytes),
                })
            }
            _ => Err(CoreError::InvalidControlMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_roundtrip() {
        let msg = ControlMessage::Rekey {
            old_key_id: 1,
            new_key_id: 2,
            rekey_salt: [7u8; 32],
            transcript_binding: [9u8; 32],
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, msg);
    }
}
