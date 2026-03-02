//! Encrypted payload TLV support (Draft v0).
//! TLV wire format (fixed-width):
//! - type: u16 (big-endian)
//! - length: u32 (big-endian)
//! - value: bytes (length as specified by length field)

use crate::CoreError;

/// Maximum TLV value length accepted by the parser/encoder.
pub const MAX_TLV_VALUE_LEN: usize = 16 * 1024 * 1024;

/// Reserved TLV type identifiers for Draft v0 payloads.
pub mod tlv_type {
    /// Opaque application bytes.
    pub const APPLICATION_DATA: u16 = 0x0001;
    /// Metadata for a file chunk payload.
    pub const FILE_CHUNK_META: u16 = 0x0101;
    /// Chunk payload bytes.
    pub const FILE_CHUNK_PAYLOAD: u16 = 0x0102;
    /// Optional acknowledgement hint.
    pub const ACK_HINT: u16 = 0x0201;
    /// Optional padding bytes.
    pub const PADDING: u16 = 0xFFFF;
}

/// A single TLV record stored inside encrypted frame payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tlv {
    /// TLV type identifier.
    pub typ: u16,
    /// TLV value bytes.
    pub value: Vec<u8>,
}

impl Tlv {
    /// Creates a TLV record with explicit type/value.
    pub fn new(typ: u16, value: Vec<u8>) -> Result<Self, CoreError> {
        if value.len() > MAX_TLV_VALUE_LEN {
            return Err(CoreError::TlvTooLarge);
        }
        Ok(Self { typ, value })
    }

    /// Creates an `APPLICATION_DATA` TLV record.
    pub fn application_data(payload: &[u8]) -> Result<Self, CoreError> {
        Self::new(tlv_type::APPLICATION_DATA, payload.to_vec())
    }
}

/// Encodes a TLV sequence into the Draft v0 wire format.
pub fn encode_tlvs(tlvs: &[Tlv]) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    for tlv in tlvs {
        if tlv.value.len() > MAX_TLV_VALUE_LEN {
            return Err(CoreError::TlvTooLarge);
        }
        out.extend_from_slice(&tlv.typ.to_be_bytes());
        out.extend_from_slice(&(tlv.value.len() as u32).to_be_bytes());
        out.extend_from_slice(&tlv.value);
    }
    Ok(out)
}

/// Decodes TLV records from Draft v0 wire bytes.
pub fn decode_tlvs(buf: &[u8]) -> Result<Vec<Tlv>, CoreError> {
    let mut idx = 0usize;
    let mut out = Vec::new();

    while idx < buf.len() {
        if buf.len() - idx < 6 {
            return Err(CoreError::InvalidTlv);
        }

        let mut typ_bytes = [0u8; 2];
        typ_bytes.copy_from_slice(&buf[idx..idx + 2]);
        idx += 2;

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buf[idx..idx + 4]);
        idx += 4;

        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > MAX_TLV_VALUE_LEN {
            return Err(CoreError::TlvTooLarge);
        }
        if buf.len() - idx < len {
            return Err(CoreError::InvalidTlv);
        }

        let value = buf[idx..idx + len].to_vec();
        idx += len;

        out.push(Tlv {
            typ: u16::from_be_bytes(typ_bytes),
            value,
        });
    }

    Ok(out)
}

/// Finds the first TLV value matching `typ`.
pub fn find_first_tlv_value(tlvs: &[Tlv], typ: u16) -> Option<&[u8]> {
    tlvs.iter()
        .find(|t| t.typ == typ)
        .map(|t| t.value.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_roundtrip() {
        let src = vec![
            Tlv::application_data(b"hello").expect("app tlv"),
            Tlv::new(tlv_type::ACK_HINT, vec![0x01]).expect("ack tlv"),
        ];

        let enc = encode_tlvs(&src).expect("encode");
        let dec = decode_tlvs(&enc).expect("decode");
        assert_eq!(dec, src);
    }
}
