//! Encrypted payload TLV support (Draft v0).
//! TLV wire format (fixed-width):
//! - type: u16 (big-endian)
//! - length: u32 (big-endian)
//! - value: bytes (length as specified by length field)

use crate::CoreError;

/// Maximum TLV value length accepted by the parser/encoder.
pub const MAX_TLV_VALUE_LEN: usize = 16 * 1024 * 1024;

/// Maximum number of records in one TLV sequence, including empty records.
/// Bounds allocation amplification independently of the encrypted byte budget.
pub const MAX_TLV_RECORDS: usize = 4096;

/// Maximum encoded sequence size, including every six-byte record header.
/// A single maximum-sized value remains representable.
pub const MAX_TLV_ENCODED_LEN: usize = MAX_TLV_VALUE_LEN + 6;

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
        if payload.len() > MAX_TLV_VALUE_LEN {
            return Err(CoreError::TlvTooLarge);
        }
        Self::new(tlv_type::APPLICATION_DATA, payload.to_vec())
    }
}

/// Encodes a TLV sequence into the Draft v0 wire format.
pub fn encode_tlvs(tlvs: &[Tlv]) -> Result<Vec<u8>, CoreError> {
    if tlvs.len() > MAX_TLV_RECORDS {
        return Err(CoreError::TlvTooLarge);
    }
    // Validate the complete batch before allocating or copying any values.
    let mut encoded_len = 0usize;
    for tlv in tlvs {
        if tlv.value.len() > MAX_TLV_VALUE_LEN {
            return Err(CoreError::TlvTooLarge);
        }
        encoded_len = encoded_len
            .checked_add(6 + tlv.value.len())
            .filter(|&len| len <= MAX_TLV_ENCODED_LEN)
            .ok_or(CoreError::TlvTooLarge)?;
    }
    let mut out = Vec::with_capacity(encoded_len);
    for tlv in tlvs {
        out.extend_from_slice(&tlv.typ.to_be_bytes());
        out.extend_from_slice(&(tlv.value.len() as u32).to_be_bytes());
        out.extend_from_slice(&tlv.value);
    }
    Ok(out)
}

/// Decodes TLV records from Draft v0 wire bytes.
///
/// Validates the entire sequence before allocating values. Byte and record
/// limits apply even to zero-length and unknown records.
pub fn decode_tlvs(buf: &[u8]) -> Result<Vec<Tlv>, CoreError> {
    if buf.len() > MAX_TLV_ENCODED_LEN {
        return Err(CoreError::TlvTooLarge);
    }
    let mut idx = 0usize;
    let mut count = 0usize;
    while idx < buf.len() {
        if count == MAX_TLV_RECORDS {
            return Err(CoreError::TlvTooLarge);
        }
        if buf.len() - idx < 6 {
            return Err(CoreError::InvalidTlv);
        }
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

        idx += len;
        count += 1;
    }

    let mut out = Vec::with_capacity(count);
    idx = 0;
    for _ in 0..count {
        let typ = u16::from_be_bytes(buf[idx..idx + 2].try_into().expect("validated header"));
        let len = u32::from_be_bytes(buf[idx + 2..idx + 6].try_into().expect("validated header"))
            as usize;
        idx += 6;
        out.push(Tlv {
            typ,
            value: buf[idx..idx + len].to_vec(),
        });
        idx += len;
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

    #[test]
    fn empty_record_flood_is_bounded_in_both_directions() {
        let records = vec![Tlv::new(0x7777, Vec::new()).unwrap(); MAX_TLV_RECORDS];
        let encoded = encode_tlvs(&records).unwrap();
        assert_eq!(decode_tlvs(&encoded).unwrap(), records);
        let mut oversized = encoded;
        oversized.extend_from_slice(&[0; 6]);
        assert!(matches!(
            decode_tlvs(&oversized),
            Err(CoreError::TlvTooLarge)
        ));
        let mut oversized = records;
        oversized.push(Tlv::new(0, Vec::new()).unwrap());
        assert!(matches!(
            encode_tlvs(&oversized),
            Err(CoreError::TlvTooLarge)
        ));
    }

    #[test]
    fn aggregate_budget_and_late_truncation_are_rejected() {
        let value = vec![7; MAX_TLV_VALUE_LEN / 2];
        let records = [
            Tlv::new(1, value.clone()).unwrap(),
            Tlv::new(2, value).unwrap(),
        ];
        assert!(matches!(encode_tlvs(&records), Err(CoreError::TlvTooLarge)));
        assert!(matches!(
            decode_tlvs(&vec![0; MAX_TLV_ENCODED_LEN + 1]),
            Err(CoreError::TlvTooLarge)
        ));
        let mut encoded = encode_tlvs(&[Tlv::application_data(b"secret").unwrap()]).unwrap();
        encoded.extend_from_slice(&[0, 1, 0, 0, 0, 2, 42]);
        assert!(matches!(decode_tlvs(&encoded), Err(CoreError::InvalidTlv)));
    }
}
