use std::convert::{TryFrom, TryInto};
use std::str::Utf8Error;

/// Session ID, used for tracking requests.
/// 
/// This is a 4-byte value that is sent in the request and is echoed back in the response, allowing the client to
/// match request with responses.
/// 
/// In practice, the Minecraft server expects this value to be an UTF-8 sequence, and will replace invalid bytes with
/// `\xEF\xBF\xBD`([Replacement character](https://en.wikipedia.org/wiki/Specials_(Unicode_block)#Replacement_character), 
/// encoded in UTF-8) in the response. Thus, this type enforces the UTF-8 requirement.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 4]);

impl SessionId {
    /// Constructs a `SessionId` with 4 null bytes. Use this if you don't need to match requests with responses.
    pub fn new() -> SessionId {
        SessionId([0, 0, 0, 0])
    }
}

impl From<u16> for SessionId {
    /// Constructs a `SessionId` from given `u16`. Use this if you need to match requests with responses, but you don't
    /// need more IDs than what `u16` can handle.
    /// 
    /// This puts each 4 bits of `u16` into lower 4 bits of each byte. Higher bits end up first in sequence. For
    /// example, converting `0x1234` will result in sequence `0x01 0x02 0x03 0x04`.
    fn from(mut id: u16) -> SessionId {
        let mut bytes = [0; 4];
        for byte_slot in bytes.iter_mut().rev() {
            *byte_slot = u8::try_from(id & 0b1111).unwrap();
            id >>= 4;
        }
        debug_assert!(std::str::from_utf8(&bytes).is_ok());
        SessionId(bytes)
    }
}

impl From<SessionId> for u16 {
    /// Reverse of `u16` to `SessionId` conversion.
    fn from(id: SessionId) -> u16 {
        let mut idu16 = 0;
        for &byte in id.0.iter() {
            idu16 <<= 4;
            idu16 |= u16::from(byte);
        }
        idu16
    }
}

impl TryFrom<[u8; 4]> for SessionId {
    type Error = Utf8Error;

    /// Constructs a `SessionId` from given bytes, checking UTF-8 requirement. 
    fn try_from(id: [u8; 4]) -> Result<SessionId, Utf8Error> {
        if let Err(e) = std::str::from_utf8(&id) {
            return Err(e);
        }
        Ok(SessionId(id))
    }
}

impl From<SessionId> for [u8; 4] {
    fn from(id: SessionId) -> [u8; 4] {
        id.0
    }
}

impl TryFrom<&'_ str> for SessionId {
    type Error = ();

    /// Constructs a `SessionId` from given string, checking length requirement.
    /// This fails if the length of given string is not 4.
    fn try_from(id: &'_ str) -> Result<SessionId, ()> {
        if let Ok(bytes) = id.as_bytes().try_into() {
            Ok(SessionId(bytes))
        } else {
            Err(())
        }
    }
}