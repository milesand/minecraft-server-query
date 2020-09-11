use std::convert::{TryFrom, TryInto};
use std::str::Utf8Error;

/// Session ID, used for tracking requests.
///
/// This is a 4-byte value that is sent in the request and is echoed back in the response, allowing the client to
/// match request with responses.
///
/// The Minecraft server expects this value to be an UTF-8 sequence, and will replace invalid bytes with
/// `\xEF\xBF\xBD`([Replacement character](https://en.wikipedia.org/wiki/Specials_(Unicode_block)#Replacement_character),
/// encoded in UTF-8) in the response. This complicates the parsing of responses as it results in session ID sections
/// longer than 4 bytes. This type restricts Session IDs to UTF-8 when serializing request, side stepping the issue
/// altogether.
///
/// Note that this provides only partial protection when **parsing** a response to non-UTF-8 session ID request, as
/// are some cases where first 4 bytes of mutated ID is valid UTF-8 and the overflown part can't be distinguished from
/// the first payload.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 4]);

impl SessionId {
    /// Constructs a `SessionId` with 4 null bytes. Use this if you don't need to match requests with responses.
    pub fn new() -> SessionId {
        SessionId([0, 0, 0, 0])
    }

    /// Constructs a `SessionId` from given `u16`. Use this if you need to match requests with responses, but you don't
    /// need more IDs than what `u16` can handle.
    ///
    /// This puts each 4 bits of `u16` into lower 4 bits of each byte. Higher bits end up first in sequence. For
    /// example, converting `0x1234` will result in sequence `0x01 0x02 0x03 0x04`.
    pub fn from_u16(mut id: u16) -> SessionId {
        let mut bytes = [0; 4];
        for byte_slot in bytes.iter_mut().rev() {
            *byte_slot = u8::try_from(id & 0b1111).unwrap();
            id >>= 4;
        }
        debug_assert!(std::str::from_utf8(&bytes).is_ok());
        SessionId(bytes)
    }

    /// Converts this `SessionId` to `u16`. This is the reverse operation of `from_u16`.
    pub fn to_u16(self) -> u16 {
        let mut id = 0;
        for &byte in self.0.iter() {
            id <<= 4;
            id |= u16::from(byte);
        }
        id
    }

    /// Constructs a `SessionId` from given bytes, checking UTF-8 requirement.
    pub fn try_from_bytes(id: [u8; 4]) -> Result<SessionId, Utf8Error> {
        if let Err(e) = std::str::from_utf8(&id) {
            return Err(e);
        }
        Ok(SessionId(id))
    }

    /// Extracts the inner value of this `SessionId`.
    pub fn inner(&self) -> [u8; 4] {
        self.0
    }

    /// Constructs a `SessionId` from given string, checking length requirement.
    /// This fails if the length of given string is not 4.
    pub fn try_from_str(id: &'_ str) -> Result<SessionId, ()> {
        if let Ok(bytes) = id.as_bytes().try_into() {
            Ok(SessionId(bytes))
        } else {
            Err(())
        }
    }
}

impl From<u16> for SessionId {
    /// Equal to `from_u16`.
    fn from(id: u16) -> SessionId {
        SessionId::from_u16(id)
    }
}

impl From<SessionId> for u16 {
    /// Equal to `to_u16`.
    fn from(id: SessionId) -> u16 {
        id.to_u16()
    }
}

impl TryFrom<[u8; 4]> for SessionId {
    type Error = Utf8Error;

    /// Equal to `try_from_bytes`.
    fn try_from(id: [u8; 4]) -> Result<SessionId, Utf8Error> {
        SessionId::try_from_bytes(id)
    }
}

impl From<SessionId> for [u8; 4] {
    fn from(id: SessionId) -> [u8; 4] {
        id.0
    }
}

impl TryFrom<&'_ str> for SessionId {
    type Error = ();

    /// Equal to `try_from_str`.
    fn try_from(id: &'_ str) -> Result<SessionId, ()> {
        if let Ok(bytes) = id.as_bytes().try_into() {
            Ok(SessionId(bytes))
        } else {
            Err(())
        }
    }
}
