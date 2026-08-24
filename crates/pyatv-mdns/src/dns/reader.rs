//! A bounds-checked cursor over a DNS message.
//!
//! pyatv parses straight out of an `io.BytesIO`, which silently returns short reads at EOF and
//! happily seeks past the end. Every read here is checked instead, so a truncated or hostile
//! datagram produces a [`DnsError`] rather than a panic or a silently-wrong parse.
//!
//! The cursor deliberately keeps the *whole* message in scope even while parsing a single record:
//! DNS name compression points backwards into arbitrary earlier bytes, so a sub-slice view is not
//! enough. Position discipline is instead enforced by the callers, which check the cursor lands
//! exactly on the end of each record's RDATA.

use super::DnsError;

/// A read cursor over a complete DNS message.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a complete DNS message, positioned at its first byte.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// The whole message, ignoring the current position.
    ///
    /// Needed by the name parser, which follows compression pointers to absolute offsets.
    #[must_use]
    pub const fn message(&self) -> &'a [u8] {
        self.data
    }

    /// The current read offset, in bytes from the start of the message.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Move the cursor to an absolute offset.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::OffsetOutOfBounds`] if `pos` is past the end of the message.
    pub fn seek(&mut self, pos: usize) -> Result<(), DnsError> {
        if pos > self.data.len() {
            return Err(DnsError::OffsetOutOfBounds {
                offset: pos,
                length: self.data.len(),
            });
        }
        self.pos = pos;
        Ok(())
    }

    /// How many bytes remain after the cursor.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Read exactly `count` bytes and advance.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::UnexpectedEof`] if fewer than `count` bytes remain.
    pub fn read_slice(&mut self, count: usize) -> Result<&'a [u8], DnsError> {
        let end = self.pos.checked_add(count).ok_or(DnsError::UnexpectedEof {
            needed: count,
            available: self.remaining(),
        })?;
        if end > self.data.len() {
            return Err(DnsError::UnexpectedEof {
                needed: count,
                available: self.remaining(),
            });
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Read one byte and advance.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::UnexpectedEof`] at the end of the message.
    pub fn read_u8(&mut self) -> Result<u8, DnsError> {
        Ok(self.read_slice(1)?[0])
    }

    /// Read a big-endian `u16` and advance.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::UnexpectedEof`] if fewer than two bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, DnsError> {
        let bytes = self.read_slice(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Read a big-endian `u32` and advance.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::UnexpectedEof`] if fewer than four bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, DnsError> {
        let bytes = self.read_slice(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use crate::dns::DnsError;

    #[test]
    fn reads_advance_the_cursor() {
        let mut reader = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(reader.read_u8().unwrap(), 0x01);
        assert_eq!(reader.read_u16().unwrap(), 0x0203);
        assert_eq!(reader.read_u32().unwrap(), 0x0405_0607);
        assert_eq!(reader.position(), 7);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn a_short_read_is_an_error_not_a_panic() {
        let mut reader = Reader::new(&[0x01]);
        assert!(matches!(
            reader.read_u32(),
            Err(DnsError::UnexpectedEof {
                needed: 4,
                available: 1
            })
        ));
    }

    #[test]
    fn a_length_that_overflows_usize_is_rejected() {
        let mut reader = Reader::new(&[0x00]);
        assert!(matches!(
            reader.read_slice(usize::MAX),
            Err(DnsError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn seeking_past_the_end_is_rejected_but_seeking_to_the_end_is_fine() {
        let mut reader = Reader::new(&[0x00, 0x01]);
        assert!(reader.seek(2).is_ok());
        assert!(matches!(
            reader.seek(3),
            Err(DnsError::OffsetOutOfBounds {
                offset: 3,
                length: 2
            })
        ));
    }
}
