use std::io::{Error, ErrorKind, Result};

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    /// Creates a new buffer for holding packet contents.
    /// Includes a field `pos` to keep track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    /// Methods for reading 1, 2, or 4 bytes.

    pub fn read(&mut self) -> Result<u8> {
        // check if we're at/past the end of buffer
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);
        Ok(res)
    }

    /// Methods for writing

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;
        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    /// Methods for setting

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    /// Methods for fetching data at a specified position or range without
    /// modifying the internal position.

    pub fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        Ok(self.buf[pos])
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// The tricky part is in reading domain names and taking labels into
    /// consideration.
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;

        // A delimiter that is appended for each label.
        let mut delim = "";
        loop {
            let len = self.get(pos)?;

            // If `len` has the 2 most significant bits set, it represents a jump
            // to some other offset in this packet.
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current label.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate the offset and perform the jump
                // by updating our local position variable.
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
            } else {
                pos += 1;

                // Domain names are terminated by an empty label of length 0.
                if len == 0 {
                    break;
                }

                outstr.push_str(delim);

                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        // If a jump was performed, we've already modified the buffer position state
        // and shouldn't do it again.
        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        let split_str = qname.split('.').collect::<Vec<&str>>();

        for label in split_str {
            let len = label.len();
            if len > 0x344 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Single label exceeds 63 characters of length",
                ));
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}
