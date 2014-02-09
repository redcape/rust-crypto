// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use mac::Mac;

use std::io::IoResult;

// TODO - Have this take the writer to wrap by value!
pub struct MacWriter<'a, W, M> {
    priv writer: &'a mut W,
    priv mac: M
}

impl <'a, W: Writer, M: Mac> MacWriter<'a, W, M> {
    pub fn new(writer: &'a mut W, mac: M) -> MacWriter<'a, W, M> {
        MacWriter {
            writer: writer,
            mac: mac
        }
    }
}

impl <'a, W: Writer, M: Mac> Writer for MacWriter<'a, W, M> {
    fn write(&mut self, buff: &[u8]) -> IoResult<()> {
        self.mac.input(buff);
        self.writer.write(buff)
    }
}

// TODO - Have this take the reader to wrap by value!
pub struct MacReader<'a, R, M> {
    priv reader: &'a mut R,
    priv mac: M
}

impl <'a, R: Reader, M: Mac> MacReader<'a, R, M> {
    pub fn new(reader: &'a mut R, mac: M) -> MacReader<'a, R, M> {
        MacReader {
            reader: reader,
            mac: mac
        }
    }
}

impl <'a, R: Reader, M: Mac> Reader for MacReader<'a, R, M> {
    fn read(&mut self, buff: &mut [u8]) -> IoResult<uint> {
        let cnt = if_ok!(self.reader.read(buff));
        self.mac.input(buff.slice_to(cnt));
        Ok(cnt)
    }
}
