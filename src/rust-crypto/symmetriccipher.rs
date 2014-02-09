// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use cryptoutil::symm_enc_or_dec;

pub trait BlockEncryptor {
    fn block_size(&self) -> uint;
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockEncryptorX8 {
    fn block_size(&self) -> uint;
    fn encrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptor {
    fn block_size(&self) -> uint;
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptorX8 {
    fn block_size(&self) -> uint;
    fn decrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub enum SymmetricCipherError {
    InvalidLength,
    InvalidPadding
}

pub trait Encryptor {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
        -> Result<BufferResult, SymmetricCipherError>;
    fn reset(&mut self, iv: &[u8]) -> Result<(), ()>;
}

pub trait Decryptor {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
        -> Result<BufferResult, SymmetricCipherError>;
    fn reset(&mut self, iv: &[u8]) -> Result<(), ()>;
}

pub trait SynchronousStreamCipher {
    fn process(&mut self, input: &[u8], output: &mut [u8]);
    fn reset(&mut self, iv: &[u8]) -> Result<(), ()>;
}

// TODO - Its a bit unclear to me why this is necessary
impl SynchronousStreamCipher for ~SynchronousStreamCipher {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        self.process(input, output);
    }
    fn reset(&mut self, iv: &[u8]) -> Result<(), ()> {
        self.reset(iv)
    }
}

impl Encryptor for ~SynchronousStreamCipher {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
    fn reset(&mut self, iv: &[u8]) -> Result<(), ()> {
        self.reset(iv)
    }
}

impl Decryptor for ~SynchronousStreamCipher {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
    fn reset(&mut self, iv: &[u8]) -> Result<(), ()> {
        self.reset(iv)
    }
}
