// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
 * A Simple Encryption / Decryption format.
 *
 * The format of the files produced is fairly simple: There is an 8 byte header, followed by a
 * series of different Chunks. Each chunk identifies its type, its length, its 0-indexed position,
 * and whether it must be undrestood by the Decryptor. Each Chunk ends with the Mac code of the
 * entire Chunk, which must be verified during decryption. The Chunks may be put in any order,
 * however, the chunks necessary to construct the authentication function must come first and all
 * Chunks necesary to setup the decruption function must appear before the fist encrypted data
 * chunk. The design of the format closely matches that of a PNG file. All integers are encoded in
 * big-endian format.
 *
 * =Header=
 *
 * The Header contains the bare minimum ammount of information necessary to start parsing - just the
 * magic value. It is the only piece of data that is not covered by a Mac code.
 *
 * Field         - Type                - Description
 * MAGIC         - ASCII CHAR[8]       - "RUSTCRPT"
 *
 * =Chunk Header=
 *
 * Each Chunk has the following header:
 * Field         - Type                - Description
 * NAME          - ASCII CHAR[4]       - 4 ASCII bytes that name the chunk
 * POSITION      - U64                 - The Chunk position. The first Chunk is in position 0.
 * LENGTH        - U32                 - The length of the chunk, including this chunk header and
 *                                       the Mac code at the end.
 * FLAGS         - U32                 - The 0th bit is set if the Chunk must be understood. The 1st
 *                                       bit is set if this is the last chunk. The rest of the bits
 *                                       are reserved.
 *
 * =Chunk Footer=
 *
 * Each Chunk has the following at the end:
 * Field         - Type                - Description
 * MAC           - U8*                 - The MAC code of the entire Chunk, including the Chunk
 *                                       Header. The length of this field depends on the Mac
 *                                       function in use.
 *
 * =Chunks=
 *
 * ==Symmetric Encryption Algorithm Chunk==
 *
 * Name: "SYMA"
 *
 * Field         - Length              - Description
 * ALGO_NAME_LEN - U32                 - length of next field
 * ALGO_NAME     - U8*                 - name of algorithm used for encryption
 * IV_LEN        - U32                 - length of next field
 * IV            - U8*                 - IV
 * MAC_NAME_LEN  - U32                 - length of next field
 * MAC_NAME      - ASCII CHAR*         - name of the Mac algorithm
 * KDF_NAME_LEN  - U32                 - length of next field
 * KDF_NAME      - ASCII CHAR*         - name of the KDF algorithm
 * ENC_SALT_LEN  - U32                 - length of next field
 * ENC_SALT      - U8*                 - encryption salt value
 * MAC_SALT_LEN  - U32                 - length of next field
 * MAC_SALT      - U8*                 - Mac salt value
 *
 * ==Plaintext Data Chunk==
 *
 * Some modes require that all plaintext chunks come before encrypted chunks.
 *
 * Name: "PDAT"
 *
 * Field         - Length              - Description
 * DATA          - U8*                 - Plaintext data
 *
 * ==Encrypted Data Chunk==
 *
 * Name: "EDAT"
 *
 * Field         - Length              - Description
 * DATA          - U8*                 - Encrypted data
 */

use rust_crypto::aes;
use rust_crypto::aes::{KeySize, KeySize128, KeySize192, KeySize256};
use rust_crypto::blockmodes::{NoPadding, PkcsPadding, StandardPadding};
use rust_crypto::buffer::{BufferUnderflow, BufferOverflow, OwnedReadBuffer, OwnedWriteBuffer,
    ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use rust_crypto::hmac::Hmac;
use rust_crypto::rc4::Rc4;
use rust_crypto::mac::{Mac, MacResult};
use rust_crypto::scrypt;
use rust_crypto::scrypt::ScryptParams;
use rust_crypto::sha2::Sha256;
use rust_crypto::symmetriccipher::{Decryptor, Encryptor};

use std::from_str::FromStr;
use std::io;
use std::io::{BufferedReader, BufReader, File, IoError, IoResult, MemReader, MemWriter,
    OtherIoError};
use std::io::fs;
use std::io::util::{copy, LimitReader, NullWriter};
use std::os;
use std::rand::{OSRng, Rng};
use std::str;
use std::vec;

macro_rules! try( ($x:expr) =>
    (
        match $x {
            Ok(y) => y,
            Err(e) => return Err(e)
        }
    )
)

static MustUnderstandFlag: u32 = 0x01;
static LastChunkFlag: u32 = 0x02;

struct ChunkHeader {
    chunk_pos: u64,
    chunk_remaining_len: u32,
    chunk_flags: u32
}

struct SymmetricAlgoChunkInfo {
    algo_name: ~str,
    iv: ~[u8],
    mac_name: ~str,
    kdf_name: ~str,
    enc_salt: ~[u8],
    mac_salt: ~[u8]
}

enum Chunk {
    SymmetricAlgoChunk(SymmetricAlgoChunkInfo),
    PlainDataChunk,
    EncryptedDataChunk,
    UnknownChunk
}

fn read_full<R: Reader>(reader: &mut R, buff: &mut [u8]) -> IoResult<uint> {
    let mut pos = 0;
    loop {
        match reader.read(buff.mut_slice_from(pos)) {
            Ok(cnt) => {
                pos += cnt;
                if pos == buff.len() {
                    return Ok(pos)
                }
            }
            e @ Err(_) => return e
        }
    }
}

fn parse_chunk<R: Reader>(
        chunk_name: &[u8, ..4],
        chunk_pos: u64,
        chunk_remaining_len: u32,
        chunk_flags: u32,
        chunk_reader: &mut R)
        -> IoResult<(ChunkHeader, Chunk)> {
    let chunk_reader = &mut LimitReader::new(chunk_reader, chunk_remaining_len as uint);

    fn read_field<R: Reader>(reader: &mut R) -> IoResult<~[u8]> {
        let field_len = if_ok!(reader.read_be_u32());
        reader.read_bytes(field_len as uint)
    }

    fn to_str(f: &[u8]) -> IoResult<~str> {
        match str::from_utf8_owned(f.to_owned()) {
            Some(s) => Ok(s),
            None => Err(IoError { kind: OtherIoError, desc: "Invalid str", detail: None })
        }
    }

    fn read_str_field<R: Reader>(reader: &mut R) -> IoResult<~str> {
        to_str(if_ok!(read_field(reader)))
    }

    fn consume_remaining<R: Reader>(reader: &mut R) -> IoResult<()> {
        copy(reader, &mut NullWriter)
    }

    let chunk_header = ChunkHeader {
        chunk_pos: chunk_pos,
        chunk_remaining_len: chunk_remaining_len,
        chunk_flags: chunk_flags
    };

    let chunk_name = if_ok!(to_str(chunk_name.to_owned()));

    match chunk_name.as_slice() {
        "SYMA" => {
            let algo_name = if_ok!(read_str_field(chunk_reader));
            let iv = if_ok!(read_field(chunk_reader));
            let mac_name = if_ok!(read_str_field(chunk_reader));
            let kdf_name = if_ok!(read_str_field(chunk_reader));
            let enc_salt = if_ok!(read_field(chunk_reader));
            let mac_salt = if_ok!(read_field(chunk_reader));
            if_ok!(consume_remaining(chunk_reader));
            let chunk_info = SymmetricAlgoChunkInfo {
                algo_name: algo_name,
                iv: iv,
                mac_name: mac_name,
                kdf_name: kdf_name,
                enc_salt: enc_salt,
                mac_salt: mac_salt };
            Ok((chunk_header, SymmetricAlgoChunk(chunk_info)))
        }
        // The Data chunks are special in that we don't read their bodies - so, we specifically
        // don't want to consume the remaining input from the reader.
        "PDAT" => {
            Ok((chunk_header, PlainDataChunk))
        }
        "EDAT" => {
            Ok((chunk_header, EncryptedDataChunk))
        }
        _ => {
            if_ok!(consume_remaining(chunk_reader));
            Ok((chunk_header, UnknownChunk))
        }
    }
}

fn read_next_chunk_with_data<R: Reader>(reader: &mut R) -> IoResult<(ChunkHeader, Chunk, ~[u8])> {
    let mut chunk_data = if_ok!(reader.read_bytes(20));
    let (chunk_name, chunk_pos, chunk_remaining_len, chunk_flags) = {
        let chunk_header_reader = BufReader::new(chunk_data);
        let mut chunk_name = [0u8, ..4];
        if_ok!(read_full(reader, chunk_name));
        (chunk_name, if_ok!(reader.read_be_u64()), if_ok!(reader.read_be_u32()) - 20, if_ok!(reader.read_be_u32()))
    };
    chunk_data.grow_fn(chunk_remaining_len as uint, |_| { 0u8 });
    if_ok!(read_full(reader, chunk_data.mut_slice_from(20)));
    let (chunk_header, chunk) = if_ok!(parse_chunk(
        &chunk_name,
        chunk_pos,
        chunk_remaining_len,
        chunk_flags,
        &mut BufReader::new(chunk_data.slice_from(20))));
    Ok((chunk_header, chunk, chunk_data))
}

fn read_next_chunk<R: Reader>(reader: &mut R) -> IoResult<(ChunkHeader, Chunk)> {
    let mut chunk_name = [0u8, ..4];
    if_ok!(read_full(reader, chunk_name));
    let chunk_pos = if_ok!(reader.read_be_u64());
    let chunk_remaining_len = if_ok!(reader.read_be_u32()) - 20;
    let chunk_flags = if_ok!(reader.read_be_u32());
    parse_chunk(&chunk_name, chunk_pos, chunk_remaining_len, chunk_flags, reader)
}

fn os_rand(size: uint) -> ~[u8] {
    let mut rng = OSRng::new();
    let vec: ~[u8] = rng.gen_vec(size);
    vec
}

fn gen_key(scrypt_params: &ScryptParams, pass: &[u8], salt: &[u8], size: uint) -> ~[u8] {
    let mut result = vec::from_elem(size, 0u8);
    scrypt::scrypt(pass, salt, scrypt_params, result);
    result
}

fn io_err<T>(desc: ~str) -> IoResult<T> {
    Err(IoError { kind: OtherIoError, desc: "Invalid", detail: Some(desc) })
}

fn parse_aes_key_size(ks: Option<&str>) -> IoResult<(KeySize, uint)> {
    match ks {
        Some("128") => Ok((KeySize128, 16)),
        Some("192") => Ok((KeySize192, 24)),
        Some("256") => Ok((KeySize256, 32)),
        _ => io_err(~"Invalid or missing key size")
    }
}

fn parse_rc4_key_size(ks: Option<&str>) -> IoResult<uint> {
    match ks {
        Some(key_size_str) => {
            match from_str::<uint>(key_size_str) {
                Some(x) => if x < 40 {
                    io_err(~"Key size must be at least 40")
                } else if x > 2048 {
                    io_err(~"Key size must be no more than 2048")
                } else if x % 8 != 0 {
                    io_err(~"Key size must be a multiple of 8 bits")
                } else {
                    Ok(x / 8)
                },
                None => io_err(~"Invalid key size")
            }
        }
        None => io_err(~"Key size not specified")
    }
}

fn parse_padding(pad: Option<&str>) -> IoResult<StandardPadding> {
    match pad {
        Some("NoPadding") => Ok(NoPadding),
        Some("PkcsPadding") => Ok(PkcsPadding),
        _ => io_err(~"Invalid padding")
    }
}

// Parse the supplied algorithm name and return a suitable ~Encryptor
fn get_encryptor(
        algo_name: &str,
        pass: &[u8],
        salt: &[u8],
        scrypt_params: &ScryptParams) -> IoResult<(~Encryptor, Option<~[u8]>)> {
    let mut x = algo_name.split('/');
    match x.next() {
        Some("AES") => {
            let (key_size, ks) = if_ok!(parse_aes_key_size(x.next()));
            match x.next() {
                Some("ECB") => {
                    let padding = if_ok!(parse_padding(x.next()));
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok((aes::ecb_encryptor(key_size, key, padding), None))
                }
                Some("CBC") => {
                    let padding = if_ok!(parse_padding(x.next()));
                    let iv = os_rand(16);
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok((aes::cbc_encryptor(key_size, key, iv, padding), Some(iv)))
                }
                Some("CTR") => {
                    let iv = os_rand(16);
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok((aes::ctr_enc(key_size, key, iv), Some(iv)))
                }
                _ => io_err(~"Invalid mode")
            }
        }
        Some("RC4") => {
            let ks = if_ok!(parse_rc4_key_size(x.next()));
            if x.next().is_some() {
                return io_err(~"Invalid RC4 specification");
            }
            let key = gen_key(scrypt_params, pass, salt, ks);
            Ok((~Rc4::new(key) as ~Encryptor, None))
        }
        _ => io_err(~"Invalid cipher")
    }
}

// Parse the supplied algorithm name and return a suitable ~Decryptor
fn get_decryptor(
        algo_name: &str,
        pass: &[u8],
        salt: &[u8],
        scrypt_params: &ScryptParams,
        iv: &[u8]) -> IoResult<~Decryptor> {
    let mut x = algo_name.split('/');
    match x.next() {
        Some("AES") => {
            let (key_size, ks) = if_ok!(parse_aes_key_size(x.next()));
            match x.next() {
                Some("ECB") => {
                    let padding = if_ok!(parse_padding(x.next()));
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok(aes::ecb_decryptor(key_size, key, padding))
                }
                Some("CBC") => {
                    let padding = if_ok!(parse_padding(x.next()));
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok(aes::cbc_decryptor(key_size, key, iv, padding))
                }
                Some("CTR") => {
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok(aes::ctr_dec(key_size, key, iv))
                }
                _ => io_err(~"Invalid mode")
            }
        }
        Some("RC4") => {
            let ks = if_ok!(parse_rc4_key_size(x.next()));
            if x.next().is_some() {
                return io_err(~"Invalid RC4 specification");
            }
            let key = gen_key(scrypt_params, pass, salt, ks);
            Ok(~Rc4::new(key) as ~Decryptor)
        }
        _ => io_err(~"Invalid cipher")
    }
}

// TODO - Make this more generic!
fn get_kdf(kdf_name: &str) -> IoResult<ScryptParams> {
    let mut x = kdf_name.split('/');
    match x.next() {
        Some("SCrypt") => {
            // TODO - Remove unwraps and validate ranges!
            let log_n: u8 = match x.next() {
                Some(x) => match FromStr::from_str(x) {
                    Some (y) => y,
                    None => return io_err(~"Inv")
                },
                None => return io_err(~"Inv")
            };
            let r: u32 = match x.next() {
                Some(x) => match FromStr::from_str(x) {
                    Some (y) => y,
                    None => return io_err(~"Inv")
                },
                None => return io_err(~"Inv")
            };
            let p: u32 = match x.next() {
                Some(x) => match FromStr::from_str(x) {
                    Some (y) => y,
                    None => return io_err(~"Inv")
                },
                None => return io_err(~"Inv")
            };
            Ok(ScryptParams::new(log_n, r, p))
        }
        _ => io_err(~"Invalid KDF")
    }
}

// Parse the supplied algorithm name and return a suitable ~Encryptor
fn get_mac(
        mac_name: &str,
        pass: &[u8],
        salt: &[u8],
        scrypt_params: &ScryptParams) -> IoResult<~Mac> {
    let mut x = mac_name.split('/');
    match x.next() {
        Some("HMAC") => {
            match x.next() {
                Some("SHA-256") => {
                    let sha256 = Sha256::new();
                    let mut mac_key = [0u8, ..64];
                    scrypt::scrypt(pass, salt, scrypt_params, mac_key);
                    Ok(~Hmac::new(sha256, mac_key) as ~Mac)
                }
                _ => io_err(~"Invalid HMAC Digest")
            }
        }
        _ => io_err(~"Invalid mac")
    }
}

enum ReaderState {
    BeforeReading(~[u8]),
    BeforeDataChunk(~Mac, ~Decryptor),
    AfterDataChunk(~Mac, ~Decryptor, MemReader)
}

pub struct ClanReader<R> {
    priv reader: R,
    priv state: Option<ReaderState>,
    priv next_chunk_pos: u64,
    priv password: Option<~[u8]>
}

impl <R: Reader> ClanReader<R> {
    pub fn new(reader: R, password: &str) -> ClanReader<R> {
        ClanReader {
            reader: reader,
            state: Some(BeforeReading(password.as_bytes().to_owned())),
            next_chunk_pos: 0,
            password: Some(password.as_bytes().to_owned())
        }
    }
    pub fn unwrap(self) -> R {
        let ClanReader { reader, .. } = self;
        reader
    }
}

impl <R: Reader> Reader for ClanReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        loop {
            match self.state.take_unwrap() {
                BeforeReading(password) => {
                    // Read in the header
                    // TODO - get rid of allocation here
                    let magic = if_ok!(self.reader.read_bytes(8));
                    if magic.as_slice() != "RUSTCRPT".as_bytes() {
                        fail!("Invalid header");
                    }

                    let mut algo_chunk: Option<SymmetricAlgoChunkInfo> = None;

                    let mut chunk_data_items: ~[~[u8]] = ~[];

                    loop {
                        let (chunk_header, chunk, chunk_data) =
                            if_ok!(read_next_chunk_with_data(&mut self.reader));
                        chunk_data_items.push(chunk_data);

                        assert!(chunk_header.chunk_pos == self.next_chunk_pos);
                        self.next_chunk_pos += 1;

                        match chunk {
                            SymmetricAlgoChunk(c) => algo_chunk = Some(c),
                            PlainDataChunk => { break; }
                            EncryptedDataChunk => { break; }
                            UnknownChunk => {
                                if chunk_header.chunk_flags & MustUnderstandFlag != 0 {
                                    fail!("Encountered unkown must-understand chunk");
                                }
                            }
                        }

                        if chunk_header.chunk_flags & LastChunkFlag != 0 {
                            break;
                        }
                    }

                    // Validate that we got all the chunks we needed
                    assert!(algo_chunk.is_some());
                    let algo_info = algo_chunk.take_unwrap();

                    // Construct the Mac
                    let scrypt_params = if_ok!(get_kdf(algo_info.kdf_name));
                    let mut mac = if_ok!(get_mac(
                        algo_info.mac_name,
                        password,
                        algo_info.mac_salt,
                        &scrypt_params));

                    // Validate all of the headers we've already read
                    for c in chunk_data_items.move_iter() {
                        mac.reset();
                        mac.input(c);
                        let r1 = mac.result();
                        // TODO - the size of the Mac can vary!
                        let r2 = MacResult::new(c.slice_from(c.len() - 32));
                        if r1 != r2 {
                            return io_err(~"Invalid chunk mac");
                        }
                    }

                    // Construct the Decryptor
                    let mut dec = if_ok!(get_decryptor(
                        algo_info.algo_name,
                        password,
                        algo_info.mac_salt,
                        &scrypt_params,
                        algo_info.iv));

                    // Begin decrypting now that we're all set up
                    self.state = Some(BeforeDataChunk(mac, dec));
                }
                BeforeDataChunk(mut mac, mut dec) => {
                    let (chunk_header, chunk) = if_ok!(read_next_chunk(&mut self.reader));

                    assert!(chunk_header.chunk_pos == self.next_chunk_pos);
                    self.next_chunk_pos += 1;

                    // TODO - avoid allocation!
                    let chunk_data = if_ok!(self.reader.read_bytes(
                        chunk_header.chunk_remaining_len as uint));
                    // TODO - the size of the Mac can vary!
                    let r2 = MacResult::new_from_owned(if_ok!(self.reader.read_bytes(32)));

                    // Verify Mac
                    mac.reset();
                    mac.input(chunk_data);
                    let r1 = mac.result();
                    if r1 != r2 {
                        return io_err(~"Invalid chunk mac");
                    }

                    // Decrypt
                    fn decrypt_full(dec: &mut Decryptor, buff_in: &[u8], output: &mut MemWriter) -> IoResult<()> {
                        let mut bin = RefReadBuffer::new(buff_in);
                        let mut buff_out = [0u8, ..1024];
                        loop {
                            let mut wout = RefWriteBuffer::new(buff_out);
                            match dec.decrypt(&mut bin, &mut wout, true) {
                                Ok(BufferUnderflow) => {
                                    if_ok!(output.write(wout.take_read_buffer().take_remaining()));
                                    return Ok(());
                                }
                                Ok(BufferOverflow) => if_ok!(output.write(wout.take_read_buffer().take_remaining())),
                                Err(_) => return io_err(~"Decryption error")
                            }
                        }
                    };

                    let mut mw = MemWriter::new();
                    if_ok!(decrypt_full(dec, chunk_data, &mut mw));

                    self.state = Some(AfterDataChunk(mac, dec, MemReader::new(mw.unwrap())));
                }
                AfterDataChunk(mac, dec, mut mr) => {
                    use std::io::File;
                    use std::path::Path;
                    let mut f = File::open(&Path::new("/"));
                    match f.read(buf) {
                        Ok(x) => {
                            self.state = Some(AfterDataChunk(mac, dec, mr));
                            return Ok(x)
                        }
                        Err(IoError { kind: EndOfFile, .. }) => {
                            self.state = Some(BeforeDataChunk(mac, dec));
                        }
                        // TODO - why is this not reachable?
                        // Err(e) => return Err(e)
                    }
                }
            }
        }
    }
}

// TODO - Each EncryptedDataChunk should have its own IV
// TOOD - Decryptors need a way to reset their IV
// TOOD - Decryptors need a way to determine if their IV needs to be reset
// TOOD - Handle PlainDataChunk as part of decryption
// TODO - Make KDFs into a trait!
// TODO - reduces copies during decryption - decrypt directly into the result buffer!

/*
pub struct ClanWriter<W, M, D> {
    priv writer: W,
    priv mac: M,
    priv dec: D
}

impl <R: Reader, M: Mac, D: Decryptor> Writer for ClanWriter<R, M, D> {
    fn write(&mut self, buf: &[u8]) {

    }

    fn flush(&mut self) {

    }
}
*/
