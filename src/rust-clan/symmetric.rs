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
 * ==SCrypt Chunk==
 *
 * Name: "SCRP"
 *
 * Field         - Length              - Description
 * SCRIPT_LOG_N  - U8                  - The log of the N parameter to SCrypt
 * SCRIPT_R      - U32                 - the R parameter to SCrypt
 * SCRIPT_P      - U32                 - the P parameter to SCrypt
 * ENC_SALT_LEN  - U32                 - length of next field
 * ENC_SALT      - U8*                 - encryption salt value
 * MAC_SALT_LEN  - U32                 - length of next field
 * MAC_SALT      - U8*                 - Mac salt value
 *
 * ==MAC Algo Chunk==
 *
 * Name: "MAC1"
 *
 * This Chunk describes a simple Mac algorithm such as HMAC.
 *
 * Field         - Type                - Description
 * MAC_NAME_LEN  - U32                 - length of next field
 * MAC_NAME      - ASCII CHAR*         - name of the Mac algorithm
 *
 * ==Cipher Algorithm Chunk==
 *
 * Name: "CIPR"
 *
 * Field         - Length              - Description
 * ALGO_NAME_LEN - U32                 - length of next field
 * ALGO_NAME     - U8*                 - name of algorithm used for encryption
 * IV_LEN        - U32                 - length of next field
 * IV            - U8*                 - IV
 *
 * ==Data Chunk==
 *
 * Name: "DATA"
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

use std::io;
use std::io::{BufferedReader, BufReader, File};
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

struct ScryptChunkInfo {
    log_n: u8,
    r: u32,
    p: u32,
    enc_salt: ~[u8],
    mac_salt: ~[u8]
}

struct MacChunkInfo {
    mac_name: ~str
}

struct CipherAlgoChunkInfo {
    algo_name: ~str,
    iv: ~[u8]
}

enum Chunk {
    SCryptChunk(ScryptChunkInfo),
    MacChunk(MacChunkInfo),
    CipherAlgoChunk(CipherAlgoChunkInfo),
    DataChunk,
    UnknownChunk
}

fn read_full<R: Reader>(reader: &mut R, buff: &mut [u8]) {
    let mut pos = 0;
    loop {
        match reader.read(buff.mut_slice_from(pos)) {
            Some(cnt) => {
                pos += cnt;
                if pos == buff.len() {
                    return
                }
            }
            None => { fail!("Unexpected EOF") }
        }
    }
}

fn parse_chunk<R: Reader>(
        chunk_name: &[u8, ..4],
        chunk_pos: u64,
        chunk_remaining_len: u32,
        chunk_flags: u32,
        chunk_reader: &mut R)
        -> (ChunkHeader, Chunk) {
    let chunk_reader = &mut LimitReader::new(chunk_reader, chunk_remaining_len as uint);

    fn read_field<R: Reader>(reader: &mut R) -> ~[u8] {
        let field_len = reader.read_be_u32();
        reader.read_bytes(field_len as uint)
    }

    fn read_str_field<R: Reader>(reader: &mut R) -> ~str {
        match str::from_utf8_owned(read_field(reader)) {
            Some(s) => s,
            None => fail!("Invalid string field value")
        }
    }

    fn consume_remaining<R: Reader>(reader: &mut R) {
        copy(reader, &mut NullWriter);
    }

    let chunk_header = ChunkHeader {
        chunk_pos: chunk_pos,
        chunk_remaining_len: chunk_remaining_len,
        chunk_flags: chunk_flags
    };

    let chunk_name = match str::from_utf8_owned(chunk_name.to_owned()) {
        Some(s) => s,
        None => fail!("Invalid chunk name")
    };

    match chunk_name.as_slice() {
        "SCRP" => {
            let log_n = chunk_reader.read_u8();
            let r = chunk_reader.read_be_u32();
            let p = chunk_reader.read_be_u32();
            let enc_salt = read_field(chunk_reader);
            let mac_salt = read_field(chunk_reader);
            consume_remaining(chunk_reader);
            let chunk_info = ScryptChunkInfo {
                log_n: log_n,
                r: r,
                p: p,
                enc_salt: enc_salt,
                mac_salt: mac_salt };
            (chunk_header, SCryptChunk(chunk_info))
        }
        "MAC1" => {
            let mac_name = read_str_field(chunk_reader);
            consume_remaining(chunk_reader);
            let chunk_info = MacChunkInfo { mac_name: mac_name };
            (chunk_header, MacChunk(chunk_info))
        }
        "CIPR" => {
            let algo_name = read_str_field(chunk_reader);
            let iv = read_field(chunk_reader);
            consume_remaining(chunk_reader);
            let chunk_info = CipherAlgoChunkInfo { algo_name: algo_name, iv: iv };
            (chunk_header, CipherAlgoChunk(chunk_info))
        }
        "DATA" => {
            // The Data chunk is special in that we don't read its body - so, we specifically don't
            // want to consume the remaining input from the reader.
            (chunk_header, DataChunk)
        }
        _ => {
            consume_remaining(chunk_reader);
            (chunk_header, UnknownChunk)
        }
    }
}

fn read_next_chunk_with_data<R: Reader>(reader: &mut R) -> (ChunkHeader, Chunk, ~[u8]) {
    let mut chunk_data = reader.read_bytes(20);
    let (chunk_name, chunk_pos, chunk_remaining_len, chunk_flags) = {
        let chunk_header_reader = BufReader::new(chunk_data);
        let mut chunk_name = [0u8, ..4];
        read_full(reader, chunk_name);
        (chunk_name, reader.read_be_u64(), reader.read_be_u32() - 20, reader.read_be_u32())
    };
    chunk_data.grow_fn(chunk_remaining_len as uint, |_| { 0u8 });
    read_full(reader, chunk_data.mut_slice_from(20));
    let (chunk_header, chunk) = parse_chunk(
        &chunk_name,
        chunk_pos,
        chunk_remaining_len,
        chunk_flags,
        &mut BufReader::new(chunk_data.slice_from(20)));
    (chunk_header, chunk, chunk_data)
}

fn read_next_chunk<R: Reader>(reader: &mut R) -> (ChunkHeader, Chunk) {
    let mut chunk_name = [0u8, ..4];
    read_full(reader, chunk_name);
    let chunk_pos = reader.read_be_u64();
    let chunk_remaining_len = reader.read_be_u32() - 20;
    let chunk_flags = reader.read_be_u32();
    parse_chunk(&chunk_name, chunk_pos, chunk_remaining_len, chunk_flags, reader)
}

fn os_rand(size: uint) -> ~[u8] {
    let mut rng = OSRng::new();
    let vec: ~[u8] = rng.gen_vec(size);
    vec
}

fn gen_key(scrypt_params: &ScryptParams, pass: &str, salt: &[u8], size: uint) -> ~[u8] {
    let mut result = vec::from_elem(size, 0u8);
    scrypt::scrypt(pass.as_bytes(), salt, scrypt_params, result);
    result
}

fn parse_aes_key_size(ks: Option<&str>) -> Result<(KeySize, uint), &'static str> {
    match ks {
        Some("128") => Ok((KeySize128, 16)),
        Some("192") => Ok((KeySize192, 24)),
        Some("256") => Ok((KeySize256, 32)),
        _ => Err("Invalid or missing key size")
    }
}

fn parse_rc4_key_size(ks: Option<&str>) -> Result<uint, &'static str> {
    match ks {
        Some(key_size_str) => {
            match from_str::<uint>(key_size_str) {
                Some(x) => if x < 40 {
                    Err("Key size must be at least 40")
                } else if x > 2048 {
                    Err("Key size must be no more than 2048")
                } else if x % 8 != 0 {
                    Err("Key size must be a multiple of 8 bits")
                } else {
                    Ok(x / 8)
                },
                None => Err("Invalid key size")
            }
        }
        None => Err("Key size not specified")
    }
}

fn parse_padding(pad: Option<&str>) -> Result<StandardPadding, &'static str> {
    match pad {
        Some("NoPadding") => Ok(NoPadding),
        Some("PkcsPadding") => Ok(PkcsPadding),
        _ => Err("Invalid padding")
    }
}

// Parse the supplied algorithm name and return a suitable ~Encryptor
fn get_encryptor(
        algo_name: &str,
        pass: &str,
        salt: &[u8],
        scrypt_params: &ScryptParams) -> Result<(~Encryptor, Option<~[u8]>), &'static str> {
    let mut x = algo_name.split('/');
    match x.next() {
        Some("AES") => {
            let (key_size, ks) = try!(parse_aes_key_size(x.next()));
            match x.next() {
                Some("ECB") => {
                    let padding = try!(parse_padding(x.next()));
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok((aes::ecb_encryptor(key_size, key, padding), None))
                }
                Some("CBC") => {
                    let padding = try!(parse_padding(x.next()));
                    let iv = os_rand(16);
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok((aes::cbc_encryptor(key_size, key, iv, padding), Some(iv)))
                }
                Some("CTR") => {
                    let iv = os_rand(16);
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok((aes::ctr_enc(key_size, key, iv), Some(iv)))
                }
                _ => Err("Invalid mode")
            }
        }
        Some("RC4") => {
            let ks = try!(parse_rc4_key_size(x.next()));
            if x.next().is_some() {
                return Err("Invalid RC4 specification");
            }
            let key = gen_key(scrypt_params, pass, salt, ks);
            Ok((~Rc4::new(key) as ~Encryptor, None))
        }
        _ => Err("Invalid cipher")
    }
}

// Parse the supplied algorithm name and return a suitable ~Encryptor
fn get_mac(
        mac_name: &str,
        pass: &[u8],
        salt: &[u8],
        scrypt_params: &ScryptParams) -> Result<~Mac, &'static str> {
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
                _ => Err("Invalid HMAC Digest")
            }
        }
        _ => Err("Invalid mac")
    }
}

enum ReaderState {
    BeforeReading(~[u8]),
    BeforeDataChunk(~Mac, ~Decryptor, OwnedWriteBuffer),
    AfterDataChunk(~Mac, ~Decryptor, OwnedReadBuffer),
    DoneReading
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
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        loop {
            match self.state.take_unwrap() {
                BeforeReading(password) => {
                    // Read in the header
                    // TODO - get rid of allocation here
                    let magic = self.reader.read_bytes(8);
                    if magic.as_slice() != "RUSTCRPT".as_bytes() {
                        fail!("Invalid header");
                    }

                    let mut scrypt_chunk: Option<ScryptChunkInfo> = None;
                    let mut mac_chunk: Option<MacChunkInfo> = None;
                    let mut algo_chunk: Option<CipherAlgoChunkInfo> = None;

                    let mut chunk_data_items: ~[~[u8]] = ~[];

                    loop {
                        let (chunk_header, chunk, chunk_data) =
                            read_next_chunk_with_data(&mut self.reader);
                        chunk_data_items.push(chunk_data);

                        assert!(chunk_header.chunk_pos == self.next_chunk_pos);
                        self.next_chunk_pos += 1;

                        match chunk {
                            SCryptChunk(s) => scrypt_chunk = Some(s),
                            MacChunk(m) => mac_chunk = Some(m),
                            CipherAlgoChunk(c) => algo_chunk = Some(c),
                            DataChunk => { break; }
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
                    assert!(scrypt_chunk.is_some());
                    let scrypt_info = scrypt_chunk.take_unwrap();
                    assert!(mac_chunk.is_some());
                    let mac_info = mac_chunk.take_unwrap();
                    assert!(algo_chunk.is_some());
                    let algo_info = algo_chunk.take_unwrap();

                    // Construct the Mac

                    // Validate all of the headers we've already read

                    // Construct the Decryptor

                    // Begin decrypting now that we're all set up
                    self.state = None;
                }
                BeforeDataChunk(mac, dec, owb) => {
                    return None;
                }
                AfterDataChunk(mac, dec, owb) => {
                    return None;
                }
                DoneReading => {
                    return None;
                }
            }
        }
    }
}

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

fn main() {
    let tmp1 = [0u8, ..16];
    let reader = BufReader::new(tmp1);
    let hmac = Hmac::new(Sha256::new(), [0u8, ..16]);
    let enc = EcbEncryptor::new(AesSafe128Encryptor::new([0u8, ..16]), PkcsPadding);
    let cr = ClanReader::new(reader, hmac, enc);
}
*/
