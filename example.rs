// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
 * A Simple Encryption / Decryption utility.
 *
 * The format of the files produced is:
 * Field         - Length              - Description
 * MAGIC         - 8 bytes             - "RUSTCRPT"
 * VERSION       - U32                 - Only supports version 1 right now
 * HEADER_LEN    - U32                 - Length of header (up to ENC_DATA_LEN, including MAGIC and
 *                                       VERSION)
 * ALGO_NAME_LEN - U32                 - length of next field
 * ALGO_NAME     - ALGO_NAME_LEN bytes - name of algorithm used for encryption
 * SCRIPT_LOG_N  - U8                  - The log of the N parameter to SCrypt
 * SCRIPT_R      - U32                 - the R parameter to SCrypt
 * SCRIPT_P      - U32                 - the P parameter to SCrypt
 * ENC_SALT_LEN  - U32                 - length of next field
 * ENC_SALT      - ENC_SALT_LEN bytes  - encryption salt value
 * MAC_SALT_LEN  - U32                 - length of next field
 * MAC_SALT      - ENC_SALT_LEN bytes  - encryption salt value
 * IV_LEN        - U32                 - length of next field
 * IV            - IV_LEN bytes        - IV
 * DATA          - Everything to MAC   - The encrypted message
 * MAC           - Always 32 bytes     - The HMAC-Sha256 of the entire message, including the header
 */

#[feature(macro_rules)];

extern mod crypto = "rust-crypto";
extern mod extra;

use crypto::aes;
use crypto::aes::{KeySize, KeySize128, KeySize192, KeySize256};
use crypto::blockmodes::{NoPadding, PkcsPadding, StandardPadding};
use crypto::buffer::{BufferUnderflow, BufferOverflow, ReadBuffer, RefReadBuffer, RefWriteBuffer,
    WriteBuffer};
use crypto::hmac::Hmac;
use crypto::rc4::Rc4;
use crypto::mac::{Mac, MacResult};
use crypto::scrypt;
use crypto::scrypt::ScryptParams;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::{Decryptor, Encryptor};

use extra::getopts;

use std::io;
use std::io::{BufferedReader, BufReader, File};
use std::io::fs;
use std::os;
use std::rand::{OSRng, Rng};
use std::str;
use std::vec;

// TODO - Would this fit in better as a utility class in rust-crypto itself?
struct MacWriter<'a, W, M> {
    priv writer: &'a mut W,
    priv mac: &'a mut M
}

impl <'a, W: Writer, M: Mac> MacWriter<'a, W, M> {
    fn new(writer: &'a mut W, mac: &'a mut M) -> MacWriter<'a, W, M> {
        MacWriter {
            writer: writer,
            mac: mac
        }
    }
}

impl <'a, W: Writer, M: Mac> Writer for MacWriter<'a, W, M> {
    fn write(&mut self, buff: &[u8]) {
        self.mac.input(buff);
        self.writer.write(buff);
    }
}

macro_rules! try( ($x:expr) =>
    (
        match $x {
            Ok(y) => y,
            Err(e) => return Err(e)
        }
    )
)

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

// Parse the supplied algorithm name and return a suitable ~Decryptor
fn get_decryptor(
        algo_name: &str,
        pass: &str,
        salt: &[u8],
        scrypt_params: &ScryptParams,
        iv: &[u8]) -> Result<~Decryptor, &'static str> {
    let mut x = algo_name.split('/');
    match x.next() {
        Some("AES") => {
            let (key_size, ks) = try!(parse_aes_key_size(x.next()));
            match x.next() {
                Some("ECB") => {
                    let padding = try!(parse_padding(x.next()));
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok(aes::ecb_decryptor(key_size, key, padding))
                }
                Some("CBC") => {
                    let padding = try!(parse_padding(x.next()));
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok(aes::cbc_decryptor(key_size, key, iv, padding))
                }
                Some("CTR") => {
                    let key = gen_key(scrypt_params, pass, salt, ks);
                    Ok(aes::ctr_dec(key_size, key, iv))
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
            Ok(~Rc4::new(key) as ~Decryptor)
        }
        _ => Err("Invalid cipher")
    }
}

// Encrypt all of the remaining bytes from input and write them to output. The output is presumed to
// already be wrapped in a MacWriter, so, anything written to there is already being passed to the
// Mac function as well.
fn do_encrypt<R: Reader, W: Writer>(
        input: &mut R,
        output: &mut W,
        mut enc: ~Encryptor) -> Result<(), &'static str> {
    let mut buff_in = [0u8, ..4096];
    let mut buff_out = [0u8, ..4096];
    let mut wout = RefWriteBuffer::new(buff_out);
    loop {
        match input.read(buff_in) {
            Some(cnt) => {
                let mut rin = RefReadBuffer::new(buff_in.slice_to(cnt));

                loop {
                    match enc.encrypt(&mut rin, &mut wout, false) {
                        Ok(BufferUnderflow) => {
                            // TODO - its way too easy to not call take_read_buffer() on this
                            // which results in an infinite loop. Rename that method?
                            output.write(wout.take_read_buffer().take_remaining());
                            break;
                        }
                        Ok(BufferOverflow) => output.write(wout.take_read_buffer().take_remaining()),
                        Err(_) => return Err("Encryption failed")
                    }
                }
            }
            None => {
                loop {
                    match enc.encrypt(&mut RefReadBuffer::new(&[]), &mut wout, true) {
                        Ok(BufferUnderflow) => {
                            output.write(wout.take_read_buffer().take_remaining());
                            return Ok(());
                        }
                        Ok(BufferOverflow) => output.write(wout.take_read_buffer().take_remaining()),
                        Err(_) => return Err("Encryption failed")
                    }
                }
            }
        }
    }
}

// Decrypt all of the remaining data from input. The last 32 bytes of input are the Mac code -
// wrap those bytes in a MacResult and return it. All bytes before the last 32, are passed into the
// Mac function before being decrypted.
fn do_decrypt<R: Reader, W: Writer, M: Mac>(
        input: &mut R,
        output: &mut W,
        dec: &mut ~Decryptor,
        mac: &mut M) -> Result<MacResult, &'static str> {
    // We need to process all remaining input, except for the last 32 bytes which represent the
    // Mac code.
    // Algorithm:
    // 0. Make sure that buff_in_1 and buff_in_2 are both bigger than the mac size.
    // 1. Read into buff_in_1 until it is full. If EOF occurs first, process everything but the last
    //    32 bytes.
    // 2. Read into buff_in_2 until it is full. Once its full, process buff_in_1. Then, swap
    //    buff_in_1 and buff_in_2. Then, repeat this step. Once we get to EOF, we know that the Mac
    //    must either be full in buff_in_1 (up until the 2nd), split across the two, or fully in
    //    buff_in_2. Process everything except the Mac and then return the Mac value.

    let mut buff_in_1 = &mut [0u8, ..4096];
    let mut buff_in_2 = &mut [0u8, ..4096];
    let mut buff_out = [0u8, ..4096];

    assert!(buff_in_1.len() == buff_in_2.len());
    assert!(buff_in_1.len() > 32);

    // Keep reading until the specified vector is full or until EOF, then return the number of bytes
    // actually read.
    fn read_all<R: Reader>(reader: &mut R, buff: &mut [u8]) -> uint {
        let mut pos = 0;
        loop {
            match reader.read(buff.mut_slice_from(pos)) {
                Some(cnt) => {
                    pos += cnt;
                    if pos == buff.len() {
                        return pos;
                    }
                }
                None => return pos
            }
        }
    }

    // Decrypt the entire input buffer and write it to the output
    let decrypt_full_input = |buff_in: &[u8], eof: bool | -> Result<(), &'static str> {
        let mut bin = RefReadBuffer::new(buff_in);
        loop {
            let mut wout = RefWriteBuffer::new(buff_out);
            match dec.decrypt(&mut bin, &mut wout, eof) {
                Ok(BufferUnderflow) => {
                    output.write(wout.take_read_buffer().take_remaining());
                    return Ok(());
                }
                Ok(BufferOverflow) => output.write(wout.take_read_buffer().take_remaining()),
                Err(_) => return Err("Decryption error")
            }
        }
    };

    match read_all(input, buff_in_1.as_mut_slice()) {
        cnt => {
            if cnt < 32 {
                return Err("EOF");
            } else if cnt < buff_in_1.len() {
                mac.input(buff_in_1.slice_to(cnt - 32));
                try!(decrypt_full_input(buff_in_1.slice_to(cnt - 32), true));
                return Ok(MacResult::new(buff_in_1.slice(cnt - 32, cnt)));
            } else {
                // nothing to do. Go on to processing buff_in_2
            }
        }
    }

    loop {
        let cnt = read_all(input, buff_in_2.as_mut_slice());
        if cnt < buff_in_2.len() {
            if cnt < 32 {
                // The Mac is split across the end of buff_in_1 and the beggining of
                // buff_in_2
                let crypt_len = buff_in_1.len() - 32 + cnt;
                mac.input(buff_in_1.slice_to(crypt_len));
                try!(decrypt_full_input(buff_in_1.slice_to(crypt_len), true));
                let mut code = ~[];
                code.push_all(buff_in_1.slice_from(crypt_len));
                code.push_all(buff_in_2.slice_to(cnt));
                return Ok(MacResult::new_from_owned(code));
            } else {
                // The Mac is completely contained in buff_in_2
                mac.input(buff_in_1.as_slice());
                mac.input(buff_in_2.slice_to(cnt - 32));
                try!(decrypt_full_input(buff_in_1.as_slice(), false));
                try!(decrypt_full_input(buff_in_2.slice_to(cnt - 32), true));
                return Ok(MacResult::new(buff_in_2.slice(cnt - 32, cnt)));
            }
        } else {
            // Process buff_in_1
            mac.input(buff_in_1.as_slice());
            try!(decrypt_full_input(buff_in_1.as_slice(), false));
            std::util::swap(&mut buff_in_1, &mut buff_in_2);
        }
    }
}

fn encrypt<R: Reader, W: Writer>(
        pass: &str,
        algo_name: &str,
        input: &mut R,
        output: &mut W) -> Result<(), &'static str> {
    let default_scrypt_log_n = 14;
    let default_scrypt_r = 8;
    let default_scrypt_p = 1;
    let scrypt_params = ScryptParams::new(default_scrypt_log_n, default_scrypt_r, default_scrypt_p);

    let enc_salt = os_rand(16);
    let mac_salt = os_rand(16);
    let (enc, iv) = try!(get_encryptor(algo_name, pass, enc_salt, &scrypt_params));

    let iv_len = match iv {
        Some(ref iv) => iv.len(),
        None => 0
    };

    let mac_key = gen_key(&scrypt_params, pass, mac_salt, 64);
    let mut mac = Hmac::new(Sha256::new(), mac_key);
    {
        // we re-bind output until the end of this block so that we can make sure that any values
        // output will be passed to the Mac function.
        let mut output = MacWriter::new(output, &mut mac);

        // TODO - algo_name.len() returns characters, not bytes. Does this need to be changed to
        // support non-utf8 algorithm names?
        let header_len = (41 + algo_name.len() + enc_salt.len() + mac_salt.len() + iv_len) as u32;

        output.write_str("RUSTCRPT");
        output.write_be_u32(1);
        output.write_be_u32(header_len);

        output.write_be_u32(algo_name.len() as u32);
        output.write_str(algo_name);

        output.write_u8(default_scrypt_log_n);
        output.write_be_u32(default_scrypt_r);
        output.write_be_u32(default_scrypt_p);

        output.write_be_u32(enc_salt.len() as u32);
        output.write(enc_salt);

        output.write_be_u32(mac_salt.len() as u32);
        output.write(mac_salt);

        match iv {
            Some(ref iv) => {
                output.write_be_u32(iv.len() as u32);
                output.write(iv.as_slice());
            }
            None => output.write_be_u32(0)
        }

        try!(do_encrypt(input, &mut output, enc));
    }

    output.write(mac.result().code());

    Ok(())
}

fn decrypt<R: Reader, W: Writer>(
        pass: &str,
        input: &mut R,
        output: &mut W) -> Result<(), &'static str> {
    // Read the first 3 fields of the header which are of a fixed length.
    // We have to save this data so we can pass it to the Mac function later.
    // Unfortunately, we can't pass this data to the Mac function until we've read most of the
    // header since we need to know whats in the header to construct the Mac function.
    let header1 = input.read_bytes(16);

    let mut header1_reader = BufReader::new(header1);

    let magic = header1_reader.read_bytes(8);
    if magic.as_slice() != "RUSTCRPT".as_bytes() {
        return Err("Invalid MAGIC value.");
    }

    let version = header1_reader.read_be_u32();
    if version != 1 {
        return Err("Unsupported version");
    }

    let header_len = header1_reader.read_be_u32();

    // Read the rest of the header - we still can't construct the Mac function, so we need to save
    // this part of the header for passing to the Mac later as well.
    let header2 = input.read_bytes((header_len - 16) as uint);

    let mut header2_reader = BufReader::new(header2);

    // Read a length-prefixed field
    let read_field = || -> ~[u8] {
        let field_len = header2_reader.read_be_u32() as uint;
        header2_reader.read_bytes(field_len)
    };

    let algo_name = match str::from_utf8_owned(read_field()) {
        Some(s) => s,
        None => return Err("Invalid algorithm name - not valid utf-8")
    };

    let scrypt_log_n = header2_reader.read_u8();
    let scrypt_r = header2_reader.read_be_u32();
    let scrypt_p = header2_reader.read_be_u32();

    let scrypt_params = ScryptParams::new(scrypt_log_n, scrypt_r, scrypt_p);

    let enc_salt = read_field();
    let mac_salt = read_field();
    let iv = read_field();

    // Its possible that their are more header fields, but we can ignore them. If for some reason we
    // can't ignore them, then the VERSION field in the header should have been incremented.

    let mac_key = gen_key(&scrypt_params, pass, mac_salt, 64);
    let mut mac = Hmac::new(Sha256::new(), mac_key);
    mac.input(header1);
    mac.input(header2);

    let mut dec = try!(get_decryptor(algo_name, pass, enc_salt, &scrypt_params, iv));

    // The return value of do_decrypt() is the Mac value from the message we are decrypting, not the
    // calculated Mac value.
    let mac_code = try!(do_decrypt(input, output, &mut dec, &mut mac));

    if mac_code == mac.result() {
        Ok(())
    } else {
        Err("Mac code not valid")
    }
}

fn print_usage(opts: &[getopts::groups::OptGroup]) {
    println!("{}", getopts::groups::usage("A simple encryption utility.", opts));
}

fn main() {
    // report failure by default
    os::set_exit_status(1);

    let args = os::args();

    let opts = ~[
        getopts::groups::optflag("h", "help", "Display help"),
        getopts::groups::optopt("f", "file", "Input file", ""),
        getopts::groups::optopt("o", "out", "Output file", ""),
        getopts::groups::optflag("e", "encrypt", "Encrypt (Default)"),
        getopts::groups::optflag("d", "decrypt", "Decrypt"),
        getopts::groups::optopt(
            "a",
            "algorithm",
            "Algorithm to use (Default: AES/128/CBC/PkcsPadding). Only valid for encryption.",
            "")
    ];

    let matches = match getopts::groups::getopts(args.tail(), opts) {
        Ok(m) => m,
        Err(f) => {
            println!("{}", f.to_err_msg());
            return;
        }
    };

    if matches.opt_present("h") {
        print_usage(opts);
        os::set_exit_status(0);
        return;
    }

    // Check for missing options and logical inconsistencies in the command line options
    let files_specified = matches.opt_present("f") && matches.opt_present("o");
    let ambiguous_mode = matches.opt_present("e") && matches.opt_present("d");
    let decrypt_and_algo = matches.opt_present("d") && matches.opt_present("a");
    if !files_specified || ambiguous_mode || decrypt_and_algo {
        print_usage(opts);
        return;
    }

    let mut input_file = match File::open(&Path::new(matches.opt_str("f").unwrap())) {
        Some(f) => f,
        None => {
            println!("Failed to open input file.");
            return;
        }
    };

    let out_path = Path::new(matches.opt_str("o").unwrap());
    let mut output_file = match File::create(&out_path) {
        Some(f) => f,
        None => {
            println!("Failed to open output file.");
            return;
        }
    };

    let algo_name = match matches.opt_str("a") {
        Some(x) => x,
        None => ~"AES/128/CBC/PkcsPadding"
    };

    // FIXME? - print!() doesn't flush the string to STDOUT before read_line(), which seems like a
    // bug in Rust.
    io::stdout().write(bytes!("Please type the password: "));
    let mut stdin = BufferedReader::new(io::stdin());
    // TODO - It would be better to disable echoing before doing this
    let pass = match stdin.read_line() {
        Some(x) => x,
        None => fail!("Couldn't read password.")
    };

    let op_result = if !matches.opt_present("d") {
        encrypt(pass, algo_name, &mut input_file, &mut output_file)
    } else {
        decrypt(pass, &mut input_file, &mut output_file)
    };

    match op_result {
        Ok(_) => os::set_exit_status(0),
        Err(msg) => {
            fs::unlink(&out_path);
            println!("Operation failed: {}", msg)
        }
    }
}
