// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[feature(macro_rules)];

extern mod crypto = "rust-crypto";
extern mod extra;

use crypto::aes;
use crypto::blockmodes;
use crypto::buffer;
use crypto::rc4;
use crypto::scrypt;
use crypto::symmetriccipher;

use extra::base64;
use extra::base64::ToBase64;
use extra::getopts;

use std::io;
use std::os;
use std::rand;
use std::rand::Rng;
use std::vec;

macro_rules! try( ($x:expr) =>
    (
        match $x {
            Ok(y) => y,
            Err(e) => return Err(e)
        }
    )
)

fn os_rand(size: uint) -> ~[u8] {
    let mut rng = rand::OSRng::new();
    let vec: ~[u8] = rng.gen_vec(size);
    vec
}

fn gen_key(pass: &str, salt: &[u8], size: uint) -> ~[u8] {
    let params = scrypt::ScryptParams::new(10, 1, 8);
    let mut result = vec::from_elem(size, 0u8);
    scrypt::scrypt(pass.as_bytes(), salt, &params, result);
    result
}

fn get_encryptor(
        algo_name: &str,
        pass: &str,
        salt: &[u8]) -> Result<(~symmetriccipher::Encryptor, Option<~[u8]>), &'static str> {
    fn parse_aes_key_size(ks: Option<&str>) -> Result<(aes::KeySize, uint), &'static str> {
        match ks {
            Some("128") => Ok((aes::KeySize128, 16)),
            Some("192") => Ok((aes::KeySize192, 24)),
            Some("256") => Ok((aes::KeySize256, 32)),
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

    fn parse_padding(pad: Option<&str>) -> Result<blockmodes::StandardPadding, &'static str> {
        match pad {
            Some("NoPadding") => Ok(blockmodes::NoPadding),
            Some("PkcsPadding") => Ok(blockmodes::PkcsPadding),
            _ => Err("Invalid padding")
        }
    }

    let mut x = algo_name.split('/');
    match x.next() {
        Some("AES") => {
            let (key_size, ks) = try!(parse_aes_key_size(x.next()));
            match x.next() {
                Some("ECB") => {
                    let padding = try!(parse_padding(x.next()));
                    let key = gen_key(pass, salt, ks);
                    Ok((aes::ecb_encryptor(key_size, key, padding), None))
                }
                Some("CBC") => {
                    let padding = try!(parse_padding(x.next()));
                    let iv = os_rand(16);
                    let key = gen_key(pass, salt, ks);
                    Ok((aes::cbc_encryptor(key_size, key, iv, padding), Some(iv)))
                }
                Some("CTR") => {
                    let iv = os_rand(16);
                    let key = gen_key(pass, salt, ks);
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
            let key = gen_key(pass, salt, ks);
            Ok((~rc4::Rc4::new(key) as ~symmetriccipher::Encryptor, None))
        }
        _ => Err("Invalid cipher")
    }
}

fn encrypt(
        pass: &str,
        algo_name: &str,
        input_file: &mut io::File,
        output_file: &mut io::File) -> Result<(), &'static str> {
    let enc_salt = os_rand(16);
    let mac_salt = os_rand(16);
    let (encryptor, iv) = try!(get_encryptor(algo_name, pass, enc_salt));

    // Format:
    // MAGIC         - 8 bytes             - "RUSTCRPT"
    // VERSION       - U32                 - Only supports version 1 right now
    // HEADER_LEN    - U32                 - Length of header (up to ENC_DATA_LEN, including MAGIC and VERSION)
    // ALGO_NAME_LEN - U32                 - length of next field
    // ALGO_NAME     - ALGO_NAME_LEN bytes - name of algorithm used for encryption
    // SCRIPT_LOG_N  - U8
    // SCRIPT_R      - U32
    // SCRIPT_P      - U32
    // ENC_SALT_LEN  - U32                 - length of next field
    // ENC_SALT      - ENC_SALT_LEN bytes  - encryption salt value
    // MAC_SALT_LEN  - U32                 - length of next field
    // MAC_SALT      - ENC_SALT_LEN bytes  - encryption salt value
    // IV_LEN        - U32                 - length of next field
    // IV            - IV_LEN bytes        - IV
    // ENC_DATA_LEN  - U32
    // DATA          - ENC_DATA_LEN bytes
    // MAC_LEN       - length of next field
    // MAC           - MAC_LEN bytes

    Ok(())
}

fn decrypt(
        pass: &str,
        algo_name: &str,
        input_file: &mut io::File,
        output_file: &mut io::File) -> Result<(), &'static str> {

    Ok(())
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
        getopts::groups::optopt("a", "algorithm", "Algorithm to use (Default: AES/128/CBC)", "")
    ];

    let matches = match getopts::groups::getopts(args.tail(), opts) {
        Ok(m) => m,
        Err(f) => {
            println!("{}", f.to_err_msg());
            os::set_exit_status(1);
            return;
        }
    };

    if matches.opt_present("h") {
        print_usage(opts);
        os::set_exit_status(0);
        return;
    }

    let files_specified = matches.opt_present("f") && matches.opt_present("o");
    let ambiguous_mode = matches.opt_present("e") && matches.opt_present("d");

    if !files_specified || ambiguous_mode {
        print_usage(opts);
        return;
    }

    let mut input_file = match io::File::open(&Path::new(matches.opt_str("f").unwrap())) {
        Some(f) => f,
        None => {
            println!("Failed to open input file.");
            return;
        }
    };

    let mut output_file = match io::File::create(&Path::new(matches.opt_str("o").unwrap())) {
        Some(f) => f,
        None => {
            println!("Failed to open output file.");
            return;
        }
    };

    let algo_name = match matches.opt_str("a") {
        Some(x) => x,
        None => ~"AES128/CBC"
    };

    io::stdout().write(bytes!("Please type the password: "));
    let mut stdin = io::BufferedReader::new(io::stdin());
    let pass = match stdin.read_line() {
        Some(x) => x,
        None => fail!("Couldn't read password.")
    };

    let op_result = if !matches.opt_present("d") {
        encrypt(pass, algo_name, &mut input_file, &mut output_file)
    } else {
        decrypt(pass, algo_name, &mut input_file, &mut output_file)
    };

    match op_result {
        Ok(_) => os::set_exit_status(0),
        Err(msg) => println!("Operation failed: {}", msg)
    }
}
