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

macro_rules! try( ($x:expr) =>
    (
        match $x {
            Ok(y) => y,
            e @ Err(_) => return e
        }
    )
)

fn gen_key(pass: &str) -> ~[u8] {
    ~[]
}

fn parse_padding(pad: Option<&str>) -> Result<blockmodes::PkcsPadding, ()> {
    match pad {
        // TODO - Fix this!
        Some("NoPadding") => Ok(blockmodes::PkcsPadding),
        Some("PKCS") => Ok(blockmodes::PkcsPadding),
        _ => Err(())
    }
}

fn parse_key_size(ks: Option<&str>) -> Result<aes::KeySize, ()> {
    match ks {
        Some("128") => Ok(aes::KeySize128),
        Some("192") => Ok(aes::KeySize192),
        Some("256") => Ok(aes::KeySize256),
        _ => Err(())
    }
}

fn encrypt(
    pass: &str,
    algo_name: &str,
    input_file: &mut io::File,
    output_file: &mut io::File) -> Result<(), ()> {

    let mut x = algo_name.split('/');
    let encryptor: ~symmetriccipher::Encryptor = match x.next() {
        Some("AES") => {
            let key_size = try!(parse_key_size(x.next()));
            match x.next() {
                Some("ECB") => {
                    aes::ecb_encryptor(key_size, gen_key(pass), blockmodes::PkcsPadding)
                }
                Some("CBC") => {
                    aes::ecb_encryptor(key_size, gen_key(pass), blockmodes::PkcsPadding)
                }
                Some("CTR") => {
                    aes::ecb_encryptor(key_size, gen_key(pass), blockmodes::PkcsPadding)
                }
                _ => return Err(())
            }
        }
        Some("RC4") => match x.next() {
            Some(_) => return Err(()),
            None => rc4::Rc4::new(gen_key(pass))
        },
        _ => return Err(())
    };

    Ok(())
}

fn decrypt(
    pass: &str,
    algo_name: &str,
    input_file: &mut io::File,
    output_file: &mut io::File) -> Result<(), ()> {

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
        return;
    }

    let files_specified = !matches.opt_present("f") || !matches.opt_present("o");
    let ambiguous_mode = matches.opt_present("e") && matches.opt_present("d");

    if !files_specified || ambiguous_mode {
        print_usage(opts);
        os::set_exit_status(1);
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

    let op_result = if matches.opt_present("d") {
        encrypt(pass, algo_name, &mut input_file, &mut output_file)
    } else {
        decrypt(pass, algo_name, &mut input_file, &mut output_file)
    };

    match op_result {
        Ok(_) => os::set_exit_status(0),
        _ => {}
    }
}
