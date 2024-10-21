use clap::{
    arg, builder::PossibleValue, command, value_parser, Arg, ArgAction, ArgMatches, ValueEnum,
};
use colorful::Colorful;
use sha3::Digest;
use spinoff::{spinners, Color, Spinner};
use std::fmt::Write;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

struct ColorScheme(u8, u8, u8, u8, u8, u8);

const COLOR_SCHEMES: [ColorScheme; 16] = [
    ColorScheme(32, 0, 224, 223, 255, 31),
    ColorScheme(254, 24, 0, 254, 255, 0),
    ColorScheme(0, 240, 240, 255, 15, 15),
    ColorScheme(32, 0, 224, 0, 255, 255),
    ColorScheme(124, 31, 248, 248, 124, 31),
    ColorScheme(32, 128, 32, 223, 127, 223),
    ColorScheme(248, 0, 0, 0, 248, 0),
    ColorScheme(192, 16, 192, 192, 192, 192),
    ColorScheme(127, 254, 127, 128, 1, 128),
    ColorScheme(240, 64, 160, 15, 0, 160),
    ColorScheme(192, 248, 0, 248, 64, 192),
    ColorScheme(0, 128, 240, 255, 0, 0),
    ColorScheme(248, 93, 0, 64, 93, 93),
    ColorScheme(64, 0, 0, 0, 191, 191),
    ColorScheme(128, 24, 0, 0, 128, 255),
    ColorScheme(64, 208, 0, 64, 64, 255),
];

//TODO: Cyclic redundancy check (CRC32) as another 'low end' solution

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Algorithm {
    Md4,
    Md5,
    Blake2s256,
    Blake2b512,
    Blake3,
    Ripemd128,
    Ripemd160,
    Ripemd256,
    Ripemd320,
    Sha1,
    Sha2,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Keccak224,
    Keccak256,
    // Keccak256Full,
    Keccak384,
    Keccak512,
    // Skein256,
    // Skein512,
    // Skein1024,
    // Sm3,
    Tiger,
    Tiger2,
    // Whirlpool,
}

// Can also be derived with feature flag `derive`
impl ValueEnum for Algorithm {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Algorithm::Md4,
            Algorithm::Md5,
            Algorithm::Blake2s256,
            Algorithm::Blake2b512,
            Algorithm::Blake3,
            Algorithm::Ripemd128,
            Algorithm::Ripemd160,
            Algorithm::Ripemd256,
            Algorithm::Ripemd320,
            Algorithm::Sha1,
            Algorithm::Sha2,
            Algorithm::Sha224,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
            Algorithm::Sha512_224,
            Algorithm::Sha512_256,
            Algorithm::Sha3,
            Algorithm::Sha3_224,
            Algorithm::Sha3_256,
            Algorithm::Sha3_384,
            Algorithm::Sha3_512,
            Algorithm::Keccak224,
            Algorithm::Keccak256,
            // Algorithm::Keccak256Full,
            Algorithm::Keccak384,
            Algorithm::Keccak512,
            // Algorithm::Skein256,
            // Algorithm::Skein512,
            // Algorithm::Skein1024,
            // Algorithm::Sm3,
            Algorithm::Tiger,
            Algorithm::Tiger2,
            // Algorithm::Whirlpool,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<PossibleValue> {
        Some(match self {
            Algorithm::Md4 => PossibleValue::new("md4")
                .help("Designed for 32-bit machines - fast but insecure due to many collisions"),
            Algorithm::Md5 => PossibleValue::new("md5").help(
                "Designed for 32-bit machines - no longer considered cryptographically secure",
            ),
            Algorithm::Blake2s256 => PossibleValue::new("blake2s256").help(""),
            Algorithm::Blake2b512 => PossibleValue::new("blake2b512").help("Very fast and secure"),
            Algorithm::Blake3 => {
                PossibleValue::new("blake3").help("Very fast and secure [DEFAULT]")
            }
            Algorithm::Ripemd128 => PossibleValue::new("ripemd128").help(""),
            Algorithm::Ripemd160 => PossibleValue::new("ripemd160").help(""),
            Algorithm::Ripemd256 => PossibleValue::new("ripemd256").help(""),
            Algorithm::Ripemd320 => PossibleValue::new("ripemd320").help(""),
            Algorithm::Sha1 => {
                PossibleValue::new("sha1").help("no longer considered cryptographically secure")
            }
            Algorithm::Sha2 => PossibleValue::new("sha2").help("Alias for sha256"),
            Algorithm::Sha224 => PossibleValue::new("sha224").help(""),
            Algorithm::Sha256 => PossibleValue::new("sha256").help("Not that fast, but secure"),
            Algorithm::Sha384 => PossibleValue::new("sha384").help(""),
            Algorithm::Sha512 => PossibleValue::new("sha512").help(""),
            Algorithm::Sha512_224 => PossibleValue::new("sha512_224").help(""),
            Algorithm::Sha512_256 => PossibleValue::new("sha512_256").help(""),
            Algorithm::Sha3 => PossibleValue::new("sha3").help("Alias for sha3_256"),
            Algorithm::Sha3_224 => PossibleValue::new("sha3_224").help(""),
            Algorithm::Sha3_256 => PossibleValue::new("sha3_256").help(""),
            Algorithm::Sha3_384 => PossibleValue::new("sha3_384").help(""),
            Algorithm::Sha3_512 => PossibleValue::new("sha3_512").help(""),
            Algorithm::Keccak224 => PossibleValue::new("keccak224").help(""),
            Algorithm::Keccak256 => PossibleValue::new("keccak256").help(""),
            // Algorithm::Keccak256Full => PossibleValue::new("keccak256full").help(""),
            Algorithm::Keccak384 => PossibleValue::new("keccak384").help(""),
            Algorithm::Keccak512 => PossibleValue::new("keccak512").help(""),
            // Algorithm::Skein256 => PossibleValue::new("skein256").help(""),
            // Algorithm::Skein512 => PossibleValue::new("skein512").help(""),
            // Algorithm::Skein1024 => PossibleValue::new("skein1024").help(""),
            // Algorithm::Sm3 => PossibleValue::new("sm3").help(""),
            Algorithm::Tiger => PossibleValue::new("tiger").help("192 bit - Fast and still secure"),
            Algorithm::Tiger2 => PossibleValue::new("tiger2")
                .help("Designed for 64-bit machines - Fast and still secure"),
            // Algorithm::Whirlpool => PossibleValue::new("whirlpool").help(""),
        })
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

impl std::str::FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for variant in Self::value_variants() {
            if variant.to_possible_value().unwrap().matches(s, false) {
                return Ok(*variant);
            }
        }
        Err(format!("invalid variant: {s}"))
    }
}

// impl sha3::Digest for blake3::Hash {
//
//     fn finalize(self) -> sha3::digest::Output<Self> {
//         self.final_output().root_hash().as_bytes()
//     }
// }

fn main() {
    let matches: ArgMatches = command!()
        .author("Maurice-Jörg Nießen <info@mjniessen.com>\n")
        .arg(arg!(<FILE>).value_parser(value_parser!(PathBuf)))
        .arg(
            Arg::new("ALGORITHM")
                .long("algorithm")
                .alias("algo")
                .default_value("blake3")
                .help("Use <ALGORITHM> for hash calculating")
                .value_parser(value_parser!(Algorithm)),
        )
        .arg(
            Arg::new("CODE")
                .short('c')
                .long("code")
                .action(ArgAction::SetTrue)
                .help("Print code in hexadecimal"),
        )
        .arg(
            Arg::new("QUIET")
                .short('q')
                .long("quiet")
                .action(ArgAction::SetTrue)
                .help("No warnings, hints or any additional information"),
        )
        .get_matches();

    let input = matches.get_one::<PathBuf>("FILE").unwrap();
    let algorithm = matches
        .get_one::<Algorithm>("ALGORITHM")
        .unwrap()
        .to_string();
    multi_digest(
        &algorithm[..],
        input,
        matches.get_flag("CODE"),
        matches.get_flag("QUIET"),
    );
}

fn print_blocks(digest: &[u8]) {
    let mut blockstr = String::new();
    let mut colorindex = 0;
    let blocks: [char; 16] = [
        ' ', '▗', '▖', '▘', '▝', '▐', '▞', '▄', '▚', '▌', '▀', '▜', '▙', '▛', '▟', '█',
    ];
    for x in digest {
        let b1 = x >> 4;
        let b2 = x & 0x0F;
        colorindex += x;
        let a = format!("{}{}", blocks[b1 as usize], blocks[b2 as usize]);
        blockstr.push_str(&a);
    }

    // TODO: better code for mapping color scheme
    let colors = match colorindex % 16 {
        0 => &COLOR_SCHEMES[0],
        1 => &COLOR_SCHEMES[1],
        2 => &COLOR_SCHEMES[2],
        3 => &COLOR_SCHEMES[3],
        4 => &COLOR_SCHEMES[4],
        5 => &COLOR_SCHEMES[5],
        6 => &COLOR_SCHEMES[6],
        7 => &COLOR_SCHEMES[7],
        8 => &COLOR_SCHEMES[8],
        9 => &COLOR_SCHEMES[9],
        10 => &COLOR_SCHEMES[10],
        11 => &COLOR_SCHEMES[11],
        12 => &COLOR_SCHEMES[12],
        13 => &COLOR_SCHEMES[13],
        14 => &COLOR_SCHEMES[14],
        15 => &COLOR_SCHEMES[15],
        _ => &ColorScheme(0, 0, 0, 0, 0, 0),
    };
    println!(
        "{}",
        blockstr
            .rgb(colors.0, colors.1, colors.2)
            .bg_rgb(colors.3, colors.4, colors.5)
    );
}

// digest functions -- {{{
fn multi_digest(hasher: &str, path: &PathBuf, showcode: bool, quiet: bool) {
    let mut spinner = Spinner::new(spinners::Dots, "Calculating hash...", Color::Green);
    if quiet {
        spinner.clear();
    }
    // TODO: match on <Algorithm> instead of <String>
    let hash = match hasher {
        "md4" => get_digest::<md4::Md4>(path),
        "md5" => get_digest::<md5::Md5>(path),
        "blake2s256" => get_digest::<blake2::Blake2s256>(path),
        "blake2b512" => get_digest::<blake2::Blake2b512>(path),
        "blake3" => get_digest_blake3(path),
        "ripemd128" => get_digest::<ripemd::Ripemd128>(path),
        "ripemd160" => get_digest::<ripemd::Ripemd160>(path),
        "ripemd256" => get_digest::<ripemd::Ripemd256>(path),
        "ripemd320" => get_digest::<ripemd::Ripemd320>(path),
        "sha1" => get_digest::<sha1::Sha1>(path),
        "sha2" => get_digest::<sha2::Sha256>(path),
        "sha224" => get_digest::<sha2::Sha224>(path),
        "sha256" => get_digest::<sha2::Sha256>(path),
        "sha384" => get_digest::<sha2::Sha384>(path),
        "sha512" => get_digest::<sha2::Sha512>(path),
        "Sha512_224" => get_digest::<sha2::Sha512_224>(path),
        "sha512_256" => get_digest::<sha2::Sha512_256>(path),
        "sha3" => get_digest::<sha3::Sha3_256>(path),
        "sha3_224" => get_digest::<sha3::Sha3_224>(path),
        "sha3_256" => get_digest::<sha3::Sha3_256>(path),
        "sha3_384" => get_digest::<sha3::Sha3_384>(path),
        "sha3_512" => get_digest::<sha3::Sha3_512>(path),
        "keccak224" => get_digest::<sha3::Keccak224>(path),
        "keccak256" => get_digest::<sha3::Keccak256>(path),
        // "keccak256full" => get_digest::<sha3::Keccak256Full>(path),
        "keccak384" => get_digest::<sha3::Keccak384>(path),
        "keccak512" => get_digest::<sha3::Keccak512>(path),
        // "skein256" => get_digest::<skein::Skein256>(path),
        // "skein512" => get_digest::<skein::Skein512>(path),
        // "skein1024" => get_digest::<skein::Skein1024>(path),
        // "sm3" => get_digest::<sm3::Sm3>(path),
        "tiger" => get_digest::<tiger::Tiger>(path),
        "tiger2" => get_digest::<tiger::Tiger2>(path),
        // "whirlpool" => get_digest::<whirlpool::Whirlpool>(path),
        _ => get_digest_blake3(path),
    };

    if !quiet {
        spinner.clear();
    }

    print_blocks(&hash);

    if showcode {
        print_digest(&hash);
    }
}

#[allow(dead_code)]
fn print_digest(digest: &[u8]) {
    println!(
        "{}",
        digest.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02x}");
            output
        })
    );
}

fn get_digest_blake3(path: &PathBuf) -> Vec<u8> {
    let input = File::open(path).unwrap();
    let mut reader = BufReader::new(input);

    let digest = {
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0; 1024];
        loop {
            let count = reader.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    // TODO: impl to_vec()
    // let mut digest_vec = digest.as_bytes().to_vec();
    // digest_vec.remove(0);
    // digest_vec
    digest.as_bytes().to_vec()
}

fn get_digest<T: Digest>(path: &PathBuf) -> Vec<u8> {
    let input = File::open(path).unwrap();
    let mut reader = BufReader::new(input);

    let digest = {
        let mut hasher = T::new();
        let mut buffer = [0; 1024];
        loop {
            let count = reader.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    digest.to_vec()
}
// }}}

// vim: ft=rust ts=2 sw=2 sts=2 fileencoding=utf-8 foldmethod=marker
