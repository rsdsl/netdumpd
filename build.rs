use std::env;

fn main() {
    match env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default().as_str() {
        "x86_64" => {
            println!("cargo:rustc-link-search=./lib/libpcap/out/x86_64")
        }
        "aarch64" => {
            println!("cargo:rustc-link-search=./lib/libpcap/out/rpi")
        }
        _ => println!("cargo:warning=Building for unsupported architecture, library search paths may be incorrect"),
    }

    println!("cargo:rustc-link-lib=static=pcap");
}
