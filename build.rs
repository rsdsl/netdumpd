use std::env;

fn main() {
    // #[cfg(arch = "x86_64")]
    // println!("cargo:rustc-link-search=./libpcap/x86_64");

    // #[cfg(arch = "aarch64")]
    // println!("cargo:rustc-link-search=./libpcap/rpi");

    match env::var("CARGO_CFG_TARGET_ARCH").unwrap_or(String::new()).as_str() {
        "x86_64" => {
            println!("cargo:rustc-link-search=./libpcap/out/x86_64")
        }
        "aarch64" => {
            println!("cargo:rustc-link-search=./libpcap/out/rpi")
        }
        _ => println!("cargo:warning=Building for unsupported architecture, library search paths may be incorrect"),
    }

    println!("cargo:rustc-link-lib=static=pcap");
}
