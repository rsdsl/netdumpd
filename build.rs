fn main() {
    println!("{:?}", std::env::var("LIBPCAP_LIBDIR"));
    println!("cargo:rustc-link-arg=-lc");
    println!("cargo:rustc-link-arg=-lnl-3");
    println!("cargo:rustc-link-arg=-lnl-genl-3");
}
