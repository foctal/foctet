fn main() {
    let target = std::env::var("TARGET").expect("Cargo provides TARGET");
    if target.ends_with("windows-msvc") {
        // The entry point lives in libFuzzer's static library. With no Rust
        // main, MSVC needs the subsystem to select and link the console CRT.
        println!("cargo:rustc-link-arg-bins=/SUBSYSTEM:CONSOLE");
    }
}
