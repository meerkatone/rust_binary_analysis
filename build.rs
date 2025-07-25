use std::env;

fn main() {
    // This build script will locate binaryninjacore on your system
    // The binaryninja crate handles the linking automatically when using the git dependency
    
    // Set up any additional environment variables or build configuration if needed
    if let Ok(binja_path) = env::var("BINJA_DIR") {
        println!("cargo:rustc-link-search=native={}", binja_path);
    }
}