extern crate cc;

fn main() {
    println!("cargo:rerun-if-changed=vendor/sfm/src/main.c");

    cc::Build::new()
        .file("vendor/sfm/src/main.c")
        .compile("sfm");

    println!("cargo:rustc-link-lib=dylib=ssl");
    println!("cargo:rustc-link-lib=dylib=crypto");
}