use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bls_dir = manifest_dir.join("bls");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Build the static library via the submodule's Makefile.
    // `make` handles incremental builds internally, so we always invoke it.
    // Pass OUT_DIR so the library is written into Cargo's output directory,
    // which means `cargo clean` will remove it and force a rebuild next time.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let mut cmd = Command::new("make");
    cmd.arg("-C")
        .arg(&bls_dir)
        .arg("-f")
        .arg("Makefile.onelib")
        .arg("ETH_CFLAGS=-DBLS_ETH")
        .arg(format!("OUT_DIR={}", out_dir.display()));

    if target_arch != "x86_64" {
        cmd.arg("CXX=clang++");
    }

    let status = cmd.status().expect("failed to run make");

    if !status.success() {
        panic!("make failed with status: {}", status);
    }

    // Map cargo target OS/arch to the directory names the Makefile uses.
    //   Makefile OS names: linux, darwin, windows, openbsd, freebsd
    //   Makefile arch names: amd64, arm64, arm, s390x
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let os_dir = match target_os.as_str() {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        "openbsd" => "openbsd",
        "freebsd" => "freebsd",
        other => panic!("Unsupported target OS: {}", other),
    };

    let arch_dir = match target_arch.as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "s390x" => "s390x",
        other => panic!("Unsupported target arch: {}", other),
    };

    // The Makefile places the library at:
    //   <out_dir>/bls/lib/<os>/<arch>/libbls384_256.a
    let lib_dir = out_dir.join("bls").join("lib").join(os_dir).join(arch_dir);

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
}
