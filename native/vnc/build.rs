//! Called from the engine build.rs as `vnc::build()`.
//! Requires the Cargo build dependency `cmake = "0.1"` and target zlib headers/library.
use std::{env, fs, path::Path};

pub fn build() {
    println!("cargo:rerun-if-changed=native/vnc");
    let target = env::var("TARGET").unwrap_or_default();
    for name in ["CMAKE", "CMAKE_TOOLCHAIN_FILE", "CMAKE_GENERATOR", "CMAKE_GENERATOR_TOOLSET", "CMAKE_PREFIX_PATH", "CC", "CXX", "AR", "CFLAGS", "CXXFLAGS", "ZLIB_ROOT"] {
        for key in [name.to_owned(), format!("{name}_{target}"), format!("{name}_{}", target.replace('-', "_")), format!("HOST_{name}"), format!("TARGET_{name}")] {
            println!("cargo:rerun-if-env-changed={key}");
            if name == "CMAKE_TOOLCHAIN_FILE" {
                if let Some(path) = env::var_os(&key) { println!("cargo:rerun-if-changed={}", Path::new(&path).display()); }
            }
        }
    }
    let mut config = cmake::Config::new("native/vnc");
    config.profile("Release").build_target("rd_engine_vnc_client");
    // cmake-rs respects CMAKE_TOOLCHAIN_FILE and target-qualified compiler/env
    // settings, including the project's NDK cross toolchain. Never use host
    // libraries to make an unavailable target dependency appear to work.
    let output = config.build();
    println!("cargo:rustc-link-search=native={}", output.join("build/lib").display());
    println!("cargo:rustc-link-lib=static=vncclient");
    let zlib = fs::read_to_string(output.join("build/rd_vnc_zlib_Release.txt"))
        .unwrap_or_else(|error| panic!("CMake did not report the required target zlib: {error}"));
    link_zlib(Path::new(zlib.trim()));
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=ws2_32");
    }
}

fn link_zlib(path: &Path) {
    let directory = path.parent().unwrap_or_else(|| panic!("invalid CMake zlib path: {}", path.display()));
    let file = path.file_name().and_then(|name| name.to_str())
        .unwrap_or_else(|| panic!("invalid CMake zlib filename: {}", path.display()));
    let name = file.strip_prefix("lib").unwrap_or(file);
    let (name, kind) = if let Some(name) = name.strip_suffix(".a") {
        (name, "static=")
    } else if let Some(name) = name.strip_suffix(".lib") {
        (name, "")
    } else if let Some(name) = name.strip_suffix(".dylib") {
        (name, "")
    } else if let Some(name) = name.strip_suffix(".tbd") {
        (name, "")
    } else if let Some((name, _)) = name.split_once(".so") {
        (name, "")
    } else {
        panic!("unsupported CMake zlib library filename: {file}");
    };
    println!("cargo:rustc-link-search=native={}", directory.display());
    println!("cargo:rustc-link-lib={kind}{name}");
}
