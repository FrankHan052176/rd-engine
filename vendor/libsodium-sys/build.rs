extern crate cc;

#[cfg(target_env = "msvc")]
extern crate libc;

extern crate pkg_config;
extern crate walkdir;

use std::{
    env,
    path::{Path, PathBuf},
};

static VERSION: &str = "1.0.18";

fn main() {
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_SHARED");
    println!("cargo:rerun-if-env-changed=SODIUM_USE_PKG_CONFIG");

    if cfg!(not(windows)) {
        println!("cargo:rerun-if-env-changed=SODIUM_DISABLE_PIE");
    }

    if env::var("SODIUM_STATIC").is_ok() {
        panic!("SODIUM_STATIC is deprecated. Use SODIUM_SHARED instead.");
    }

    let lib_dir_isset = env::var("SODIUM_LIB_DIR").is_ok();
    let use_pkg_isset = if cfg!(feature = "use-pkg-config") {
        true
    } else {
        env::var("SODIUM_USE_PKG_CONFIG").is_ok()
    };
    let shared_isset = env::var("SODIUM_SHARED").is_ok();

    if lib_dir_isset && use_pkg_isset {
        panic!("SODIUM_LIB_DIR is incompatible with SODIUM_USE_PKG_CONFIG. Set the only one env variable");
    }

    if lib_dir_isset {
        find_libsodium_env();
    } else if use_pkg_isset {
        if shared_isset {
            println!("cargo:warning=SODIUM_SHARED has no effect with SODIUM_USE_PKG_CONFIG");
        }

        find_libsodium_pkg();
    } else {
        if shared_isset {
            println!(
                "cargo:warning=SODIUM_SHARED has no effect for building libsodium from source"
            );
        }

        build_libsodium();
    }
}

/* Must be called when SODIUM_LIB_DIR is set to any value
This function will set `cargo` flags.
*/
fn find_libsodium_env() {
    let lib_dir = env::var("SODIUM_LIB_DIR").unwrap(); // cannot fail

    println!("cargo:rustc-link-search=native={}", lib_dir);
    let mode = if env::var("SODIUM_SHARED").is_ok() {
        "dylib"
    } else {
        "static"
    };
    let name = if cfg!(target_env = "msvc") {
        "libsodium"
    } else {
        "sodium"
    };
    println!("cargo:rustc-link-lib={}={}", mode, name);
    println!(
        "cargo:warning=Using unknown libsodium version.  This crate is tested against \
         {} and may not be fully compatible with other versions.",
        VERSION
    );
}

/* Must be called when no SODIUM_USE_PKG_CONFIG env var is set
This function will set `cargo` flags.
*/
#[cfg(target_env = "msvc")]
fn find_libsodium_pkg() {
    panic!("SODIUM_USE_PKG_CONFIG is not supported on msvc");
}

/* Must be called when SODIUM_USE_PKG_CONFIG env var is set
This function will set `cargo` flags.
*/
#[cfg(not(target_env = "msvc"))]
fn find_libsodium_pkg() {
    match pkg_config::Config::new().probe("libsodium") {
        Ok(lib) => {
            if lib.version != VERSION {
                println!(
                    "cargo:warning=Using libsodium version {}.  This crate is tested against {} \
                     and may not be fully compatible with {}.",
                    lib.version, VERSION, lib.version
                );
            }
            for lib_dir in &lib.link_paths {
                println!("cargo:lib={}", lib_dir.to_str().unwrap());
            }
            for include_dir in &lib.include_paths {
                println!("cargo:include={}", include_dir.to_str().unwrap());
            }
        }
        Err(e) => {
            panic!(
                "
Failed to run pkg-config:
{:?}

You can try fixing this by installing pkg-config:

    # On Ubuntu
    sudo apt install pkg-config
    # On Arch Linux
    sudo pacman -S pkgconf
    # On Fedora
    sudo dnf install pkgconf-pkg-config

",
                e
            );
        }
    }
}

fn make_libsodium(target: &str, source_dir: &Path, install_dir: &Path) -> PathBuf {
    use std::{process::Command, str};

    // Native Windows targets keep using the bundled precompiled libraries.
    #[cfg(windows)]
    if target.contains("windows") {
        return get_lib_dir();
    }

    // Decide on CC, CFLAGS and the --host configure argument
    let build_compiler = cc::Build::new().get_compiler();
    let mut compiler = build_compiler.path().to_str().unwrap().to_string();
    let mut cflags = build_compiler.cflags_env().into_string().unwrap();
    let mut host_arg = format!("--host={}", target);
    let mut cross_compiling = target != env::var("HOST").unwrap();
    if target.contains("-ios") {
        // Determine Xcode directory path
        let xcode_select_output = Command::new("xcode-select").arg("-p").output().unwrap();
        if !xcode_select_output.status.success() {
            panic!("Failed to run xcode-select -p");
        }
        let xcode_dir = str::from_utf8(&xcode_select_output.stdout)
            .unwrap()
            .trim()
            .to_string();

        // Determine SDK directory paths
        let sdk_dir_simulator = Path::new(&xcode_dir)
            .join("Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk")
            .to_str()
            .unwrap()
            .to_string();
        let sdk_dir_ios = Path::new(&xcode_dir)
            .join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk")
            .to_str()
            .unwrap()
            .to_string();

        // Min versions
        let ios_simulator_version_min = "6.0.0";
        let ios_version_min = "6.0.0";

        // Roughly based on `dist-build/ios.sh` in the libsodium sources
        match &*target {
            "aarch64-apple-ios" => {
                cflags += " -arch arm64";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -fembed-bitcode";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7-apple-ios" => {
                cflags += " -arch armv7";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7s-apple-ios" => {
                cflags += " -arch armv7s";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "i386-apple-ios" => {
                cflags += " -arch i386";
                cflags += &format!(" -isysroot {}", sdk_dir_simulator);
                cflags += &format!(" -mios-simulator-version-min={}", ios_simulator_version_min);
                host_arg = "--host=i686-apple-darwin10".to_string();
            }
            "x86_64-apple-ios" => {
                cflags += " -arch x86_64";
                cflags += &format!(" -isysroot {}", sdk_dir_simulator);
                cflags += &format!(" -mios-simulator-version-min={}", ios_simulator_version_min);
                host_arg = "--host=x86_64-apple-darwin10".to_string();
            }
            _ => panic!("Unknown iOS build target: {}", target),
        }
        cross_compiling = true;
    } else if target.contains("i686") {
        compiler += " -m32 -maes";
        cflags += " -march=i686";
    } else if target.ends_with("-linux-ohos") {
        host_arg = format!("--host={}", target.replace("-linux-ohos", "-linux-gnu"));
        cross_compiling = true;
    }

    let help = if cross_compiling {
        "***********************************************************\n\
         Possible missing dependencies.\n\
         See https://github.com/sodiumoxide/sodiumoxide#cross-compiling\n\
         ***********************************************************\n\n"
    } else {
        ""
    };

    // Run `./configure`
    let prefix_arg = format!("--prefix={}", shell_path(install_dir));
    let libdir_arg = format!("--libdir={}/lib", shell_path(install_dir));
    let tool_path_prefixes = host_tool_path_prefixes();
    let mut configure_cmd = configure_command(source_dir);
    prepend_path(&mut configure_cmd, &tool_path_prefixes);
    if !compiler.is_empty() {
        configure_cmd.env("CC", &compiler);
    }
    if !cflags.is_empty() {
        configure_cmd.env("CFLAGS", &cflags);
    }
    if target.ends_with("-linux-ohos") {
        if let Some(ar) = target_env_tool("AR", target) {
            configure_cmd.env("AR", ar);
        }
        if let Some(ld) = target_env_tool("LD", target) {
            configure_cmd.env("LD", ld);
        }
        if let Some(ranlib) = target_env_tool("RANLIB", target) {
            configure_cmd.env("RANLIB", ranlib);
        }
        if let Some(make) = make_env_value() {
            configure_cmd.env("MAKE", make);
        }
        configure_cmd.arg("--disable-dependency-tracking");
        configure_cmd.arg("--disable-asm");
    }
    if env::var("SODIUM_DISABLE_PIE").is_ok() {
        configure_cmd.arg("--disable-pie");
    }
    let configure_status = configure_cmd
        .current_dir(&source_dir)
        .arg(&prefix_arg)
        .arg(&libdir_arg)
        .arg(&host_arg)
        .arg("--enable-shared=no")
        .status()
        .unwrap_or_else(|error| {
            panic!("Failed to run './configure': {}\n{}", error, help);
        });
    if !configure_status.success() {
        panic!(
            "\nFailed to configure libsodium using {:?}\nCFLAGS={}\nCC={}\n{}\n",
            configure_cmd, cflags, compiler, help
        );
    }

    // Run `make check`, or `make all` if we're cross-compiling
    let jobs = env::var("NUM_JOBS").unwrap();
    let j_arg = format!("-j{}", jobs);
    let make_arg = if cross_compiling { "all" } else { "check" };
    let mut make_cmd = make_command();
    prepend_path(&mut make_cmd, &tool_path_prefixes);
    if target.ends_with("-linux-ohos") {
        if let Some(ar) = target_env_tool("AR", target) {
            make_cmd.env("AR", ar);
        }
        if let Some(ld) = target_env_tool("LD", target) {
            make_cmd.env("LD", ld);
        }
        if let Some(ranlib) = target_env_tool("RANLIB", target) {
            make_cmd.env("RANLIB", ranlib);
        }
        if let Some(make) = make_env_value() {
            make_cmd.env("MAKE", make);
        }
    }
    let make_status = make_cmd
        .current_dir(&source_dir)
        .env("V", "1")
        .arg(make_arg)
        .arg(&j_arg)
        .status()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make {}': {}\n{}", make_arg, error, help);
        });
    if !make_status.success() {
        panic!("\nFailed to build libsodium using {:?}\n{}", make_cmd, help);
    }

    if target.ends_with("-linux-ohos") {
        return source_dir.join("src").join("libsodium").join(".libs");
    }

    // Run `make install`
    let mut install_cmd = make_command();
    prepend_path(&mut install_cmd, &tool_path_prefixes);
    let install_status = install_cmd
        .current_dir(&source_dir)
        .arg("install")
        .status()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make install': {}", error);
        });
    if !install_status.success() {
        panic!("\nFailed to install libsodium using {:?}", install_cmd);
    }

    install_dir.join("lib")
}

fn shell_path(path: &Path) -> String {
    path.to_str().unwrap().replace('\\', "/")
}

fn configure_command(source_dir: &Path) -> std::process::Command {
    #[cfg(windows)]
    {
        let sh = find_program("sh.exe", &windows_shell_search_paths()).unwrap_or_else(|| {
            panic!(
                "Failed to find sh.exe. Install Git for Windows or MSYS2 and put usr/bin in PATH"
            )
        });
        let mut command = std::process::Command::new(sh);
        command.current_dir(source_dir).arg("./configure");
        command
    }

    #[cfg(not(windows))]
    {
        let configure = std::fs::canonicalize(source_dir.join("configure")).expect(
            "Failed to find configure script! Did you clone the submodule at `libsodium-sys/libsodium`?",
        );
        std::process::Command::new(configure)
    }
}

fn make_command() -> std::process::Command {
    if let Some(make) = env::var_os("MAKE") {
        return std::process::Command::new(make);
    }

    #[cfg(windows)]
    {
        if let Some(make) = find_program("make.exe", &[]) {
            return std::process::Command::new(make);
        }
        if let Some(make) = find_program("mingw32-make.exe", &[]) {
            return std::process::Command::new(make);
        }
        std::process::Command::new("mingw32-make")
    }

    #[cfg(not(windows))]
    {
        std::process::Command::new("make")
    }
}

fn make_env_value() -> Option<String> {
    if let Some(make) = env::var_os("MAKE") {
        return Some(normalize_tool_path(make.to_string_lossy().into_owned()));
    }

    #[cfg(windows)]
    {
        find_program("mingw32-make.exe", &[])
            .or_else(|| find_program("make.exe", &[]))
            .map(|path| shell_path(&path))
    }

    #[cfg(not(windows))]
    {
        Some("make".to_string())
    }
}

fn target_env_tool(prefix: &str, target: &str) -> Option<String> {
    let normalized = target.replace('-', "_");
    if let Ok(value) = env::var(format!("{}_{}", prefix, normalized)) {
        return Some(normalize_tool_path(value));
    }

    if prefix == "RANLIB" {
        if let Some(ar) = target_env_tool("AR", target) {
            let ranlib_name = if cfg!(windows) {
                "llvm-ranlib.exe"
            } else {
                "llvm-ranlib"
            };
            let ranlib = PathBuf::from(ar).with_file_name(ranlib_name);
            if ranlib.is_file() {
                return Some(shell_path(&ranlib));
            }
        }
    }

    None
}

fn normalize_tool_path(path: String) -> String {
    path.replace('\\', "/")
}

fn prepend_path(command: &mut std::process::Command, prefixes: &[PathBuf]) {
    if prefixes.is_empty() {
        return;
    }

    let mut paths = prefixes.to_vec();
    if let Some(path) = env::var_os("PATH") {
        paths.extend(env::split_paths(&path));
    }
    let path = env::join_paths(paths).expect("Failed to join PATH entries");
    command.env("PATH", path);
}

fn host_tool_path_prefixes() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        windows_shell_search_paths()
            .into_iter()
            .filter(|path| path.is_dir())
            .collect()
    }

    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

fn find_program(name: &str, extra_paths: &[PathBuf]) -> Option<PathBuf> {
    for dir in extra_paths {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(windows)]
fn windows_shell_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        // Prefer short/no-space paths because libtool stores the shell path.
        PathBuf::from(r"C:\PROGRA~1\Git\usr\bin"),
        PathBuf::from(r"C:\PROGRA~1\Git\bin"),
        PathBuf::from(r"C:\msys64\usr\bin"),
    ];

    if let Some(path) = env::var_os("PATH") {
        paths.extend(
            env::split_paths(&path)
                .filter(|path| path.join("sh.exe").is_file())
                .filter(|path| !path.to_string_lossy().contains(' ')),
        );
    }

    paths.push(PathBuf::from(r"C:\Program Files\Git\usr\bin"));
    paths.push(PathBuf::from(r"C:\Program Files\Git\bin"));
    paths
}

#[cfg(any(windows, target_env = "msvc"))]
fn get_crate_dir() -> PathBuf {
    env::var("CARGO_MANIFEST_DIR").unwrap().into()
}

#[cfg(target_env = "msvc")]
fn is_release_profile() -> bool {
    env::var("PROFILE").unwrap() == "release"
}

#[cfg(all(target_env = "msvc", target_pointer_width = "32"))]
fn get_lib_dir() -> PathBuf {
    if is_release_profile() {
        get_crate_dir().join("msvc/Win32/Release/v142/")
    } else {
        get_crate_dir().join("msvc/Win32/Debug/v142/")
    }
}

#[cfg(all(target_env = "msvc", target_pointer_width = "64"))]
fn get_lib_dir() -> PathBuf {
    if is_release_profile() {
        get_crate_dir().join("msvc/x64/Release/v142/")
    } else {
        get_crate_dir().join("msvc/x64/Debug/v142/")
    }
}

#[cfg(all(windows, not(target_env = "msvc"), target_pointer_width = "32"))]
fn get_lib_dir() -> PathBuf {
    get_crate_dir().join("mingw/win32/")
}

#[cfg(all(windows, not(target_env = "msvc"), target_pointer_width = "64"))]
fn get_lib_dir() -> PathBuf {
    get_crate_dir().join("mingw/win64/")
}

fn build_libsodium() {
    use std::{ffi::OsStr, fs};

    // Determine build target triple
    let mut out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    let profile = env::var("PROFILE").unwrap();

    // Avoid issues with paths containing spaces by falling back to using a tempfile.
    // See https://github.com/jedisct1/libsodium/issues/207
    if out_dir.to_str().unwrap().contains(' ') {
        out_dir = env::temp_dir()
            .join("libsodium-sys")
            .join(&target)
            .join(&profile);
        println!(
            "cargo:warning=The path to the usual build directory contains spaces and hence \
             can't be used to build libsodium.  Falling back to use {}.  If running `cargo \
             clean`, ensure you also delete this fallback directory",
            out_dir.display()
        );
    }

    // Determine source and install dir
    let install_dir = out_dir.join("installed");
    let source_dir = out_dir.join("source").join("libsodium");

    // Create directories
    fs::create_dir_all(&install_dir).unwrap();
    fs::create_dir_all(&source_dir).unwrap();

    // Copy sources into build directory
    // Skip .git because it's marked read-only and that causes problems re-building
    for entry in walkdir::WalkDir::new("libsodium")
        .into_iter()
        .filter_entry(|e| e.file_name() != OsStr::new(".git"))
        .filter_map(Result::ok)
    {
        let outpath = out_dir.join("source").join(entry.path());
        if let Err(e) = if entry.file_type().is_dir() {
            fs::create_dir_all(outpath)
        } else {
            fs::copy(entry.path(), outpath).map(|_| ())
        } {
            panic!("Failed to copy sources into build directory: {}", e);
        }
    }

    let lib_dir = make_libsodium(&target, &source_dir, &install_dir);

    if target.contains("msvc") {
        println!("cargo:rustc-link-lib=static=libsodium");
    } else {
        println!("cargo:rustc-link-lib=static=sodium");
    }

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir.to_str().unwrap()
    );

    let include_dir = source_dir.join("src/libsodium/include");

    println!("cargo:include={}", include_dir.to_str().unwrap());
    println!("cargo:lib={}", lib_dir.to_str().unwrap());
}
