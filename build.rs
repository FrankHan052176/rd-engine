#[path = "native/vnc/build.rs"]
mod vnc;

use std::{
    env,
    path::{Path, PathBuf},
};

/// The libvpx release the Windows install is pinned to, and the vcpkg triplet
/// that install lives in: the vendored overlay
/// (`native/frb/vcpkg-overlays/libvpx`) builds `libvpx:x64-windows-static-md`
/// from libvpx 1.15.2, and both the workflow and the remote sync validate that
/// same pair before they export the prefix.
const PINNED_WINDOWS_VPX_VERSION: &str = "1.15.2";
const PINNED_WINDOWS_TRIPLET_SUFFIX: &str = "-windows-static-md";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(dsh_windows_typecheck)");
    println!("cargo:rustc-check-cfg=cfg(rd_vpx_linked)");
    vnc::build();
    println!("cargo:rerun-if-changed=native/windows-capture/rd_desktop_duplication.cpp");
    println!("cargo:rerun-if-changed=native/windows-capture/rd_desktop_duplication.h");
    println!("cargo:rerun-if-changed=native/windows-input/windows_input.cpp");
    println!("cargo:rerun-if-changed=native/windows-input/windows_input.h");
    println!("cargo:rerun-if-changed=native/windows-nvenc/windows_nvenc.cpp");
    println!("cargo:rerun-if-changed=native/windows-nvenc/windows_nvenc.h");
    println!("cargo:rerun-if-changed=native/windows-nvenc/include/nvEncodeAPI.h");
    println!("cargo:rerun-if-changed=native/windows-decoder/rd_windows_decoder.cpp");
    println!("cargo:rerun-if-changed=native/windows-decoder/rd_windows_decoder.h");

    let windows = std::env::var_os("CARGO_CFG_TARGET_OS").as_deref() == Some("windows".as_ref());
    if windows {
        cc::Build::new()
            .cpp(true)
            .std("c++17")
            .flag_if_supported("/EHsc")
            .file("native/windows-decoder/rd_windows_decoder.cpp")
            .include("native/windows-decoder")
            .compile("rd_engine_windows_decoder");
        for library in ["d3d11", "dxgi", "dxguid", "mfplat", "mfuuid", "ole32"] {
            println!("cargo:rustc-link-lib={library}");
        }
    }
    software_vpx();
    let native_default = std::env::var_os("CARGO_FEATURE_WINDOWS_MODERN_PRODUCER").is_some();
    if !windows || !native_default {
        return;
    }

    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .file("native/windows-capture/rd_desktop_duplication.cpp")
        .file("native/windows-input/windows_input.cpp")
        .file("native/windows-nvenc/windows_nvenc.cpp")
        .include("native/windows-capture")
        .include("native/windows-input")
        .include("native/windows-nvenc")
        .include("native/windows-nvenc/include")
        .compile("rd_engine_windows_native");

    for library in ["d3d11", "dxgi", "dxguid", "user32"] {
        println!("cargo:rustc-link-lib={library}");
    }
}

enum Kind {
    Static,
    Shared,
}

/// A libvpx install that was verified to have both halves this crate needs: the
/// header the ABI was generated from, and a library file to link.
struct Found {
    include: PathBuf,
    lib: PathBuf,
    version: String,
    origin: &'static str,
}

/// The target this script resolves a library for.
///
/// Cargo sets both halves for every build script, and this feature has to tell
/// two Windows ABIs apart: only MSVC installs the pinned static `vpx.lib` from
/// the vendored vcpkg overlay, while GNU Windows keeps the Unix archive name.
struct Target {
    os: String,
    env: String,
}

impl Target {
    fn current() -> Self {
        Self {
            os: env::var("CARGO_CFG_TARGET_OS").unwrap_or_default(),
            env: env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default(),
        }
    }

    /// Whether this is the one Windows ABI that installs `vpx.lib`.
    fn windows_msvc(&self) -> bool {
        self.os == "windows" && self.env == "msvc"
    }

    /// The one static library file name this target's installs use.
    ///
    /// The pinned Windows install is the vendored vcpkg overlay, which builds
    /// libvpx's MSVC project with its library suffixes removed
    /// (`0004-remove-library-suffixes.patch`) and so installs a single
    /// `vpx.lib`. A GNU Windows target links the MinGW archive like any other
    /// GNU target, and everything else this module resolves for ships the Unix
    /// archive name.
    fn static_file(&self) -> &'static str {
        if self.windows_msvc() {
            "vpx.lib"
        } else {
            "libvpx.a"
        }
    }

    fn has_static(&self, lib: &Path) -> bool {
        lib.join(self.static_file()).is_file()
    }

    /// Whether `-lvpx` can resolve in this directory: the one unversioned file
    /// name the linker searches for on this target.
    ///
    /// Apple platforms link `libvpx.dylib` and ELF ones `libvpx.so`, which is
    /// what `cargo:rustc-link-lib=dylib=vpx` asks for. A directory that holds
    /// only the versioned runtime files (`libvpx.so.12`, `libvpx.12.dylib`) is
    /// therefore not a shared install this can link: those names are not
    /// searched for, so accepting them here would set `rd_vpx_linked` and fail
    /// at link time instead of reporting the candidate as unusable and
    /// continuing the search. No Windows target is served here: neither the
    /// pinned install nor a GNU Windows one is staged with a runtime
    /// `vpx.dll`, so Windows resolves through its static archive or not at all.
    fn has_shared(&self, lib: &Path) -> bool {
        let name = match self.os.as_str() {
            "macos" | "ios" => "libvpx.dylib",
            "windows" => return false,
            _ => "libvpx.so",
        };
        lib.join(name).is_file()
    }

    /// Whether this target links the static archive when the install ships
    /// both kinds.
    fn prefers_static(&self) -> bool {
        matches!(self.os.as_str(), "macos" | "ios" | "windows")
    }
}

/// Links an installed libvpx for the `software-vpx` feature.
///
/// Nothing here downloads, builds or generates libvpx: only a library that is
/// already installed is ever linked, and a target where none resolves is not a
/// broken build. The MSVC Windows install is pinned: it is the static
/// `x64-windows-static-md` vcpkg prefix the vendored overlay
/// (`native/frb/vcpkg-overlays/libvpx`, libvpx 1.15.2) produces and
/// `LIBVPX_PREFIX` names, `verify` accepts no other layout there, and the
/// overlay is provisioning rather than a second decoder - this script still
/// links only what that install actually holds.
///
/// The feature stays compiled, `platform/vpx_decoder.rs` refuses every entry
/// point by name, and the reason travels in `RD_LIBVPX_PROVENANCE` so a
/// capability report can name it instead of guessing.
fn software_vpx() {
    for name in [
        "LIBVPX_PREFIX",
        "LIBVPX_INCLUDE_DIR",
        "LIBVPX_LIB_DIR",
        "LIBVPX_STATIC",
        "PKG_CONFIG",
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
        "PKG_CONFIG_SYSROOT_DIR",
        // Read by the `pkg-config` crate, which refuses a cross probe unless
        // this or a target-prefixed tool is configured: toggling it changes
        // which candidate resolves, so it must rerun the script.
        "PKG_CONFIG_ALLOW_CROSS",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("CARGO_FEATURE_SOFTWARE_VPX").is_none() {
        return;
    }
    let target = Target::current();
    if target.env == "ohos" {
        // The device build links OpenHarmony's own media stack for H264/H265
        // and refuses VPx there; a host archive must never enter that link.
        unavailable("target_env=ohos uses OpenHarmony's media stack, not a host libvpx");
        return;
    }
    match resolve(&target) {
        Ok(found) => link(&found, &target),
        Err(reason) => unavailable(&reason),
    }
}

/// Resolves one install, in the order this feature froze: pkg-config, then an
/// explicit environment, then - only for a build whose HOST is its TARGET - the
/// host's own Homebrew and system prefixes. Every candidate is verified before
/// use, and none of the four ever reaches the network.
///
/// The pinned Windows ABI is the one exception to that order, because its
/// install is the one the release is built against: an explicit `LIBVPX_*` is
/// consulted first and decides on its own, so a `pkg-config vpx` from elsewhere
/// cannot take the link away from the prefix the workflow and the remote sync
/// validated. A named prefix that is not that pinned install is refused by
/// name, never replaced by another library. Every candidate accepted there -
/// named or discovered - is held to that same rule (`verify`).
///
/// The host prefixes are absolute paths of the machine running this script, so
/// they can only describe a library built for that machine's own target. A
/// `cargo build --target ...` therefore resolves through a target-aware
/// pkg-config or an explicit `LIBVPX_*` and stays unlinked when neither is
/// configured, instead of linking a host-architecture archive into a foreign
/// target. The explicit environment comes before those prefixes for the same
/// reason: it is the only way a cross build can name its own install.
fn resolve(target: &Target) -> Result<Found, String> {
    if target.windows_msvc() && install_named() {
        return from_env(target);
    }
    let mut tried = Vec::new();
    match from_pkg_config(target) {
        Ok(found) => return Ok(found),
        Err(note) => tried.push(note),
    }
    match from_env(target) {
        Ok(found) => return Ok(found),
        Err(note) => tried.push(note),
    }
    if !host_is_target() {
        tried.push(format!(
            "host prefixes not searched for a cross build: HOST is {}, TARGET is {}",
            env::var("HOST").unwrap_or_else(|_| "<unset>".into()),
            env::var("TARGET").unwrap_or_else(|_| "<unset>".into()),
        ));
        return Err(format!("no usable libvpx ({})", tried.join("; ")));
    }
    for prefix in homebrew_prefixes(target) {
        if !prefix.is_dir() {
            continue;
        }
        match verify(
            "homebrew",
            &prefix.join("include"),
            &prefix.join("lib"),
            target,
        ) {
            Ok(found) => return Ok(found),
            Err(note) => tried.push(note),
        }
    }
    for prefix in system_prefixes(target) {
        match verify(
            "system",
            &prefix.join("include"),
            &prefix.join("lib"),
            target,
        ) {
            Ok(found) => return Ok(found),
            Err(note) => tried.push(note),
        }
    }
    Err(format!("no usable libvpx ({})", tried.join("; ")))
}

/// Whether an install was named explicitly, in either of the two shapes
/// `from_env` accepts. Only a request the caller actually made may decide a
/// Windows build, so the absence of one still allows discovery.
fn install_named() -> bool {
    let prefix = env::var_os("LIBVPX_PREFIX").is_some();
    let includes = env::var_os("LIBVPX_INCLUDE_DIR").is_some();
    let libs = env::var_os("LIBVPX_LIB_DIR").is_some();
    prefix || (includes && libs)
}

/// Whether this script is resolving a library for the machine it runs on.
///
/// Cargo sets both triples for a build script. An absent one counts as "not the
/// host", so an unusual environment stays unlinked rather than falling back to
/// host-only paths.
fn host_is_target() -> bool {
    match (env::var("HOST"), env::var("TARGET")) {
        (Ok(host), Ok(target)) => host == target,
        _ => false,
    }
}

/// Discovery through pkg-config, when the tool exists.
///
/// The crate is asked for metadata only: this script decides which library file
/// is linked, because "static first on Apple platforms" is a decision about the
/// files that are actually installed, not about pkg-config's own default.
///
/// A cross build is served here only when the `pkg-config` crate itself allows
/// the probe - a target-prefixed `pkg-config`, or `PKG_CONFIG_ALLOW_CROSS`,
/// which is the caller's own statement that its `PKG_CONFIG_*` paths describe
/// the target. The crate refuses otherwise, and that refusal is recorded
/// alongside the other candidates instead of being worked around with host
/// paths.
///
/// The pair this metadata names is then held to the same rule as an explicit
/// one (`verify`): a discovered Windows install has to be the pinned static
/// one, so a `vpx.lib` that pkg-config happens to know about cannot be linked
/// on its file name alone.
fn from_pkg_config(target: &Target) -> Result<Found, String> {
    let mut config = pkg_config::Config::new();
    config.cargo_metadata(false).statik(true);
    let library = config
        .probe("vpx")
        .map_err(|error| format!("pkg-config vpx: {error}"))?;
    // Both halves must be present and named: the header that defines the
    // decoder ABI, and a library file a linker can use.
    let include = library
        .include_paths
        .iter()
        .find(|dir| dir.join("vpx").join("vpx_decoder.h").is_file())
        .ok_or_else(|| {
            format!(
                "pkg-config vpx: no include path with vpx/vpx_decoder.h (version {})",
                library.version
            )
        })?
        .clone();
    let lib = library
        .link_paths
        .iter()
        .find(|dir| target.has_static(dir) || target.has_shared(dir))
        .ok_or_else(|| {
            format!(
                "pkg-config vpx: no library directory among {:?}",
                library.link_paths
            )
        })?
        .clone();
    verify("pkg-config", &include, &lib, target)
}

/// The audited keg first, then the version-independent Homebrew link, so a
/// machine carrying a different libvpx release still resolves through a path
/// this audit names.
///
/// These are host paths, reached only when HOST is TARGET (`resolve`), so the
/// list names the host platform itself: an iOS target never takes a macOS keg,
/// because it is never the host of its own build.
fn homebrew_prefixes(target: &Target) -> Vec<PathBuf> {
    match target.os.as_str() {
        "macos" => vec![
            PathBuf::from("/opt/homebrew/Cellar/libvpx/1.17.0"),
            PathBuf::from("/opt/homebrew/opt/libvpx"),
        ],
        // Linuxbrew, when it is what is installed.
        "linux" => vec![PathBuf::from("/home/linuxbrew/.linuxbrew/opt/libvpx")],
        _ => Vec::new(),
    }
}

/// The prefixes a plain Unix install uses. Both are verified, so a directory
/// that holds only half an install is reported rather than linked.
///
/// Host paths like the Homebrew list above: reached only when HOST is TARGET.
fn system_prefixes(target: &Target) -> Vec<PathBuf> {
    match target.os.as_str() {
        "macos" => vec![PathBuf::from("/usr/local")],
        "linux" | "android" | "freebsd" | "dragonfly" | "netbsd" | "openbsd" | "illumos"
        | "solaris" => vec![PathBuf::from("/usr"), PathBuf::from("/usr/local")],
        // Windows and anything else have no system prefix to search: this
        // audit covers an installed library, not a vendored copy.
        _ => Vec::new(),
    }
}

/// An explicit request, consulted before any host prefix so a cross build can
/// name its own install and so an override is never shadowed by a host keg.
/// It can name what the search order cannot: a sysroot, a cross toolchain, a
/// non-standard prefix. On the pinned Windows ABI it is consulted before
/// pkg-config as well, and decides on its own (`resolve`).
fn from_env(target: &Target) -> Result<Found, String> {
    if let Some(prefix) = env::var_os("LIBVPX_PREFIX") {
        let prefix = PathBuf::from(prefix);
        return verify(
            "LIBVPX_PREFIX",
            &prefix.join("include"),
            &prefix.join("lib"),
            target,
        );
    }
    match (
        env::var_os("LIBVPX_INCLUDE_DIR"),
        env::var_os("LIBVPX_LIB_DIR"),
    ) {
        (Some(include), Some(lib)) => verify(
            "LIBVPX_INCLUDE_DIR + LIBVPX_LIB_DIR",
            &PathBuf::from(include),
            &PathBuf::from(lib),
            target,
        ),
        _ => Err("no LIBVPX_PREFIX or LIBVPX_INCLUDE_DIR + LIBVPX_LIB_DIR".into()),
    }
}

/// A candidate counts only when the header that defines the decoder ABI and a
/// library file the linker can actually take from this directory are both
/// present: `libvpx.a` on Unix targets and the pinned static `vpx.lib` on the
/// MSVC Windows one, or the unversioned shared library where one is what gets
/// linked.
///
/// Every candidate passes through here - pkg-config, the explicit environment
/// and the host prefixes alike - so the stricter rule for the pinned Windows
/// install below cannot be bypassed by naming an install another way.
fn verify(
    origin: &'static str,
    include: &Path,
    lib: &Path,
    target: &Target,
) -> Result<Found, String> {
    let header = include.join("vpx").join("vpx_decoder.h");
    if !header.is_file() {
        return Err(format!("{origin}: no {}", header.display()));
    }
    if !target.has_static(lib) && !target.has_shared(lib) {
        return Err(format!(
            "{origin}: no {} or shared libvpx in {}",
            target.static_file(),
            lib.display()
        ));
    }
    if target.windows_msvc() {
        verify_pinned_windows_static(origin, include, lib)?;
    }
    Ok(Found {
        include: include.to_path_buf(),
        lib: lib.to_path_buf(),
        version: installed_version(lib),
        origin,
    })
}

/// The pinned Windows static install, checked as one layout.
///
/// A Windows `.lib` file name cannot tell a static archive from a DLL import
/// library, so `vpx.lib` alone proves nothing: a dynamic install would leave
/// the produced dll needing a `vpx.dll` that neither the workflow nor the sync
/// script stages. The only Windows install this feature links is the pinned
/// static vcpkg one, so a candidate is accepted only in that install's own
/// layout: one prefix whose directory name ends in the pinned triplet, that
/// prefix's `include/` and `lib/` (never two directories from elsewhere), the
/// `vpx.lib` the static gate above requires, and a `lib/pkgconfig/vpx.pc`
/// declaring exactly the pinned release. Everything else is refused by name.
/// This is deliberately strict for the pinned Windows output, not a path for
/// arbitrary DLL installs.
fn verify_pinned_windows_static(
    origin: &'static str,
    include: &Path,
    lib: &Path,
) -> Result<(), String> {
    let Some(prefix) = include.parent() else {
        return Err(format!(
            "{origin}: {} has no prefix directory to check",
            include.display()
        ));
    };
    if lib != prefix.join("lib").as_path() {
        return Err(format!(
            "{origin}: {} and {} are not the include/ and lib/ of one prefix",
            include.display(),
            lib.display()
        ));
    }
    let Some(triplet) = prefix.file_name().and_then(|name| name.to_str()) else {
        return Err(format!(
            "{origin}: {} has no directory name to check",
            prefix.display()
        ));
    };
    if !triplet.ends_with(PINNED_WINDOWS_TRIPLET_SUFFIX) {
        return Err(format!(
            "{origin}: {} is not a *{PINNED_WINDOWS_TRIPLET_SUFFIX} install",
            prefix.display()
        ));
    }
    let record = lib.join("pkgconfig").join("vpx.pc");
    if !record.is_file() {
        return Err(format!("{origin}: no {}", record.display()));
    }
    let version = installed_version(lib);
    if version != PINNED_WINDOWS_VPX_VERSION {
        return Err(format!(
            "{origin}: {} records libvpx {version}, not the pinned {PINNED_WINDOWS_VPX_VERSION}",
            record.display()
        ));
    }
    Ok(())
}

/// Emits the link for one verified install, plus the evidence this feature is
/// actually reported from.
fn link(found: &Found, target: &Target) {
    let kind = link_kind(found, target);
    println!("cargo:rustc-link-search=native={}", found.lib.display());
    println!("cargo:rerun-if-changed={}", found.lib.display());
    let kind_name = match kind {
        Kind::Static => {
            println!("cargo:rustc-link-lib=static=vpx");
            // libvpx's own private libraries, as its `vpx.pc` names them
            // (`-lm -lpthread`). libSystem provides both on Apple platforms,
            // and a Windows link takes the MSVC CRT and the Win32 import
            // libraries instead: `m` and `pthread` are not libraries that
            // exist there, so they must never be named on that target.
            // Android's bionic keeps the pthread API in libc and ships no
            // libpthread for the linker to find (`ld.lld: unable to find
            // library -lpthread`), so only libm is named there.
            let private_libraries: &[&str] = match target.os.as_str() {
                "macos" | "ios" | "windows" => &[],
                "android" => &["m"],
                _ => &["m", "pthread"],
            };
            for library in private_libraries {
                println!("cargo:rustc-link-lib={library}");
            }
            "static"
        }
        Kind::Shared => {
            println!("cargo:rustc-link-lib=dylib=vpx");
            "dylib"
        }
    };
    println!("cargo:rustc-cfg=rd_vpx_linked");
    println!(
        "cargo:rustc-env=RD_LIBVPX_PROVENANCE={kind_name} via {}: headers {} library {} ({})",
        found.origin,
        found.include.display(),
        found.lib.display(),
        found.version
    );
}

/// Which library file the link will use.
///
/// Apple platforms prefer the static archive - the Homebrew keg ships both, and
/// a bare `-lvpx` would silently take the dylib - and so does Windows, whose
/// resolved install is a static archive with no import library this links.
/// Other targets prefer the system's shared library. `LIBVPX_STATIC` (0 or 1)
/// overrides that, and a request the install cannot satisfy is warned about and
/// replaced by the file that is actually there, never by a failing link line.
fn link_kind(found: &Found, target: &Target) -> Kind {
    let has_static = target.has_static(&found.lib);
    let has_shared = target.has_shared(&found.lib);
    let want_static = match env::var("LIBVPX_STATIC").ok().as_deref() {
        Some("1") => true,
        Some("0") => false,
        _ => target.prefers_static(),
    };
    if want_static && has_static {
        return Kind::Static;
    }
    if !want_static && has_shared {
        return Kind::Shared;
    }
    let present = if has_static {
        target.static_file()
    } else {
        "a shared libvpx"
    };
    println!(
        "cargo:warning=libvpx: {} requested but {} holds only {}, linking {present}",
        if want_static {
            "a static libvpx was"
        } else {
            "a shared libvpx was"
        },
        found.lib.display(),
        present
    );
    if has_static {
        Kind::Static
    } else {
        Kind::Shared
    }
}

/// The version recorded next to the library, when the install ships a
/// `vpx.pc`. "unknown" is honest: the gate that decides is the linked
/// library's own `vpx_codec_version()`, and this string is provenance.
///
/// Both the Homebrew keg and the pinned vcpkg overlay install that record at
/// `<prefix>/lib/pkgconfig/vpx.pc`, so the Windows install reports `1.15.2`
/// here rather than "unknown" - and that exact string is what
/// `verify_pinned_windows_static` accepts there.
fn installed_version(lib: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(lib.join("pkgconfig").join("vpx.pc")) else {
        return "unknown".into();
    };
    text.lines()
        .find_map(|line| line.strip_prefix("Version:"))
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// Not a build error: the feature is compiled and refuses itself at run time,
/// with the reason recorded where a capability report can read it.
fn unavailable(reason: &str) {
    // One line: a `cargo:warning` and a provenance string are read as single
    // lines, and a library tool's own multi-line error must not reshape them.
    let reason = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    println!("cargo:warning=software-vpx: {reason}");
    println!("cargo:rustc-env=RD_LIBVPX_PROVENANCE=unavailable: {reason}");
}
