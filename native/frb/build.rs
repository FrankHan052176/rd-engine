use std::{env, fs, path::PathBuf};

fn pinned_field<'a>(metadata: &'a str, name: &str) -> Result<&'a str, String> {
    let mut found = None;
    for line in metadata.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != name {
            continue;
        }
        if found.is_some() {
            return Err(format!("UPSTREAM.txt repeats '{name}'"));
        }
        let value = value
            .strip_prefix(' ')
            .ok_or_else(|| format!("UPSTREAM.txt requires '{name}: value'"))?;
        if key != name || value.is_empty() || value != value.trim() {
            return Err(format!("UPSTREAM.txt has a malformed '{name}'"));
        }
        found = Some(value);
    }
    found.ok_or_else(|| format!("UPSTREAM.txt is missing '{name}'"))
}

fn numeric_component(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn product_version(value: &str) -> bool {
    let mut count = 0;
    for component in value.split('.') {
        if !numeric_component(component) {
            return false;
        }
        count += 1;
    }
    count == 3
}

fn main() -> Result<(), String> {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("ohos") {
        panic!("The official-client FRB kernel is non-HarmonyOS only; use native/ohos_napi on HarmonyOS");
    }

    // The official consumer's product identity is not this bridge crate's version.
    // Upstream Git-object comparisons belong to verify-native-provenance.sh;
    // native builds use only these validated, source-owned offline pins.
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .ok_or_else(|| "CARGO_MANIFEST_DIR is required to read UPSTREAM.txt".to_owned())?;
    let upstream = PathBuf::from(manifest_dir).join("UPSTREAM.txt");
    println!("cargo:rerun-if-changed={}", upstream.display());
    let metadata = fs::read_to_string(&upstream)
        .map_err(|error| format!("cannot read {}: {error}", upstream.display()))?;
    let revision = pinned_field(&metadata, "Commit")?;
    let product = pinned_field(&metadata, "Official product version")?;
    let flutter = pinned_field(&metadata, "Official Flutter package version")?;

    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(
            "UPSTREAM.txt Commit must be exactly 40 lowercase hexadecimal characters".to_owned(),
        );
    }
    if !product_version(product) {
        return Err(
            "UPSTREAM.txt Official product version must be numeric X.Y.Z without leading zeros"
                .to_owned(),
        );
    }
    let (flutter_product, build) = flutter.split_once('+').ok_or_else(|| {
        "UPSTREAM.txt Official Flutter package version must be numeric X.Y.Z+N".to_owned()
    })?;
    if !product_version(flutter_product) || !numeric_component(build) {
        return Err("UPSTREAM.txt Official Flutter package version must be numeric X.Y.Z+N without leading zeros".to_owned());
    }
    if flutter_product != product {
        return Err(
            "UPSTREAM.txt official product and Flutter package versions disagree".to_owned(),
        );
    }

    println!("cargo:rustc-env=RD_OFFICIAL_PRODUCT_VERSION={product}");
    println!("cargo:rustc-env=RD_OFFICIAL_FLUTTER_VERSION={flutter}");
    println!("cargo:rustc-env=RD_OFFICIAL_CLIENT_REVISION={revision}");
    Ok(())
}
