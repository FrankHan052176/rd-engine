// SPDX-License-Identifier: AGPL-3.0-only
// RustDesk contributors; pin 092a961b629d318fe290eeafac0cd214a1e9deeb.
// Modified 2026-09-23: shared derive import; no Debug/Clone or upstream tests.
use hbb_common::{
    bail,
    base64::{
        engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
        Engine as _,
    },
    sodiumoxide::crypto::sign,
    ResultType,
};
use hbb_common::serde_derive::{Deserialize, Serialize};

#[derive(PartialEq, Default, Serialize, Deserialize)]
pub struct CustomServer {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub api: String,
    #[serde(default)]
    pub relay: String,
}

fn get_custom_server_from_config_string(s: &str) -> ResultType<CustomServer> {
    let tmp: String = s.chars().rev().collect();
    const PK: &[u8; 32] = &[
        88, 168, 68, 104, 60, 5, 163, 198, 165, 38, 12, 85, 114, 203, 96, 163, 70, 48, 0, 131, 57,
        12, 46, 129, 83, 17, 84, 193, 119, 197, 130, 103,
    ];
    let pk = sign::PublicKey(*PK);
    let data = URL_SAFE_NO_PAD
        .decode(&tmp)
        .or_else(|_| URL_SAFE.decode(&tmp))?;
    if let Ok(lic) = serde_json::from_slice::<CustomServer>(&data) {
        return Ok(lic);
    }
    if let Ok(data) = sign::verify(&data, &pk) {
        Ok(serde_json::from_slice::<CustomServer>(&data)?)
    } else {
        bail!("sign:verify failed");
    }
}

pub fn get_custom_server_from_string(s: &str) -> ResultType<CustomServer> {
    let s = if s.to_lowercase().ends_with(".exe.exe") {
        &s[0..s.len() - 8]
    } else if s.to_lowercase().ends_with(".exe") {
        &s[0..s.len() - 4]
    } else {
        s
    };
    /*
     * The following code tokenizes the file name based on commas and
     * extracts relevant parts sequentially.
     *
     * host= is expected to be the first part.
     *
     * Since Windows renames files adding (1), (2) etc. before the .exe
     * in case of duplicates, which causes the host or key values to be
     * garbled.
     *
     * This allows using a ',' (comma) symbol as a final delimiter.
     */
    if s.to_lowercase().contains("host=") {
        let stripped = &s[s.to_lowercase().find("host=").unwrap_or(0)..s.len()];
        let strs: Vec<&str> = stripped.split(",").collect();
        let mut host = String::default();
        let mut key = String::default();
        let mut api = String::default();
        let mut relay = String::default();
        let strs_iter = strs.iter();
        for el in strs_iter {
            let el_lower = el.to_lowercase();
            if el_lower.starts_with("host=") {
                host = el.chars().skip(5).collect();
            }
            if el_lower.starts_with("key=") {
                key = el.chars().skip(4).collect();
            }
            if el_lower.starts_with("api=") {
                api = el.chars().skip(4).collect();
            }
            if el_lower.starts_with("relay=") {
                relay = el.chars().skip(6).collect();
            }
        }
        return Ok(CustomServer {
            host,
            key,
            api,
            relay,
        });
    } else {
        let s = s
            .replace("-licensed---", "--")
            .replace("-licensed--", "--")
            .replace("-licensed-", "--");
        let strs = s.split("--");
        for s in strs {
            if let Ok(lic) = get_custom_server_from_config_string(s.trim()) {
                return Ok(lic);
            } else if s.contains("(") {
                // https://github.com/rustdesk/rustdesk/issues/4162
                for s in s.split("(") {
                    if let Ok(lic) = get_custom_server_from_config_string(s.trim()) {
                        return Ok(lic);
                    }
                }
            }
        }
    }
    bail!("Failed to parse");
}

