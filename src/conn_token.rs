//! The official reconnect credential (`conn_token`) read and written in the
//! pinned client's own JSON, without changing its shape.
//!
//! Provenance, `rustdesk/rustdesk` at `092a961b629d318fe290eeafac0cd214a1e9deeb`:
//!
//!  * `src/client.rs:2743-2796` — `PasswordSource` and `ConnToken` exactly as
//!    serde writes them (external tagging: a unit variant is its own string, a
//!    newtype variant is `{"Variant": <payload>}`, and `Vec<u8>` is an array of
//!    byte-valued integers);
//!  * `src/client.rs:2926-2942` — the reader: `serde_json::from_str::<ConnToken>`,
//!    then its `session_id` as the session's own (a zero one is replaced by a
//!    fresh nonzero id here by the caller) and its `password` as the last
//!    password;
//!  * `src/client.rs:3906-3920` — `get_conn_token`, which returns `None` for an
//!    empty password and otherwise writes `{password, password_source,
//!    session_id}`;
//!  * `src/client.rs:4620-4688` — where that `password` is produced:
//!    `h1 = SHA256(clear_password || peer Hash.salt)`.
//!
//! So the token's `password` is h1, not the clear password and not the challenge
//! response. A reconnect recomputes `SHA256(h1 || the peer's fresh challenge)` and
//! goes through the peer's own challenge, permissions and second factor like any
//! other login: nothing here, and nothing downstream, may treat the token as an
//! authenticated session or as a way around those steps. It is deliberately
//! reusable while the peer keeps its salt, which is why a user may share it and
//! why it is password-equivalent and never logged, never `Debug`-printed and
//! never put in a snapshot, event or status.
//!
//! Ownership: the official Dart client owns the address book and the account's
//! password source. This module only preserves the source a token already names,
//! so an export keeps saying where the password came from instead of inventing an
//! address book of its own.
//!
//! What [`ConnToken::parse`] accepts, and why: at most
//! [`MAX_CONN_TOKEN_BYTES`] bytes of UTF-8 JSON (the existing Resk bound, checked
//! before any parsing), one object with exactly the three fields `get_conn_token`
//! writes, `password` as an array of 32 byte-valued integers (the only material a
//! real h1 can be, so a shorter or longer one is not a credential this engine can
//! answer a challenge with), `password_source` in its externally tagged form, and
//! `session_id` as an unsigned 64-bit integer (`0` is a legal absence, not an
//! invalid token). An unknown or missing field, a wrong type, a float, a negative
//! number or an out-of-range integer is refused rather than reinterpreted. A key
//! repeated inside an object is read the way serde_json reads it — the last
//! occurrence wins — because that value model is the parser this build links; no
//! official producer writes such a token.

use hbb_common::{
    serde_json::{Map, Value},
    sodiumoxide::utils,
};

/// The largest token this reader will even parse. A real token is a few hundred
/// bytes; the bound exists so a hostile string cannot make the parser allocate.
pub const MAX_CONN_TOKEN_BYTES: usize = 4096;

/// A salted password is a SHA-256 digest, in the official client as here.
pub const H1_BYTES: usize = 32;

/// Where the token says its password came from, with the secret removed.
///
/// This is the part a caller may record, compare or display. The content behind
/// [`PasswordSourceKind::PersonalAb`] is password-equivalent and the content
/// behind [`PasswordSourceKind::SharedAb`] is the clear shared password, so
/// neither is reachable through this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordSourceKind {
    PersonalAb,
    SharedAb,
    Undefined,
}

/// The official `PasswordSource`, in the same externally tagged JSON shape.
///
/// `PersonalAb` carries the salted password an address book held, `SharedAb`
/// carries the clear shared password it was derived from, and `Undefined` says
/// the password came from the user or a plain config. Both payloads are secrets:
/// the value zeroes its own bytes when it is dropped, so replacing it (a typed
/// password answer, a refused attempt) leaves no copy behind.
pub enum PasswordSource {
    PersonalAb(Vec<u8>),
    SharedAb(String),
    Undefined,
}

impl PasswordSource {
    pub fn kind(&self) -> PasswordSourceKind {
        match self {
            Self::PersonalAb(_) => PasswordSourceKind::PersonalAb,
            Self::SharedAb(_) => PasswordSourceKind::SharedAb,
            Self::Undefined => PasswordSourceKind::Undefined,
        }
    }

    /// The externally tagged value serde writes for this variant.
    fn value(&self) -> Value {
        match self {
            Self::Undefined => Value::String("Undefined".to_owned()),
            Self::PersonalAb(bytes) => {
                let mut fields = Map::new();
                fields.insert("PersonalAb".to_owned(), byte_array(bytes));
                Value::Object(fields)
            }
            Self::SharedAb(text) => {
                let mut fields = Map::new();
                fields.insert("SharedAb".to_owned(), Value::String(text.clone()));
                Value::Object(fields)
            }
        }
    }
}

impl Drop for PasswordSource {
    fn drop(&mut self) {
        match self {
            Self::PersonalAb(bytes) => {
                utils::memzero(bytes);
                bytes.clear();
            }
            Self::SharedAb(text) => {
                // A shared password is clear text in the official token, so the
                // string's bytes are zeroed before its allocation is released.
                let mut bytes = std::mem::take(text).into_bytes();
                utils::memzero(&mut bytes);
                bytes.clear();
            }
            Self::Undefined => {}
        }
    }
}

/// The official `ConnToken`: what one peer's password login can be repeated with.
///
/// Deliberately neither `Debug`, `Display`, `Clone` nor `Serialize`: the one way
/// to read its secret is [`Self::to_json`], produced only on purpose, and the only
/// ways to obtain a token are [`Self::parse`] and a session's own authenticated
/// login. No copy exists unless a caller explicitly serializes it.
pub struct ConnToken {
    /// h1 = SHA256(clear_password || peer salt).
    password: Vec<u8>,
    password_source: PasswordSource,
    session_id: u64,
}

impl ConnToken {
    /// Reads the official token text, bounded before it is parsed.
    ///
    /// `None` is the same answer the official reader gives for text that is not
    /// this schema, and it carries no detail: a refusal that echoed the material
    /// would be a leak of its own.
    pub fn parse(token: &str) -> Option<Self> {
        if token.is_empty() || token.len() > MAX_CONN_TOKEN_BYTES {
            return None;
        }
        let value: Value = hbb_common::serde_json::from_str(token).ok()?;
        let Value::Object(mut fields) = value else {
            return None;
        };
        // Adopt the decoded h1 into its wiping owner before parsing anything
        // else: a malformed source/id or an unknown field must not release an
        // unowned password allocation through an early `?`/return.
        let mut token = Self::from_h1(
            byte_array_value(fields.remove("password")?)?,
            PasswordSource::Undefined,
            0,
        )?;
        token.password_source = password_source_value(fields.remove("password_source")?)?;
        token.session_id = fields.remove("session_id")?.as_u64()?;
        if !fields.is_empty() {
            // Exactly the three fields the official struct has: an extra one
            // means this is not a token this engine can vouch for.
            return None;
        }
        Some(token)
    }

    /// The official text a reconnect is given, produced only on purpose.
    ///
    /// This is the one serialization of a password-equivalent secret; nothing
    /// derives it, so no `Debug`, snapshot, event or status message can reach it
    /// by accident. The output is byte-identical to the official writer's: the
    /// same three fields, the same external tagging, the same byte array.
    pub fn to_json(&self) -> String {
        let mut fields = Map::new();
        fields.insert("password".to_owned(), byte_array(&self.password));
        fields.insert("password_source".to_owned(), self.password_source.value());
        fields.insert("session_id".to_owned(), Value::from(self.session_id));
        let mut value = Value::Object(fields);
        let json = value.to_string();
        if let Some(Value::String(shared)) = value
            .get_mut("password_source")
            .and_then(|source| source.get_mut("SharedAb"))
        {
            let mut bytes = std::mem::take(shared).into_bytes();
            utils::memzero(&mut bytes);
        }
        json
    }

    /// The session id this credential was used with; `0` means the token carried
    /// none and the caller's fresh id applies.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Where the token says its password came from, without the secret.
    pub fn source_kind(&self) -> PasswordSourceKind {
        self.password_source.kind()
    }

    /// The salted password, which only a challenge response may consume. Only the
    /// tests read it directly: production code answers the challenge from the
    /// parts a session takes, never from a token it still holds.
    #[cfg(test)]
    pub(crate) fn h1(&self) -> &[u8] {
        &self.password
    }

    /// Builds a token from material this engine itself produced (a session's own
    /// login), refusing anything that is not a real h1. Not public: a token is
    /// obtained by parsing official text or from an authenticated session, never
    /// by fabricating material.
    pub(crate) fn from_h1(
        mut h1: Vec<u8>,
        password_source: PasswordSource,
        session_id: u64,
    ) -> Option<Self> {
        if h1.len() != H1_BYTES {
            utils::memzero(&mut h1);
            return None;
        }
        Some(Self {
            password: h1,
            password_source,
            session_id,
        })
    }

    /// Gives the secret to the session that will answer a challenge with it,
    /// without copying it. The emptied `self` drops as a shell.
    pub(crate) fn into_parts(mut self) -> (Vec<u8>, PasswordSource) {
        let h1 = std::mem::take(&mut self.password);
        let source = std::mem::replace(&mut self.password_source, PasswordSource::Undefined);
        (h1, source)
    }
}

impl Drop for ConnToken {
    fn drop(&mut self) {
        utils::memzero(&mut self.password);
        self.password.clear();
    }
}

/// The exact `Vec<u8>` JSON serde writes: an array of byte-valued integers.
fn byte_array(bytes: &[u8]) -> Value {
    Value::Array(bytes.iter().map(|byte| Value::from(*byte)).collect())
}

/// Reads that same array, scrubbing what it decoded before refusing a shape that
/// is not a byte array.
fn byte_array_value(value: Value) -> Option<Vec<u8>> {
    let Value::Array(items) = value else {
        return None;
    };
    let mut bytes = Vec::with_capacity(items.len());
    for item in items {
        let Some(byte) = item.as_u64().and_then(|value| u8::try_from(value).ok()) else {
            utils::memzero(&mut bytes);
            bytes.clear();
            return None;
        };
        bytes.push(byte);
    }
    Some(bytes)
}

/// Reads the externally tagged `PasswordSource`.
fn password_source_value(value: Value) -> Option<PasswordSource> {
    match value {
        Value::String(tag) => match tag.as_str() {
            "Undefined" => Some(PasswordSource::Undefined),
            _ => None,
        },
        Value::Object(fields) if fields.len() == 1 => {
            let (tag, content) = fields.into_iter().next()?;
            match tag.as_str() {
                "PersonalAb" => Some(PasswordSource::PersonalAb(byte_array_value(content)?)),
                "SharedAb" => match content {
                    Value::String(text) => Some(PasswordSource::SharedAb(text)),
                    _ => None,
                },
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnToken, PasswordSource, PasswordSourceKind, H1_BYTES, MAX_CONN_TOKEN_BYTES,
    };

    /// The 32 bytes of the fixture h1 in the array form serde writes.
    const H1_ARRAY: &str = "[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,\
                           7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7]";

    /// The official text, spelled the way the pinned client's serde writes it.
    fn official(password_source: &str, session_id: &str) -> String {
        format!(
            r#"{{"password":{H1_ARRAY},"password_source":{password_source},"session_id":{session_id}}}"#
        )
    }

    fn parsed(text: &str) -> ConnToken {
        ConnToken::parse(text).expect("the official shape is accepted")
    }

    /// Every variant of the official struct survives the official text exactly:
    /// the same fields, the same external tagging, the same bytes.
    #[test]
    fn the_official_schema_round_trips_unchanged() {
        for (source, kind) in [
            (r#""Undefined""#.to_owned(), PasswordSourceKind::Undefined),
            (
                format!(r#"{{"PersonalAb":{H1_ARRAY}}}"#),
                PasswordSourceKind::PersonalAb,
            ),
            (
                r#"{"SharedAb":"shared-fixture"}"#.to_owned(),
                PasswordSourceKind::SharedAb,
            ),
        ] {
            let text = official(&source, "18446744073709551615");
            let token = parsed(&text);
            assert_eq!(token.source_kind(), kind);
            assert_eq!(token.session_id(), u64::MAX, "the session id is a true u64");
            assert_eq!(token.h1(), vec![7u8; H1_BYTES].as_slice());
            assert_eq!(
                token.to_json(),
                text,
                "an exported token is the official text byte for byte"
            );
        }
    }

    /// A shared password is escaped by the same writer on both sides, so even
    /// characters that must be escaped come back unchanged.
    #[test]
    fn an_escaped_shared_password_round_trips() {
        let text = official(r#"{"SharedAb":"shared \"quoted\" \\ ünïcode"}"#, "12");
        let token = parsed(&text);
        assert_eq!(token.source_kind(), PasswordSourceKind::SharedAb);
        assert_eq!(token.to_json(), text);
    }

    /// A session id of zero is the official "no id in this token": it is accepted
    /// and reported as zero rather than refused or silently replaced here, because
    /// choosing the fresh nonzero id is the caller's step.
    #[test]
    fn a_zero_session_id_is_accepted_as_absent() {
        let token = parsed(&official(r#""Undefined""#, "0"));
        assert_eq!(token.session_id(), 0);
    }

    /// The 4096-byte bound is inclusive, and it is checked before parsing.
    #[test]
    fn the_bound_is_the_documented_4096_bytes() {
        let prefix = format!(r#"{{"password":{H1_ARRAY},"password_source":{{"SharedAb":""#);
        let suffix = r#""},"session_id":1}"#;
        let padding = MAX_CONN_TOKEN_BYTES - prefix.len() - suffix.len();
        let text = format!("{prefix}{}{suffix}", "s".repeat(padding));
        assert_eq!(text.len(), MAX_CONN_TOKEN_BYTES);
        assert_eq!(parsed(&text).session_id(), 1);
        assert!(
            ConnToken::parse(&format!("{text} ")).is_none(),
            "one byte over the bound is refused"
        );
        assert!(ConnToken::parse("").is_none(), "an empty string is no token");
    }

    /// The shapes that are not this schema are refused, not reinterpreted.
    #[test]
    fn material_and_shape_failures_are_refused() {
        let thirty_one = vec!["7"; H1_BYTES - 1].join(",");
        let thirty_three = vec!["7"; H1_BYTES + 1].join(",");
        let cases = [
            // Not this object at all.
            "[]".to_owned(),
            r#""Undefined""#.to_owned(),
            r#"{"password":[1,2],"password_source":"Undefined""#.to_owned(),
            // The three fields are all required, and nothing else may appear.
            format!(r#"{{"password_source":"Undefined","session_id":1}}"#),
            format!(r#"{{"password":{H1_ARRAY},"session_id":1}}"#),
            format!(r#"{{"password":{H1_ARRAY},"password_source":"Undefined"}}"#),
            format!(
                r#"{{"password":{H1_ARRAY},"password_source":"Undefined","session_id":1,"extra":0}}"#
            ),
            // `password` must be a real h1: 32 byte-valued integers.
            format!(r#"{{"password":[{thirty_one}],"password_source":"Undefined","session_id":1}}"#),
            format!(r#"{{"password":[{thirty_three}],"password_source":"Undefined","session_id":1}}"#),
            r#"{"password":"Nw==","password_source":"Undefined","session_id":1}"#.to_owned(),
            r#"{"password":[256],"password_source":"Undefined","session_id":1}"#.to_owned(),
            r#"{"password":[-1],"password_source":"Undefined","session_id":1}"#.to_owned(),
            r#"{"password":[1.5],"password_source":"Undefined","session_id":1}"#.to_owned(),
            r#"{"password":["7"],"password_source":"Undefined","session_id":1}"#.to_owned(),
            // `session_id` must fit an unsigned 64-bit integer.
            format!(r#"{{"password":{H1_ARRAY},"password_source":"Undefined","session_id":-1}}"#),
            format!(r#"{{"password":{H1_ARRAY},"password_source":"Undefined","session_id":1.5}}"#),
            format!(r#"{{"password":{H1_ARRAY},"password_source":"Undefined","session_id":"1"}}"#),
            format!(
                r#"{{"password":{H1_ARRAY},"password_source":"Undefined","session_id":18446744073709551616}}"#
            ),
            // `password_source` must be the external tagging serde writes.
            format!(r#"{{"password":{H1_ARRAY},"password_source":"undefined","session_id":1}}"#),
            format!(r#"{{"password":{H1_ARRAY},"password_source":{{"Undefined":null}},"session_id":1}}"#),
            format!(r#"{{"password":{H1_ARRAY},"password_source":{{"SharedAb":7}},"session_id":1}}"#),
            format!(
                r#"{{"password":{H1_ARRAY},"password_source":{{"PersonalAb":[1],"Other":[]}},"session_id":1}}"#
            ),
        ];
        for case in cases {
            assert!(
                ConnToken::parse(&case).is_none(),
                "this is not the official schema: {case}"
            );
        }
    }

    /// Material this engine fabricates is refused unless it is a real h1.
    #[test]
    fn only_real_material_becomes_a_token() {
        assert!(
            ConnToken::from_h1(vec![1, 2, 3], PasswordSource::Undefined, 1).is_none(),
            "a short blob is not a salted password"
        );
        let token = ConnToken::from_h1(
            vec![7u8; H1_BYTES],
            PasswordSource::PersonalAb(vec![7u8; H1_BYTES]),
            3,
        )
        .expect("a real h1 is a token");
        assert_eq!(token.source_kind(), PasswordSourceKind::PersonalAb);
        assert_eq!(token.session_id(), 3);
        // Handing the secret to a session leaves nothing behind in the token.
        let (h1, source) = token.into_parts();
        assert_eq!(h1.len(), H1_BYTES);
        assert_eq!(source.kind(), PasswordSourceKind::PersonalAb);
    }
}
