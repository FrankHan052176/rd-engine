//! One account owner for official Dart, native OIDC and both caches. This is
//! missing lifecycle/protected-storage integration, not a LocalConfig transplant.
//! Receipts prove operation ordering, not caller identity or authorization.

use super::{api, AccountContext, AuthAttempt};
use super::storage::{
    self, AccountRecord, RecordKind, SecretBytes, Store, MAX_TOKEN_BYTES, MAX_USER_INFO_BYTES,
};
use hbb_common::{
    anyhow::{anyhow, bail, ensure},
    serde_json,
    sodiumoxide::{crypto::hash::sha256, randombytes},
    ResultType,
};
use std::sync::{LazyLock, Mutex, MutexGuard};

static OWNER: LazyLock<Mutex<Owner>> = LazyLock::new(|| Mutex::new(Owner::default()));

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    namespace: String,
    scope: String,
    epoch: u64,
    epoch_id: [u8; 32],
}

impl Stamp {
    fn new(store: &Store, account: &AccountRecord) -> Self {
        Self { namespace: store.namespace().to_owned(), scope: account.scope.clone(),
            epoch: account.epoch, epoch_id: account.epoch_id }
    }
}

struct SessionAccount {
    token: SecretBytes,
    user_info: SecretBytes,
}

struct AttemptWitness {
    origin: AccountContext,
    serial: u64,
    receipt: String,
    committed_generation: Option<u64>,
}

/// A failed revocation keeps only its exact initiating receipt and permissible
/// durable boundaries, never an old token. The receipt may retry logout only;
/// it cannot authorize a credential write or touch a foreign account epoch.
struct FailedTransition {
    receipt: Option<String>,
    original: Stamp,
    owned: Option<Stamp>,
    uncertain_tombstone: Option<Stamp>,
    completed: bool,
}

impl FailedTransition {
    fn permits(&self, stamp: &Stamp, account: &AccountRecord) -> bool {
        &self.original == stamp || self.owned.as_ref() == Some(stamp)
            || (self.uncertain_tombstone.as_ref() == Some(stamp) && account.token.is_empty())
    }
}

#[derive(Default)]
struct Owner {
    generation: u64,
    auth_serial: u64,
    local_revision: u64,
    incarnation: Option<[u8; 32]>,
    context: Option<AccountContext>,
    observed: Option<Stamp>,
    last_receipt: Option<String>,
    attempt: Option<AttemptWitness>,
    session: Option<SessionAccount>,
    staged_user_info: Option<SecretBytes>,
    ab_cache: Option<SecretBytes>,
    group_cache: Option<SecretBytes>,
    memory_cache_revisions: [u64; 2],
    failure: Option<FailedTransition>,
}

impl Owner {
    fn retire(&mut self) -> ResultType<()> {
        self.context = None;
        self.last_receipt = None;
        self.attempt = None;
        self.session = None;
        self.staged_user_info = None;
        self.ab_cache = None;
        self.group_cache = None;
        self.local_revision = 0;
        self.generation = self.generation.checked_add(1)
            .ok_or_else(|| anyhow!("Account generation exhausted"))?;
        Ok(())
    }

    fn initialize_incarnation(&mut self) {
        if self.incarnation.is_none() {
            // Store::open already initialized sodium. This nonce is public
            // receipt domain separation, not a credential or encryption key.
            let mut value = [0; 32];
            randombytes::randombytes_into(&mut value);
            self.incarnation = Some(value);
        }
    }

    fn context(&self) -> ResultType<AccountContext> {
        self.context.clone().ok_or_else(|| anyhow!("Account context is not available"))
    }

    fn bind(&mut self, store: &Store, account: &AccountRecord, server: String, scope: String) {
        self.observed = Some(Stamp::new(store, account));
        self.context = Some(AccountContext { api_server: server, scope, generation: self.generation });
        self.memory_cache_revisions = [account.ab_revision, account.group_revision];
    }

    fn synchronize(&mut self, store: &Store, account: &AccountRecord,
        server: String, scope: String) -> ResultType<()>
    {
        let stamp = Stamp::new(store, account);
        if let Some(failure) = &self.failure {
            ensure!(!failure.permits(&stamp, account),
                "Account revocation is incomplete; retry the original logout or server configuration");
            // A genuinely foreign account transition has already retired the
            // failed operation's account. Observe it without granting its old
            // receipt any authority over the new account.
            ensure!(account.epoch != 0, "Durable account generation record disappeared");
            self.failure = None;
        }
        if account.scope != scope {
            self.retire()?;
            bail!("Account storage belongs to a different server configuration");
        }
        let changed = self.observed.as_ref() != Some(&stamp)
            || self.context.as_ref().is_some_and(|context|
                context.scope != scope || context.api_server != server);
        if changed {
            self.retire()?;
            self.bind(store, account, server, scope);
        } else if self.context.is_none() {
            self.context = Some(AccountContext { api_server: server, scope, generation: self.generation });
        }
        if self.session.is_some() && !account.token.is_empty() {
            self.retire()?;
            bail!("Session-only account conflicts with persisted credentials");
        }
        Ok(())
    }

    fn token<'a>(&'a self, account: &'a AccountRecord) -> &'a [u8] {
        match &self.session {
            Some(session) => session.token.bytes(),
            None => account.token.bytes(),
        }
    }

    fn user_info<'a>(&'a self, account: &'a AccountRecord) -> &'a [u8] {
        if let Some(session) = &self.session { return session.user_info.bytes(); }
        if let Some(staged) = &self.staged_user_info { return staged.bytes(); }
        account.user_info.bytes()
    }

    fn receipt(&self, store: &Store, account: &AccountRecord, kind: RecordKind) -> ResultType<String> {
        let incarnation = self.incarnation.as_ref().ok_or_else(|| anyhow!("Account owner is not initialized"))?;
        let mut input = Vec::with_capacity(160 + store.namespace().len() + account.scope.len());
        input.extend_from_slice(b"rd-engine/official-account/receipt/v1\0");
        input.extend_from_slice(receipt_prefix(kind).as_bytes());
        input.extend_from_slice(incarnation);
        input.extend_from_slice(store.namespace().as_bytes());
        input.push(0);
        input.extend_from_slice(account.scope.as_bytes());
        input.push(0);
        input.extend_from_slice(&account.epoch.to_le_bytes());
        input.extend_from_slice(&account.epoch_id);
        input.extend_from_slice(&self.generation.to_le_bytes());
        match kind {
            RecordKind::Account => {
                input.extend_from_slice(&account.metadata_revision.to_le_bytes());
                input.extend_from_slice(&self.local_revision.to_le_bytes());
            }
            RecordKind::AddressBook | RecordKind::Group => {
                // Independent cache leases: metadata/Ab changes do not retire
                // Group or unrelated account work. Account replacement does.
                input.extend_from_slice(&account.revision(kind)?.to_le_bytes());
            }
        }
        Ok(format!("{}{}", receipt_prefix(kind), storage::hex(&sha256::hash(&input).0)))
    }

    fn issue_account_receipt(&mut self, store: &Store, account: &AccountRecord) -> ResultType<String> {
        let receipt = self.receipt(store, account, RecordKind::Account)?;
        self.last_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    fn attempt_matches(&self, attempt: &AuthAttempt, receipt: &str) -> bool {
        let Some(witness) = &self.attempt else { return false; };
        if witness.serial != attempt.generation || witness.origin != attempt.context || witness.receipt != receipt {
            return false;
        }
        match witness.committed_generation {
            Some(generation) => generation == self.generation && self.context.is_some(),
            None => self.context.as_ref() == Some(&attempt.context),
        }
    }

    fn memory_cache(&self, kind: RecordKind) -> ResultType<&Option<SecretBytes>> {
        match kind {
            RecordKind::AddressBook => Ok(&self.ab_cache),
            RecordKind::Group => Ok(&self.group_cache),
            RecordKind::Account => bail!("Account is not a cache kind"),
        }
    }

    fn memory_cache_mut(&mut self, kind: RecordKind) -> ResultType<&mut Option<SecretBytes>> {
        match kind {
            RecordKind::AddressBook => Ok(&mut self.ab_cache),
            RecordKind::Group => Ok(&mut self.group_cache),
            RecordKind::Account => bail!("Account is not a cache kind"),
        }
    }
}

fn owner() -> ResultType<MutexGuard<'static, Owner>> {
    OWNER.lock().map_err(|_| anyhow!("Account owner lock poisoned"))
}

fn receipt_prefix(kind: RecordKind) -> &'static str {
    match kind { RecordKind::Account => "a1.", RecordKind::AddressBook => "b1.", RecordKind::Group => "g1." }
}

fn validate_receipt(receipt: &str, kind: RecordKind) -> ResultType<()> {
    let suffix = receipt.strip_prefix(receipt_prefix(kind))
        .ok_or_else(|| anyhow!("Malformed account operation receipt"))?;
    ensure!(suffix.len() == 64 && suffix.bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "Malformed account operation receipt");
    Ok(())
}

fn cache_index(kind: RecordKind) -> ResultType<usize> {
    match kind { RecordKind::AddressBook => Ok(0), RecordKind::Group => Ok(1),
        RecordKind::Account => bail!("Account is not a cache kind") }
}

/// Establish a real initial epoch before exposing any receipt. Otherwise the
/// first cache-only mutation would inadvertently change the account receipt.
fn load_current(owner: &Owner, store: &mut Store, scope: &str) -> ResultType<AccountRecord> {
    if let Some(account) = store.read_account()? { return Ok(account); }
    ensure!(!owner.observed.as_ref().is_some_and(|old|
        old.namespace == store.namespace() && old.epoch != 0), "Durable account generation record disappeared");
    let account = AccountRecord::empty(scope.to_owned(), 1);
    store.write_account(&account)?;
    Ok(account)
}

/// One lock ordering for credentials, receipts, key election and caches. No
/// callback into transport/OIDC and no await occurs while holding either lock.
fn with_current<T>(expected: Option<(RecordKind, &str)>,
    operation: impl FnOnce(&mut Owner, &mut Store, &mut AccountRecord) -> ResultType<T>) -> ResultType<T>
{
    if let Some((kind, receipt)) = expected { validate_receipt(receipt, kind)?; }
    let mut owner = owner()?;
    let scope = match api::scope() { Ok(scope) => scope, Err(error) => { owner.retire()?; return Err(error); } };
    let server = api::server();
    let mut store = match Store::open() {
        Ok(store) => store,
        Err(error) => { owner.retire()?; return Err(error.into()); }
    };
    owner.initialize_incarnation();
    let result = (|| {
        let mut account = match load_current(&owner, &mut store, &scope) {
            Ok(account) => account,
            Err(error) => { owner.retire()?; return Err(error); }
        };
        owner.synchronize(&store, &account, server, scope)?;
        owner.issue_account_receipt(&store, &account)?;
        if let Some((kind, receipt)) = expected {
            ensure!(receipt == owner.receipt(&store, &account, kind)?,
                "Account operation receipt is stale");
        }
        operation(&mut owner, &mut store, &mut account)
    })();
    finish(&mut owner, store, result)
}

fn finish<T>(owner: &mut Owner, store: Store, result: ResultType<T>) -> ResultType<T> {
    match (result, store.finish()) {
        (Ok(value), Ok(())) => {
            if owner.failure.as_ref().is_some_and(|failure| failure.completed) { owner.failure = None; }
            Ok(value)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => { owner.retire()?; Err(error.into()) }
        (Err(error), Err(unlock)) => {
            owner.retire()?;
            Err(anyhow!("{error}; account lock release failed: {unlock}"))
        }
    }
}

pub fn current_context() -> ResultType<AccountContext> {
    with_current(None, |owner, _, _| owner.context())
}

pub fn context_is_current(context: &AccountContext) -> ResultType<bool> {
    with_current(None, |owner, _, _| Ok(owner.context.as_ref() == Some(context)))
}

/// Legacy authorized synchronous read. OS provider/file-lock I/O can block;
/// the additive snapshot bridge is asynchronous and calls this owner on its
/// generated worker. Do not replace these reads with a memory-only shortcut.
pub fn get_local_option(key: &str) -> ResultType<String> {
    ensure!(matches!(key, "access_token" | "user_info"), "Unsupported private account option");
    let value = with_current(None, |owner, _, account| {
        Ok(SecretBytes::from_slice(if key == "access_token" { owner.token(account) } else { owner.user_info(account) }))
    })?;
    Ok(value.into_string()?)
}

pub fn snapshot() -> ResultType<String> {
    let result = with_current(None, |owner, store, account| {
        let receipt = owner.issue_account_receipt(store, account)?;
        let ab = owner.receipt(store, account, RecordKind::AddressBook)?;
        let group = owner.receipt(store, account, RecordKind::Group)?;
        let server = serde_json::to_string(&owner.context()?.api_server)
            .map_err(|_| anyhow!("Account snapshot serialization failed"))?;
        let token = json_string(owner.token(account))?;
        let user_info = json_string(owner.user_info(account))?;
        let token = std::str::from_utf8(token.bytes()).map_err(|_| anyhow!("Invalid account text"))?;
        let user_info = std::str::from_utf8(user_info.bytes()).map_err(|_| anyhow!("Invalid account text"))?;
        Ok(SecretBytes::from_string(format!(
            "{{\"receipt\":\"{receipt}\",\"api_server\":{server},\"access_token\":{token},\"user_info\":{user_info},\"cache_receipts\":{{\"ab\":\"{ab}\",\"group\":\"{group}\"}}}}")))
    })?;
    // Only after owner validation and lock release is the unavoidable business
    // String transferred to FRB/Dart. Native-owned buffers have no Debug/Clone.
    Ok(result.into_string()?)
}

fn json_string(value: &[u8]) -> ResultType<SecretBytes> {
    let text = std::str::from_utf8(value).map_err(|_| anyhow!("Account text is not UTF-8"))?;
    Ok(SecretBytes::from_string(serde_json::to_string(text)
        .map_err(|_| anyhow!("Account snapshot serialization failed"))?))
}

pub fn set_local_option_scoped(receipt: &str, key: &str, value: String) -> ResultType<String> {
    let value = SecretBytes::from_string(value);
    ensure!(matches!(key, "access_token" | "user_info"), "Unsupported private account option");
    if key == "access_token" && value.is_empty() { return logout_scoped(receipt); }
    let limit = if key == "access_token" { MAX_TOKEN_BYTES } else { MAX_USER_INFO_BYTES };
    ensure!(value.bytes().len() <= limit, "Private account value exceeds its size bound");
    with_current(Some((RecordKind::Account, receipt)), |owner, store, account| {
        if key == "access_token" {
            // Opaque tokens are never fed to encrypt_*_or_original heuristics.
            // An identical OIDC callback cannot upgrade session-only mode.
            if owner.token(account) != value.bytes() {
                let info = if let Some(session) = owner.session.as_mut() {
                    std::mem::take(&mut session.user_info)
                } else if let Some(staged) = owner.staged_user_info.take() {
                    staged
                } else { std::mem::take(&mut account.user_info) };
                replace_account(owner, store, account, value, info, true, receipt)?;
            }
        } else if owner.user_info(account) != value.bytes() {
            if owner.session.is_some() || account.token.is_empty() {
                let next = owner.local_revision.checked_add(1)
                    .ok_or_else(|| anyhow!("Account metadata generation exhausted"))?;
                if let Some(session) = owner.session.as_mut() { session.user_info = value; }
                else { owner.staged_user_info = Some(value); }
                owner.local_revision = next;
            } else {
                account.metadata_revision = account.metadata_revision.checked_add(1)
                    .ok_or_else(|| anyhow!("Durable account metadata generation exhausted"))?;
                account.user_info = value;
                store.write_account(account)?;
            }
        }
        owner.issue_account_receipt(store, account)
    })
}

fn replace_account(owner: &mut Owner, store: &mut Store, account: &mut AccountRecord,
    token: SecretBytes, user_info: SecretBytes, remember_me: bool, receipt: &str) -> ResultType<()>
{
    let context = owner.context()?;
    revoke(owner, store, account, context.scope.clone(), Some(receipt.to_owned()))?;
    if remember_me {
        account.token = token;
        account.user_info = user_info;
        store.write_account(account)?;
    } else {
        // Prior remembered credentials and caches were durably retired first.
        owner.session = Some(SessionAccount { token, user_info });
    }
    owner.bind(store, account, context.api_server, context.scope);
    if let Some(failure) = owner.failure.as_mut() { failure.completed = true; }
    Ok(())
}

fn revoke(owner: &mut Owner, store: &mut Store, account: &mut AccountRecord,
    scope: String, receipt: Option<String>) -> ResultType<()>
{
    owner.failure = Some(FailedTransition { receipt, original: Stamp::new(store, account),
        owned: None, uncertain_tombstone: None, completed: false });
    owner.retire()?;
    let epoch = account.epoch.checked_add(1).ok_or_else(|| anyhow!("Durable account generation exhausted"))?;
    let tombstone = AccountRecord::empty(scope, epoch);
    if let Some(failure) = owner.failure.as_mut() {
        failure.uncertain_tombstone = Some(Stamp::new(store, &tombstone));
    }
    store.write_account(&tombstone)?;
    let stamp = Stamp::new(store, &tombstone);
    owner.observed = Some(stamp.clone());
    if let Some(failure) = owner.failure.as_mut() {
        failure.owned = Some(stamp);
        failure.uncertain_tombstone = None;
    }
    *account = tombstone;
    store.remove_caches()?;
    Ok(())
}

fn remember_failed_logout(owner: &mut Owner, receipt: &str) -> ResultType<()> {
    if owner.failure.is_none() && owner.last_receipt.as_deref() == Some(receipt) {
        if let Some(original) = owner.observed.clone() {
            owner.failure = Some(FailedTransition { receipt: Some(receipt.to_owned()), original,
                owned: None, uncertain_tombstone: None, completed: false });
        }
    }
    owner.retire()
}

fn logout_scoped(receipt: &str) -> ResultType<String> {
    validate_receipt(receipt, RecordKind::Account)?;
    let mut owner = owner()?;
    let recovery = owner.failure.as_ref().is_some_and(|failure| failure.receipt.as_deref() == Some(receipt));
    let scope = if recovery { None } else {
        match api::scope() {
            Ok(scope) => Some(scope),
            Err(error) => { remember_failed_logout(&mut owner, receipt)?; return Err(error); }
        }
    };
    let mut store = match Store::open() {
        Ok(store) => store,
        Err(error) => { remember_failed_logout(&mut owner, receipt)?; return Err(error.into()); }
    };
    owner.initialize_incarnation();
    let result = (|| {
        let mut account = match store.read_account() {
            Ok(Some(account)) => account,
            Ok(None) => {
                ensure!(!owner.observed.as_ref().is_some_and(|old| old.epoch != 0),
                    "Durable account generation record disappeared");
                let initial_scope = match &scope { Some(scope) => scope.clone(), None => api::scope()? };
                AccountRecord::empty(initial_scope, 0)
            }
            Err(error) => { remember_failed_logout(&mut owner, receipt)?; return Err(error.into()); }
        };
        if recovery {
            let stamp = Stamp::new(&store, &account);
            ensure!(owner.failure.as_ref().is_some_and(|failure|
                failure.receipt.as_deref() == Some(receipt) && failure.permits(&stamp, &account)),
                "Failed logout receipt cannot revoke a newer account");
        } else {
            let scope = scope.ok_or_else(|| anyhow!("Account scope unavailable"))?;
            owner.synchronize(&store, &account, api::server(), scope)?;
            ensure!(receipt == owner.issue_account_receipt(&store, &account)?, "Account operation receipt is stale");
        }
        let old_scope = account.scope.clone();
        revoke(&mut owner, &mut store, &mut account, old_scope, Some(receipt.to_owned()))?;
        if let Ok(scope) = api::scope() {
            if account.scope == scope { owner.bind(&store, &account, api::server(), scope); }
        }
        let result = owner.issue_account_receipt(&store, &account)?;
        if let Some(failure) = owner.failure.as_mut() { failure.completed = true; }
        Ok(result)
    })();
    if result.is_err() && owner.failure.is_none() && owner.last_receipt.as_deref() == Some(receipt) {
        remember_failed_logout(&mut owner, receipt)?;
    }
    finish(&mut owner, store, result)
}

pub fn change_server_configuration<F: FnOnce()>(update: F) -> ResultType<()> {
    let mut owner = owner()?;
    // The configuration closure is an explicit configuration mutation, not an
    // old credential snapshot. It always revokes the freshly read durable owner
    // under the same OS lock before changing the selected server/trust options.
    if owner.failure.is_none() {
        if let Some(original) = owner.observed.clone() {
            owner.failure = Some(FailedTransition { receipt: None, original,
                owned: None, uncertain_tombstone: None, completed: false });
        }
    }
    owner.retire()?;
    let mut store = Store::open()?;
    owner.initialize_incarnation();
    let result = (|| {
        let mut update = Some(update);
        let mut account = match store.read_account()? {
            Some(account) => account,
            None => {
                ensure!(!owner.observed.as_ref().is_some_and(|old| old.epoch != 0),
                    "Durable account generation record disappeared");
                let scope = match api::scope() {
                    Ok(scope) => scope,
                    Err(_) => {
                        if let Some(update) = update.take() { update(); }
                        api::scope()?
                    }
                };
                AccountRecord::empty(scope, 0)
            }
        };
        let old_scope = account.scope.clone();
        revoke(&mut owner, &mut store, &mut account, old_scope, None)?;
        if let Some(update) = update.take() { update(); }
        // FnOnce() cannot expose write errors swallowed by the Config writer.
        let scope = api::scope()?;
        if account.scope != scope {
            account.scope = scope.clone();
            if let Some(failure) = owner.failure.as_mut() {
                failure.uncertain_tombstone = Some(Stamp::new(&store, &account));
            }
            store.write_account(&account)?;
            if let Some(failure) = owner.failure.as_mut() {
                failure.owned = Some(Stamp::new(&store, &account));
                failure.uncertain_tombstone = None;
            }
        }
        owner.bind(&store, &account, api::server(), scope);
        owner.issue_account_receipt(&store, &account)?;
        if let Some(failure) = owner.failure.as_mut() { failure.completed = true; }
        Ok(())
    })();
    finish(&mut owner, store, result)
}

pub fn begin_auth(receipt: &str) -> ResultType<AuthAttempt> {
    with_current(Some((RecordKind::Account, receipt)), |owner, _, _| {
        owner.auth_serial = owner.auth_serial.checked_add(1)
            .ok_or_else(|| anyhow!("Account authentication generation exhausted"))?;
        let context = owner.context()?;
        let generation = owner.auth_serial;
        owner.attempt = Some(AttemptWitness { origin: context.clone(), serial: generation,
            receipt: receipt.to_owned(), committed_generation: None });
        Ok(AuthAttempt { context, generation })
    })
}

pub fn auth_is_current(attempt: &AuthAttempt) -> ResultType<bool> {
    with_current(None, |owner, store, account| {
        Ok(owner.attempt_matches(attempt, &owner.receipt(store, account, RecordKind::Account)?))
    })
}

pub fn cancel_auth(attempt: &AuthAttempt) -> ResultType<()> {
    let mut owner = owner()?;
    ensure!(owner.attempt.as_ref().is_some_and(|value|
        value.serial == attempt.generation && value.origin == attempt.context),
        "OIDC authentication attempt is no longer current");
    owner.attempt = None;
    Ok(())
}

pub fn commit_oidc(attempt: &AuthAttempt, token: String, user_info: String,
    remember_me: bool) -> ResultType<String>
{
    let token = SecretBytes::from_string(token);
    let user_info = SecretBytes::from_string(user_info);
    ensure!(!token.is_empty() && token.bytes().len() <= MAX_TOKEN_BYTES,
        "OIDC access token is empty or exceeds its size bound");
    ensure!(user_info.bytes().len() <= MAX_USER_INFO_BYTES, "OIDC metadata exceeds its size bound");
    with_current(None, |owner, store, account| {
        let receipt = owner.receipt(store, account, RecordKind::Account)?;
        ensure!(owner.attempt_matches(attempt, &receipt)
            && owner.attempt.as_ref().is_some_and(|value| value.committed_generation.is_none()),
            "OIDC authentication attempt is no longer current");
        replace_account(owner, store, account, token, user_info, remember_me, &receipt)?;
        let committed = owner.issue_account_receipt(store, account)?;
        owner.attempt = Some(AttemptWitness { origin: attempt.context.clone(), serial: attempt.generation,
            receipt: committed.clone(), committed_generation: Some(owner.generation) });
        Ok(committed)
    })
}

pub(super) fn save_cache(receipt: &str, kind: RecordKind,
    prepare: impl FnOnce(&[u8]) -> ResultType<SecretBytes>) -> ResultType<String>
{
    with_current(Some((kind, receipt)), |owner, store, account| {
        ensure!(!owner.token(account).is_empty(), "Cannot save a cache without an active account");
        let json = prepare(owner.token(account))?;
        let remembered = owner.session.is_none();
        account.advance_cache(kind, remembered)?;
        if remembered { store.write_cache(kind, account, json.bytes())?; }
        // Commit point, also for session-only cache revisions. A session-only
        // control never claims there is a persisted token-bearing cache file.
        store.write_account(account)?;
        if !remembered { *owner.memory_cache_mut(kind)? = Some(json); }
        owner.memory_cache_revisions[cache_index(kind)?] = account.revision(kind)?;
        store.prune_cache(kind, account)?;
        owner.receipt(store, account, kind)
    })
}

pub(super) fn load_cache<T>(receipt: &str, kind: RecordKind,
    read: impl FnOnce(Option<SecretBytes>, &[u8]) -> ResultType<T>) -> ResultType<T>
{
    with_current(Some((kind, receipt)), |owner, store, account| {
        let index = cache_index(kind)?;
        if owner.memory_cache_revisions[index] != account.revision(kind)? {
            *owner.memory_cache_mut(kind)? = None;
        }
        let json = if owner.session.is_some() {
            owner.memory_cache(kind)?.as_ref().map(|value| SecretBytes::from_slice(value.bytes()))
        } else { store.read_cache(kind, account)? };
        let result = read(json, owner.token(account))?;
        owner.memory_cache_revisions[index] = account.revision(kind)?;
        Ok(result)
    })
}

pub(super) fn clear_cache(receipt: &str, kind: RecordKind) -> ResultType<String> {
    with_current(Some((kind, receipt)), |owner, store, account| {
        account.advance_cache(kind, false)?;
        store.write_account(account)?;
        *owner.memory_cache_mut(kind)? = None;
        owner.memory_cache_revisions[cache_index(kind)?] = account.revision(kind)?;
        store.remove_cache(kind)?;
        // Neither the token, account receipt nor the other kind was changed.
        owner.receipt(store, account, kind)
    })
}
