/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(unknown_lints)]
#![warn(rust_2018_idioms)]

#[macro_use]
mod error;
mod login;

mod db;
pub mod encryption;
mod schema;
mod store;
mod sync;
mod util;

use crate::encryption::EncryptorDecryptorTrait;
uniffi::include_scaffolding!("logins");

pub use crate::db::LoginDb;
use crate::encryption::{check_canary, create_canary, create_key};
pub use crate::error::*;
pub use crate::login::*;
pub use crate::store::*;
pub use crate::sync::LoginsSyncEngine;
use std::sync::Arc;

// Public encryption functions.  We publish these as top-level functions to expose them across
// UniFFI
#[handle_error(Error)]
fn encrypt_login(login: Login, enc_key: &str) -> ApiResult<EncryptedLogin> {
    let encdec = encryption::ManagedEncryptorDecryptor::new(Arc::new(
        encryption::StaticKeyManager::new(enc_key.into()),
    ));
    login.encrypt(Arc::new(encdec))
}

#[handle_error(Error)]
fn decrypt_login(login: EncryptedLogin, enc_key: &str) -> ApiResult<Login> {
    let encdec = encryption::ManagedEncryptorDecryptor::new(Arc::new(
        encryption::StaticKeyManager::new(enc_key.into()),
    ));
    login.decrypt(Arc::new(encdec))
}

#[handle_error(Error)]
fn encrypt_fields(sec_fields: SecureLoginFields, enc_key: &str) -> ApiResult<String> {
    let encdec = encryption::ManagedEncryptorDecryptor::new(Arc::new(
        encryption::StaticKeyManager::new(enc_key.into()),
    ));
    sec_fields.encrypt(Arc::new(encdec))
}

#[handle_error(Error)]
fn decrypt_fields(sec_fields: String, enc_key: &str) -> ApiResult<SecureLoginFields> {
    let encdec = encryption::ManagedEncryptorDecryptor::new(Arc::new(
        encryption::StaticKeyManager::new(enc_key.into()),
    ));
    SecureLoginFields::decrypt(&sec_fields, Arc::new(encdec))
}
