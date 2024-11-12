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

use crate::encryption::EncryptorDecryptor;
uniffi::include_scaffolding!("logins");

pub use crate::db::LoginDb;
use crate::encryption::{check_canary, create_canary, create_key};
pub use crate::error::*;
pub use crate::login::*;
pub use crate::store::*;
pub use crate::sync::LoginsSyncEngine;
