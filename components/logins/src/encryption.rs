/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// This is the *local* encryption support - it has nothing to do with the
// encryption used by sync.

// For context, what "local encryption" means in this context is:
// * We use regular sqlite, but ensure that sensitive data is encrypted in the DB in the
//   `secure_fields` column.  The encryption key is managed by the app.
// * The `decrypt_struct` and `encrypt_struct` functions are used to convert between an encrypted
//   `secure_fields` string and a decrypted `SecureFields` struct
// * Most API functions return `EncryptedLogin` which has its data encrypted.
//
// This makes life tricky for Sync - sync has its own encryption and its own
// management of sync keys. The entire records are encrypted on the server -
// so the record on the server has the plain-text data (which is then
// encrypted as part of the entire record), so:
// * When transforming a record from the DB into a Sync record, we need to
//   *decrypt* the data.
// * When transforming a record from Sync into a DB record, we need to *encrypt*
//   the data.
//
// So Sync needs to know the key etc, and that needs to get passed down
// multiple layers, from the app saying "sync now" all the way down to the
// low level sync code.
// To make life a little easier, we do that via a struct.

use crate::error::*;
use std::sync::Arc;

pub trait EncryptorDecryptor: Send + Sync {
    fn encrypt(&self, cleartext: Vec<u8>, description: String) -> ApiResult<Vec<u8>>;
    fn decrypt(&self, ciphertext: Vec<u8>, description: String) -> ApiResult<Vec<u8>>;
}

pub trait KeyManager: Send + Sync {
    fn get_key(&self) -> ApiResult<Vec<u8>>;
}

pub struct ManagedEncryptorDecryptor {
    key_manager: Arc<dyn KeyManager>,
}

impl ManagedEncryptorDecryptor {
    pub fn new(key_manager: Arc<dyn KeyManager>) -> Self {
        Self { key_manager }
    }
}

impl EncryptorDecryptor for ManagedEncryptorDecryptor {
    #[handle_error(Error)]
    fn encrypt(&self, cleartext: Vec<u8>, description: String) -> ApiResult<Vec<u8>> {
        let key = self
            .key_manager
            .get_key()
            .map_err(|_| Error::EncryptionKeyMissing)?;

        let encdec = jwcrypto::EncryptorDecryptor::new(std::str::from_utf8(&key)?)?;
        encdec
            .encrypt(std::str::from_utf8(&cleartext)?, &description)
            .map(|text| text.into())
    }

    #[handle_error(Error)]
    fn decrypt(&self, ciphertext: Vec<u8>, description: String) -> ApiResult<Vec<u8>> {
        let key = self
            .key_manager
            .get_key()
            .map_err(|_| Error::EncryptionKeyMissing)?;
        let encdec = jwcrypto::EncryptorDecryptor::new(std::str::from_utf8(&key)?)?;
        encdec
            .decrypt(std::str::from_utf8(&ciphertext)?, &description)
            .map(|text| text.into())
    }
}

// StaticKeyManager is temporary struct to ease transition of sync engine merge crypto
pub struct StaticKeyManager {
    pub key: String,
}
impl StaticKeyManager {
    pub fn new(key: String) -> Self {
        Self { key }
    }
}
impl KeyManager for StaticKeyManager {
    #[handle_error(Error)]
    fn get_key(&self) -> ApiResult<Vec<u8>> {
        Ok(self.key.as_bytes().into())
    }
}

#[handle_error(Error)]
pub fn create_canary(text: &str, key: &str) -> ApiResult<String> {
    jwcrypto::EncryptorDecryptor::new(key)?.create_canary(text)
}

#[handle_error(Error)]
pub fn check_canary(canary: &str, text: &str, key: &str) -> ApiResult<bool> {
    jwcrypto::EncryptorDecryptor::new(key)?.check_canary(canary, text)
}

#[handle_error(Error)]
pub fn create_key() -> ApiResult<String> {
    jwcrypto::EncryptorDecryptor::create_key()
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use serde::{de::DeserializeOwned, Serialize};

    lazy_static::lazy_static! {
        pub static ref TEST_ENCRYPTION_KEY: String = serde_json::to_string(&jwcrypto::Jwk::new_direct_key(Some("test-key".to_string())).unwrap()).unwrap();
    }

    struct TestKeyManager {}
    impl KeyManager for TestKeyManager {
        fn get_key(&self) -> ApiResult<Vec<u8>> {
            Ok(TEST_ENCRYPTION_KEY.as_bytes().into())
        }
    }

    lazy_static::lazy_static! {
        pub static ref TEST_ENCDEC: Arc<ManagedEncryptorDecryptor> = Arc::new(ManagedEncryptorDecryptor::new(Arc::new(TestKeyManager {})));
    }

    pub fn encrypt_struct<T: Serialize>(fields: &T) -> String {
        let string = serde_json::to_string(fields).unwrap();
        let cipherbytes = TEST_ENCDEC
            .clone()
            .encrypt(string.as_bytes().into(), "test encrypt struct".to_owned())
            .unwrap();
        std::str::from_utf8(&cipherbytes).unwrap().to_owned()
    }
    pub fn decrypt_struct<T: DeserializeOwned>(ciphertext: String) -> T {
        let jsonbytes = TEST_ENCDEC
            .clone()
            .decrypt(
                ciphertext.as_bytes().into(),
                "test decrypt struct".to_owned(),
            )
            .unwrap();
        serde_json::from_str(std::str::from_utf8(&jsonbytes).unwrap()).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt() {
        let ed: jwcrypto::EncryptorDecryptor<Error> =
            jwcrypto::EncryptorDecryptor::new(&create_key().unwrap()).unwrap();
        let cleartext = "secret";
        let ciphertext = ed.encrypt(cleartext, "test encrypt").unwrap();
        assert_eq!(ed.decrypt(&ciphertext, "test decrypt").unwrap(), cleartext);
        let ed2 = jwcrypto::EncryptorDecryptor::new(&create_key().unwrap()).unwrap();
        assert!(matches!(
            ed2.decrypt(&ciphertext, "test decrypt").err().unwrap(),
            Error::CryptoError(jwcrypto::EncryptorDecryptorError { description, .. })
            if description == "test decrypt"
        ));
    }

    #[test]
    fn test_key_error() {
        let storage_err = jwcrypto::EncryptorDecryptor::new("bad-key").err().unwrap();
        assert!(matches!(
            storage_err,
            Error::CryptoError(jwcrypto::EncryptorDecryptorError {
                from: jwcrypto::JwCryptoError::InvalidKey,
                ..
            })
        ));
    }

    #[test]
    fn test_canary_functionality() {
        const CANARY_TEXT: &str = "Arbitrary sequence of text";
        let key = create_key().unwrap();
        let canary = create_canary(CANARY_TEXT, &key).unwrap();
        assert!(check_canary(&canary, CANARY_TEXT, &key).unwrap());

        let different_key = create_key().unwrap();
        assert!(matches!(
            check_canary(&canary, CANARY_TEXT, &different_key)
                .err()
                .unwrap(),
            LoginsApiError::IncorrectKey
        ));
    }
}
