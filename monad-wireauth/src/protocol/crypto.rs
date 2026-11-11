// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use super::{common::*, errors::CryptoError};

pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_secp256k1_AEGIS128L_BLAKE3";
pub const IDENTIFIER: &[u8] = b"authenticated udp v1 -- monad";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";

pub fn encrypt_in_place(
    key: &CipherKey,
    nonce: &CipherNonce,
    data: &mut [u8],
    ad: &[u8],
) -> [u8; 16] {
    let cipher = aegis::aegis128l::Aegis128L::<16>::new(key.as_ref(), nonce.as_ref());
    cipher.encrypt_in_place(data, ad)
}

/// Encrypt shared plaintext directly into caller-owned storage.
pub fn encrypt_into(
    key: &CipherKey,
    nonce: &CipherNonce,
    plaintext: &[u8],
    ciphertext: &mut [u8],
    ad: &[u8],
) -> [u8; 16] {
    let cipher = aegis::aegis128l::Aegis128L::<16>::new(key.as_ref(), nonce.as_ref());
    cipher.encrypt_into(plaintext, ciphertext, ad)
}

pub fn decrypt_in_place(
    key: &CipherKey,
    nonce: &CipherNonce,
    data: &mut [u8],
    tag: &[u8; 16],
    ad: &[u8],
) -> Result<(), CryptoError> {
    let cipher = aegis::aegis128l::Aegis128L::<16>::new(key.as_ref(), nonce.as_ref());
    cipher
        .decrypt_in_place(data, tag, ad)
        .map_err(|_| CryptoError::MacVerificationFailed)
}

#[macro_export]
macro_rules! hash {
    ($data:expr) => {{
        use $crate::protocol::common::HashOutput;
        HashOutput(blake3::hash($data).into())
    }};
    ($data1:expr, $data2:expr) => {{
        use $crate::protocol::common::HashOutput;
        let mut hasher = blake3::Hasher::new();
        hasher.update($data1);
        hasher.update($data2);
        HashOutput(hasher.finalize().into())
    }};
    ($data1:expr, $data2:expr, $data3:expr) => {{
        use $crate::protocol::common::HashOutput;
        let mut hasher = blake3::Hasher::new();
        hasher.update($data1);
        hasher.update($data2);
        hasher.update($data3);
        HashOutput(hasher.finalize().into())
    }};
}

#[macro_export]
macro_rules! keyed_hash {
    ($key:expr, $data:expr) => {{
        use $crate::protocol::common::HashOutput;
        HashOutput(blake3::keyed_hash($key, $data).into())
    }};
    ($key:expr, $data1:expr, $data2:expr) => {{
        use $crate::protocol::common::HashOutput;
        let mut hasher = blake3::Hasher::new_keyed($key);
        hasher.update($data1);
        hasher.update($data2);
        HashOutput(hasher.finalize().into())
    }};
    ($key:expr, $data1:expr, $data2:expr, $data3:expr) => {{
        use $crate::protocol::common::HashOutput;
        let mut hasher = blake3::Hasher::new_keyed($key);
        hasher.update($data1);
        hasher.update($data2);
        hasher.update($data3);
        HashOutput(hasher.finalize().into())
    }};
}

pub fn verify_keyed_hash(key: &HashOutput, data: &[u8], tag: &[u8; 16]) -> Result<(), CryptoError> {
    let computed: MacTag = keyed_hash!(key.as_ref(), data).into();
    if computed == *tag {
        Ok(())
    } else {
        Err(CryptoError::MacVerificationFailed)
    }
}

pub fn ecdh(private_key: &monad_secp::KeyPair, public_key: &monad_secp::PubKey) -> SharedSecret {
    SharedSecret(private_key.ecdh(public_key))
}

pub fn verify_mac1<M: crate::messages::MacMessage>(
    message: &M,
    static_public: &monad_secp::PubKey,
) -> Result<(), CryptoError> {
    let mac_key = hash!(LABEL_MAC1, &static_public.bytes_compressed());
    verify_keyed_hash(&mac_key, message.mac1_input(), message.mac1().as_ref())
}

pub fn verify_mac2<M: crate::messages::MacMessage>(
    message: &M,
    static_public: &monad_secp::PubKey,
    cookie: &[u8; 16],
) -> Result<(), CryptoError> {
    let cookie_key = hash!(LABEL_COOKIE, &static_public.bytes_compressed());
    let expected_mac2: MacTag =
        keyed_hash!(cookie_key.as_ref(), message.mac2_input(), cookie).into();
    if message.mac2() == &expected_mac2 {
        Ok(())
    } else {
        Err(CryptoError::MacVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_into_matches_aegis_05_wire_bytes() {
        let key = CipherKey::from(&HashOutput([7; 32]));
        let plaintext = b"wireauth shared plaintext";
        let mut ciphertext = vec![0xa5; plaintext.len()];
        let tag = encrypt_into(&key, &9.into(), plaintext, &mut ciphertext, b"header");
        // Generated with the previous aegis 0.5.0 one-shot implementation.
        assert_eq!(
            hex::encode(&ciphertext),
            "114029c2d59d15f572af6723e95a148dca1746069671d4e09e"
        );
        assert_eq!(hex::encode(tag), "b9f0bd4703fa55c5efa22b06d31f0239");
        decrypt_in_place(&key, &9.into(), &mut ciphertext, &tag, b"header").unwrap();
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn encrypt_into_matches_one_shot_at_block_and_packet_boundaries() {
        let key = CipherKey::from(&HashOutput([7; 32]));
        for size in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1440, 1472, 65_507] {
            let plaintext: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            for ad in [&b""[..], &b"header"[..]] {
                for nonce in [0_u64, 1, u64::MAX] {
                    let nonce = nonce.into();
                    let mut in_place = plaintext.clone();
                    let expected_tag = encrypt_in_place(&key, &nonce, &mut in_place, ad);
                    let mut output = vec![0xa5; size];
                    let tag = encrypt_into(&key, &nonce, &plaintext, &mut output, ad);
                    assert_eq!(tag, expected_tag, "size={size}");
                    assert_eq!(output, in_place, "size={size}");
                }
            }
        }
    }
}
