//! AES-128-GCM заголовков: всегда, независимо от шифра тела.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

use crate::error::{VmessError, VmessResult};

fn key_of(key: &[u8; 16]) -> VmessResult<LessSafeKey> {
    UnboundKey::new(&ring::aead::AES_128_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| VmessError::malformed("ключ заголовка не той длины"))
}

/// Шифрует `plain`, заверяя `aad`; метка дописана в конец.
pub fn seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> VmessResult<Vec<u8>> {
    let mut buffer = Vec::with_capacity(plain.len() + 16);
    buffer.extend_from_slice(plain);
    key_of(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buffer,
        )
        .map_err(|_| VmessError::malformed("заголовок не зашифровался"))?;
    Ok(buffer)
}

/// Расшифровывает на месте; `Err` — метка не сошлась.
pub fn open<'a>(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &'a mut [u8],
) -> VmessResult<&'a mut [u8]> {
    key_of(key)?
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            ciphertext_and_tag,
        )
        .map_err(|_| VmessError::malformed("заголовок не расшифровался: метка не сошлась"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_sealed_can_be_opened() {
        let key = [7u8; 16];
        let nonce = [1u8; 12];
        let aad = b"aad";

        let mut sealed = seal(&key, &nonce, aad, b"payload").expect("шифруется");
        let opened = open(&key, &nonce, aad, &mut sealed).expect("расшифровывается");
        assert_eq!(opened, b"payload");
    }

    #[test]
    fn a_wrong_key_is_rejected() {
        let nonce = [1u8; 12];
        let mut sealed = seal(&[1u8; 16], &nonce, b"aad", b"payload").expect("шифруется");
        assert!(open(&[2u8; 16], &nonce, b"aad", &mut sealed).is_err());
    }

    #[test]
    fn a_wrong_aad_is_rejected() {
        let key = [7u8; 16];
        let nonce = [1u8; 12];
        let mut sealed = seal(&key, &nonce, b"aad-one", b"payload").expect("шифруется");
        assert!(open(&key, &nonce, b"aad-two", &mut sealed).is_err());
    }
}
