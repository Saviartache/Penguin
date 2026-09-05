//! Нонс: двенадцать байт, которые вдобавок служат солью для вывода ключа.
//!
//! # Почему это не `penguin_transport::aead`
//!
//! У общего кадра нонс каждого направления всегда начинается с нуля, а соль
//! нужна только для вывода ключа. У Brook соль **и есть** нонс: те же двенадцать
//! случайных байт идут на вход HKDF и без изменений становятся первым
//! значением счётчика AES-GCM. Подставить сюда общий шифр значит завести
//! второй, настоящий нонс поверх этого — и разойтись с сервером на первом же
//! кадре.
//!
//! # Как считается следующее значение
//!
//! Эталон (`nonce.go` в `txthinking/brook`, ревизия `5cd13ef`) двигает только
//! первые восемь байт, как число с младшим байтом впереди:
//!
//! ```text
//! i := binary.LittleEndian.Uint64(b[:8])
//! i += 1
//! binary.LittleEndian.PutUint64(b[:8], i)
//! ```
//!
//! Последние четыре байта не трогаются никогда — в отличие от общего кадра,
//! где переполнение первых восьми несёт единицу дальше. На числе посылок,
//! какое вообще бывает в одном соединении, разницы не видно, но реализация
//! обязана считать так же, как сервер, а не «почти так же».
//!
//! То же самое написано в `protocol/brook-server-protocol.md`: «add `1` to
//! the first 8 bytes according to the Little Endian 64-bit unsigned integer».

/// Длина нонса. Она же — длина соли для HKDF, и это не совпадение: одно и то
/// же значение служит обеим целям.
pub const NONCE_LEN: usize = 12;

/// Нонс на проводе.
pub type Nonce = [u8; NONCE_LEN];

/// Двигает нонс на шаг вперёд: первые восемь байт как `u64` в порядке
/// «младший байт первым», плюс один, с переносом только внутри этих восьми.
pub fn increment(nonce: &mut Nonce) {
    let mut low = [0u8; 8];
    low.copy_from_slice(&nonce[..8]);
    let value = u64::from_le_bytes(low).wrapping_add(1);
    nonce[..8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_nonce_becomes_one_in_the_low_byte() {
        let mut nonce = [0u8; NONCE_LEN];
        increment(&mut nonce);
        assert_eq!(nonce, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn the_carry_stays_inside_the_first_eight_bytes() {
        // Ключевое отличие от общего кадра: перенос за пределы первых восьми
        // байт здесь не уходит никогда, даже когда все восемь уже единицы.
        let mut nonce = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 5, 6, 7, 8];
        increment(&mut nonce);
        assert_eq!(
            &nonce[..8],
            &[0, 0, 0, 0, 0, 0, 0, 0],
            "восемь байт не обнулились"
        );
        assert_eq!(&nonce[8..], &[5, 6, 7, 8], "хвост нельзя трогать вовсе");
    }

    #[test]
    fn this_differs_from_the_generic_frame_counter_on_purpose() {
        // Общий кадр (`penguin_transport::aead::cipher`) при переполнении
        // первого байта несёт единицу в девятый: у [0xFF, 0x00, ...] это дало
        // бы [0x00, 0x01, ...]. Здесь девятый байт вообще не участвует в
        // счёте, и то же входное значение выходит другим — это и есть повод
        // не переиспользовать общий шифр для Brook.
        let mut nonce = [0xFF, 0x00, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9];
        increment(&mut nonce);
        assert_eq!(nonce[..2], [0x00, 0x01], "перенос ушёл не в тот байт");
        assert_eq!(&nonce[8..], &[9, 9, 9, 9], "хвост шевельнулся");
    }

    #[test]
    fn two_steps_add_up_like_a_plain_counter() {
        let mut nonce = [0u8; NONCE_LEN];
        increment(&mut nonce);
        increment(&mut nonce);
        assert_eq!(nonce[0], 2);
    }
}
