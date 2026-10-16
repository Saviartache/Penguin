//! Обфускатор как слой над UDP-сокетом, под QUIC (без GSO/GRO, поэтому без
//! обфускации берётся сокет quinn, см. [`crate::transport::quic`]).

#[cfg(feature = "obfs-gecko")]
pub mod gecko;
#[cfg(feature = "obfs-salamander")]
pub mod salamander;

/// Преобразование пакета перед отправкой и после приёма; без аллокаций.
pub trait Obfuscator: Send + Sync + std::fmt::Debug + 'static {
    /// Удлинение пакета; на него уменьшается размер датаграммы QUIC.
    fn overhead(&self) -> usize;

    /// Обфусцирует `input` в `output`; `None`, если `output` мал. Не паникует.
    fn obfuscate(&self, input: &[u8], output: &mut [u8]) -> Option<usize>;

    /// Снимает обфускацию на месте, возвращает длину результата; `None` — чужой пакет.
    fn deobfuscate(&self, buf: &mut [u8]) -> Option<usize>;
}
