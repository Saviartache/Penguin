//! Поток, у которого граница куска видна снаружи.
//!
//! Датаграмма Snell — это ровно один кусок: длины внутри посылки нет, и всё,
//! что осталось после адреса, и есть данные. Байтовому чтению граница не
//! видна, и две датаграммы склеились бы в одну.
//!
//! Трейт нужен затем, что кусок у Snell бывает двух видов. До четвёртой
//! версии это кусок общего кадра ([`penguin_transport::aead`]), с четвёртой —
//! свой кадр с дополнением. Канал датаграмм устроен одинаково для обоих, и
//! знать, какой из них внизу, ему незачем.

use async_trait::async_trait;
use bytes::BytesMut;
use penguin_proto::stream::ProxyStream;
use penguin_transport::aead::ChunkStream;

use crate::v4::V4Stream;

/// Чтение и запись кусками.
#[async_trait]
pub trait Chunks: Send + 'static {
    /// Читает кусок целиком. `Ok(None)` — поток кончился.
    ///
    /// Отменяемо: разобранное лежит в самом потоке, а не в брошенной задаче.
    async fn read_chunk(&mut self) -> std::io::Result<Option<BytesMut>>;

    /// Пишет кусок целиком и доводит его до сокета.
    async fn write_chunk(&mut self, payload: &[u8]) -> std::io::Result<()>;
}

#[async_trait]
impl Chunks for ChunkStream<Box<dyn ProxyStream>> {
    async fn read_chunk(&mut self) -> std::io::Result<Option<BytesMut>> {
        ChunkStream::read_chunk(self).await
    }

    async fn write_chunk(&mut self, payload: &[u8]) -> std::io::Result<()> {
        ChunkStream::write_chunk(self, payload).await
    }
}

#[async_trait]
impl Chunks for V4Stream<Box<dyn ProxyStream>> {
    async fn read_chunk(&mut self) -> std::io::Result<Option<BytesMut>> {
        self.read_frame().await
    }

    async fn write_chunk(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.write_frame(payload).await
    }
}
