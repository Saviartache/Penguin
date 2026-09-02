//! `ProxyStream` — двунаправленный поток байт до целевого адреса.

use tokio::io::{AsyncRead, AsyncWrite};

/// Поток до целевого адреса.
///
/// Отдельный трейт вместо `AsyncRead + AsyncWrite` нужен ровно затем, чтобы
/// `Box<dyn ProxyStream>` был законным типом: связка нескольких трейтов
/// в `dyn` не выражается.
///
/// `Send`, но не `Sync`: поток принадлежит одной задаче и между потоками
/// исполнения перемещается, а не разделяется. Требовать `Sync` значило бы
/// запретить реализации держать внутри что угодно с внутренней
/// изменяемостью — например, отложенное чтение ответа сервера.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
