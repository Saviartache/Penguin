//! Устройство smoltcp поверх очередей.
//!
//! Своё, а не готовое: пакеты приходят из асинхронного источника, а `Device`
//! синхронен. Очереди и есть тот шов, где одно превращается в другое.
//!
//! Одно на два стека. Со стороны TUN в `rx` кладут пакеты от системы, а из
//! `tx` забирают ответы приложению; со стороны тоннеля — наоборот, в `rx`
//! ложатся пакеты, пришедшие от сервера, а из `tx` уходят наши. Устройству
//! всё равно: у него нет стороны, есть две очереди.

use std::collections::VecDeque;

use bytes::BytesMut;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};

/// Очереди пакетов между источником и smoltcp.
pub struct VirtualDevice {
    rx: VecDeque<BytesMut>,
    tx: VecDeque<BytesMut>,
    mtu: usize,
}

impl VirtualDevice {
    /// Заводит устройство с заданным MTU.
    pub fn new(mtu: u16) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: mtu as usize,
        }
    }

    /// Кладёт пакет, пришедший снаружи, — его разберёт smoltcp.
    pub fn queue_rx(&mut self, packet: BytesMut) {
        self.rx.push_back(packet);
    }

    /// Кладёт пакет мимо smoltcp — так уходят датаграммы UDP.
    pub fn queue_tx(&mut self, packet: BytesMut) {
        self.tx.push_back(packet);
    }

    /// Забирает пакет, собранный стеком.
    pub fn take_tx(&mut self) -> Option<BytesMut> {
        self.tx.pop_front()
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        // Пара токенов: стеку может понадобиться ответить на тот же пакет, и
        // передатчик выдаётся вместе с приёмником.
        Some((RxTokenImpl { packet }, TxTokenImpl { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenImpl { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        // `Ip`, а не `Ethernet`: канального заголовка нет ни у TUN, ни у
        // тоннеля, и ARP тут не нужен.
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Токен приёма: отдаёт пакет стеку.
pub struct RxTokenImpl {
    packet: BytesMut,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.packet)
    }
}

/// Токен передачи: принимает пакет от стека.
pub struct TxTokenImpl<'a> {
    tx: &'a mut VecDeque<BytesMut>,
}

impl TxToken for TxTokenImpl<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = BytesMut::zeroed(len);
        let result = f(&mut packet);
        self.tx.push_back(packet);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_carries_packets_both_ways() {
        let mut device = VirtualDevice::new(1280);
        device.queue_rx(BytesMut::from(&b"incoming"[..]));

        let now = smoltcp::time::Instant::from_micros(0);
        let (rx, _tx) = device.receive(now).expect("пакет есть");
        let got = rx.consume(|packet| packet.to_vec());
        assert_eq!(got, b"incoming");

        let tx = device.transmit(now).expect("передатчик есть");
        tx.consume(4, |buffer| buffer.copy_from_slice(b"out!"));
        assert_eq!(&device.take_tx().expect("пакет есть")[..], b"out!");
    }

    #[test]
    fn empty_device_yields_nothing() {
        let mut device = VirtualDevice::new(1280);
        assert!(
            device
                .receive(smoltcp::time::Instant::from_micros(0))
                .is_none()
        );
        assert!(device.take_tx().is_none());
    }

    #[test]
    fn the_mtu_reaches_smoltcp() {
        // Соврать здесь — значит объявить стеку MSS, который не пройдёт, и
        // получить страницу, которая грузится наполовину.
        let device = VirtualDevice::new(1420);
        assert_eq!(device.capabilities().max_transmission_unit, 1420);
        assert_eq!(device.capabilities().medium, Medium::Ip);
    }
}
