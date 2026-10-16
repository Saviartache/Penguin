//! Устройство smoltcp поверх двух очередей: `rx` — пакеты снаружи, `tx` — собранные стеком.

use std::collections::VecDeque;

use bytes::BytesMut;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};

/// Пакетов на одну аллокацию буфера передачи.
const TX_BATCH: usize = 16;

/// Очереди пакетов между источником и smoltcp.
pub struct VirtualDevice {
    rx: VecDeque<BytesMut>,
    tx: VecDeque<BytesMut>,
    /// Общий буфер под собираемые пакеты: аллокация раз в [`TX_BATCH`] пакетов.
    scratch: BytesMut,
    mtu: usize,
}

impl VirtualDevice {
    /// Заводит устройство с заданным MTU.
    pub fn new(mtu: u16) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            scratch: BytesMut::new(),
            mtu: usize::from(mtu),
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

    fn tx_token(&mut self) -> TxTokenImpl<'_> {
        TxTokenImpl {
            tx: &mut self.tx,
            scratch: &mut self.scratch,
            mtu: self.mtu,
        }
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
        Some((RxTokenImpl { packet }, self.tx_token()))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(self.tx_token())
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
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
    scratch: &'a mut BytesMut,
    mtu: usize,
}

impl TxToken for TxTokenImpl<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        if self.scratch.capacity() < len {
            self.scratch.reserve(TX_BATCH * self.mtu.max(len));
        }
        self.scratch.resize(len, 0);
        let result = f(self.scratch);
        self.tx.push_back(self.scratch.split());
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
    fn consecutive_packets_stay_separate() {
        let mut device = VirtualDevice::new(1280);
        let now = smoltcp::time::Instant::from_micros(0);

        for payload in [&b"one"[..], b"three", b"2"] {
            let tx = device.transmit(now).expect("передатчик есть");
            tx.consume(payload.len(), |buffer| buffer.copy_from_slice(payload));
        }
        assert_eq!(&device.take_tx().expect("пакет")[..], b"one");
        assert_eq!(&device.take_tx().expect("пакет")[..], b"three");
        assert_eq!(&device.take_tx().expect("пакет")[..], b"2");
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
        let device = VirtualDevice::new(1420);
        assert_eq!(device.capabilities().max_transmission_unit, 1420);
        assert_eq!(device.capabilities().medium, Medium::Ip);
    }
}
