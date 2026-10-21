//! Имя профиля NLA через Network List Manager, только для заданного адаптера.

#![allow(unsafe_code, reason = "Network List Manager и IP Helper")]

use windows::Win32::Foundation::E_INVALIDARG;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::NetworkListManager::{
    INetwork, INetworkListManager, NLM_ENUM_NETWORK_ALL, NetworkListManager,
};
use windows::Win32::System::Com::{CLSCTX_ALL, CoCreateInstance};
use windows::core::{BSTR, GUID};

use crate::{PlatformError, PlatformResult};

/// Задаёт сети адаптера имя с римским номером; `false` — NLA ещё не создала профиль.
pub fn rename(index: u32, base: &str) -> PlatformResult<bool> {
    let _apartment = crate::com::Apartment::enter();
    // SAFETY: COM живёт на текущем потоке; указатели ведут на локальные структуры.
    unsafe { rename_inner(index, base) }
        .map_err(|error| PlatformError::Interface(format!("имя сети: {error}")))
}

unsafe fn rename_inner(index: u32, base: &str) -> windows::core::Result<bool> {
    unsafe {
        let mut luid = NET_LUID_LH::default();
        ConvertInterfaceIndexToLuid(index, &mut luid).ok()?;
        let mut adapter = GUID::zeroed();
        ConvertInterfaceLuidToGuid(&luid, &mut adapter).ok()?;
        let manager: INetworkListManager = CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL)?;
        let Some(network) = find_network(&manager, adapter)? else {
            return Ok(false);
        };
        if !belongs_to_adapter(&network, adapter)? {
            return Ok(false);
        }
        let id = network.GetNetworkId()?;
        let current = network.GetName()?.to_string();
        let networks = manager.GetNetworks(NLM_ENUM_NETWORK_ALL)?;
        let mut names = Vec::new();
        loop {
            let mut row = [None];
            let mut fetched = 0;
            networks.Next(&mut row, Some(&mut fetched))?;
            if fetched == 0 {
                break;
            }
            if let Some(other) = row[0].take()
                && other.GetNetworkId()? != id
            {
                names.push(other.GetName()?.to_string());
            }
        }
        let name = super::naming::next(base, &current, &names).ok_or_else(|| {
            windows::core::Error::new(
                E_INVALIDARG,
                "имя сети с римским номером длиннее 128 символов",
            )
        })?;
        if name != current {
            network.SetName(&BSTR::from(&name))?;
            tracing::info!(%name, "имя сети назначено");
        }
        Ok(true)
    }
}

unsafe fn find_network(
    manager: &INetworkListManager,
    adapter: GUID,
) -> windows::core::Result<Option<INetwork>> {
    unsafe {
        let connections = manager.GetNetworkConnections()?;
        loop {
            let mut row = [None];
            let mut fetched = 0;
            connections.Next(&mut row, Some(&mut fetched))?;
            if fetched == 0 {
                return Ok(None);
            }
            if let Some(connection) = row[0].take()
                && connection.GetAdapterId()? == adapter
            {
                return connection.GetNetwork().map(Some);
            }
        }
    }
}

unsafe fn belongs_to_adapter(network: &INetwork, adapter: GUID) -> windows::core::Result<bool> {
    unsafe {
        let connections = network.GetNetworkConnections()?;
        loop {
            let mut row = [None];
            let mut fetched = 0;
            connections.Next(&mut row, Some(&mut fetched))?;
            if fetched == 0 {
                return Ok(true);
            }
            if let Some(connection) = row[0].take()
                && connection.GetAdapterId()? != adapter
                && connection.IsConnected()?.as_bool()
            {
                return Ok(false);
            }
        }
    }
}
