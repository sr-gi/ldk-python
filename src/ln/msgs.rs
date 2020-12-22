use pyo3::prelude::*;
use pyo3::PyObjectProtocol;

use lightning::ln::msgs::NetAddress;

#[pyclass(name=NetAddress)]
#[derive(Clone)]
pub struct PyNetAddress {
    pub inner: NetAddress,
}

#[pymethods]
impl PyNetAddress {
    #[staticmethod]
    pub fn ipv4(addr: [u8; 4], port: u16) -> Self {
        PyNetAddress {
            inner: NetAddress::IPv4 { addr, port },
        }
    }

    #[staticmethod]
    pub fn ipv6(addr: [u8; 16], port: u16) -> Self {
        PyNetAddress {
            inner: NetAddress::IPv6 { addr, port },
        }
    }

    #[staticmethod]
    pub fn onionv2(addr: [u8; 10], port: u16) -> Self {
        PyNetAddress {
            inner: NetAddress::OnionV2 { addr, port },
        }
    }

    #[staticmethod]
    pub fn onionv3(ed25519_pubkey: [u8; 32], checksum: u16, version: u8, port: u16) -> Self {
        PyNetAddress {
            inner: NetAddress::OnionV3 {
                ed25519_pubkey,
                checksum,
                version,
                port,
            },
        }
    }

    #[getter]
    fn addr(&self) -> &[u8] {
        match &self.inner {
            NetAddress::IPv4 { addr, .. } => &addr[..],
            NetAddress::IPv6 { addr, .. } => &addr[..],
            NetAddress::OnionV2 { addr, .. } => &addr[..],
            NetAddress::OnionV3 { ed25519_pubkey, .. } => &ed25519_pubkey[..],
        }
    }

    #[getter]
    fn port(&self) -> u16 {
        match self.inner {
            NetAddress::IPv4 { port, .. } => port,
            NetAddress::IPv6 { port, .. } => port,
            NetAddress::OnionV2 { port, .. } => port,
            NetAddress::OnionV3 { port, .. } => port,
        }
    }

    #[getter]
    fn checksum(&self) -> Option<u16> {
        match self.inner {
            NetAddress::OnionV3 { checksum, .. } => Some(checksum),
            _ => None,
        }
    }

    #[getter]
    fn version(&self) -> Option<u8> {
        match self.inner {
            NetAddress::OnionV3 { version, .. } => Some(version),
            _ => None,
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyNetAddress {
    fn __str__(&self) -> String {
        format!("{:?}", self.inner)
    }
}
