use pyo3::prelude::*;

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
}
