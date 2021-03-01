use pyo3::class::basic::CompareOp;
use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyObjectProtocol;
use std::collections::BTreeMap;

use bitcoin::secp256k1;
use lightning::routing::network_graph::{
    ChannelInfo, DirectionalChannelInfo, NetGraphMsgHandler, NetworkGraph, NodeAnnouncementInfo,
    NodeInfo, RoutingFees,
};
use lightning::util::ser::{Readable, Writeable};

use crate::chain::PyAccess;
use crate::ln::features::{PyChannelFeatures, PyNodeFeatures};
use crate::ln::msgs::{
    PyChannelAnnouncement, PyChannelUpdate, PyLightningError, PyNetAddress, PyNodeAnnouncement,
    PyUnsignedChannelAnnouncement, PyUnsignedChannelUpdate, PyUnsignedNodeAnnouncement,
};
use crate::logger::LDKLogger;
use crate::primitives::PyPublicKey;

#[pyclass(name=NetworkGraph)]
#[derive(Clone)]
pub struct PyNetworkGraph {
    inner: NetworkGraph,
}

#[pymethods]
impl PyNetworkGraph {
    #[new]
    fn new() -> Self {
        PyNetworkGraph {
            inner: NetworkGraph::new(),
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match NetworkGraph::read(&mut data) {
            Ok(x) => Ok(PyNetworkGraph { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }

    #[getter]
    fn get_channels(&self) -> BTreeMap<u64, PyChannelInfo> {
        let mut foreign_channels = BTreeMap::new();
        for (chan_id, chan_info) in self.inner.get_channels() {
            foreign_channels.insert(
                chan_id.clone(),
                PyChannelInfo {
                    inner: chan_info.clone(),
                },
            );
        }
        foreign_channels
    }

    #[getter]
    fn get_nodes(&self) -> BTreeMap<PyPublicKey, PyNodeInfo> {
        let mut foreign_nodes = BTreeMap::new();
        for (node_id, node_info) in self.inner.get_nodes() {
            foreign_nodes.insert(
                PyPublicKey {
                    inner: node_id.clone(),
                },
                PyNodeInfo {
                    inner: node_info.clone(),
                },
            );
        }
        foreign_nodes
    }

    fn get_addresses(&self, pubkey: PyPublicKey) -> Option<Vec<PyNetAddress>> {
        let mut foreign_net_addrs: Vec<PyNetAddress> = vec![];
        match self.inner.get_addresses(&pubkey.inner) {
            Some(addresses) => {
                for address in addresses.iter() {
                    foreign_net_addrs.push(PyNetAddress {
                        inner: address.clone(),
                    })
                }
                Some(foreign_net_addrs)
            }
            None => None,
        }
    }

    // TODO: This should return PyResult<LightningError>, but LightningError cannot be properly created atm
    fn update_node_from_announcement(&mut self, msg: PyNodeAnnouncement, py: Python) -> Py<PyAny> {
        match self
            .inner
            .update_node_from_announcement(&msg.inner, &secp256k1::Secp256k1::verification_only())
        {
            Ok(_) => ().into_py(py),
            Err(e) => PyLightningError { inner: e }.into_py(py),
        }
    }

    // TODO: This should return PyResult<LightningError>, but LightningError cannot be properly created atm
    fn update_node_from_unsigned_announcement(
        &mut self,
        msg: PyUnsignedNodeAnnouncement,
        py: Python,
    ) -> Py<PyAny> {
        match self
            .inner
            .update_node_from_unsigned_announcement(&msg.inner)
        {
            Ok(_) => ().into_py(py),
            Err(e) => PyLightningError { inner: e }.into_py(py),
        }
    }

    // TODO: This should return PyResult<LightningError>, but LightningError cannot be properly created atm
    fn update_channel_from_announcement(
        &mut self,
        msg: PyChannelAnnouncement,
        chain_access: Option<PyAccess>,
        py: Python,
    ) -> Py<PyAny> {
        let deref_chain_access = match chain_access {
            Some(x) => Some(Box::new(x)),
            None => None,
        };
        match self.inner.update_channel_from_announcement(
            &msg.inner,
            &deref_chain_access,
            &secp256k1::Secp256k1::verification_only(),
        ) {
            Ok(_) => ().into_py(py),
            Err(e) => PyLightningError { inner: e }.into_py(py),
        }
    }

    // TODO: This should return PyResult<LightningError>, but LightningError cannot be properly created atm
    fn update_channel_from_unsigned_announcement(
        &mut self,
        msg: PyUnsignedChannelAnnouncement,
        chain_access: Option<PyAccess>,
        py: Python,
    ) -> Py<PyAny> {
        let deref_chain_access = match chain_access {
            Some(x) => Some(Box::new(x)),
            None => None,
        };
        match self
            .inner
            .update_channel_from_unsigned_announcement(&msg.inner, &deref_chain_access)
        {
            Ok(_) => ().into_py(py),
            Err(e) => PyLightningError { inner: e }.into_py(py),
        }
    }

    fn close_channel_from_update(&mut self, short_channel_id: u64, is_permanent: bool) {
        self.inner
            .close_channel_from_update(short_channel_id, is_permanent)
    }

    // TODO: This should return PyResult<LightningError>, but LightningError cannot be properly created atm
    fn update_channel(&mut self, msg: PyChannelUpdate, py: Python) -> Py<PyAny> {
        match self
            .inner
            .update_channel(&msg.inner, &secp256k1::Secp256k1::verification_only())
        {
            Ok(_) => ().into_py(py),
            Err(e) => PyLightningError { inner: e }.into_py(py),
        }
    }

    // TODO: This should return PyResult<LightningError>, but LightningError cannot be properly created atm
    fn update_channel_unsigned(&mut self, msg: PyUnsignedChannelUpdate, py: Python) -> Py<PyAny> {
        match self.inner.update_channel_unsigned(&msg.inner) {
            Ok(_) => ().into_py(py),
            Err(e) => PyLightningError { inner: e }.into_py(py),
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyNetworkGraph {
    fn __str__(&self) -> String {
        format!("{}", self.inner)
    }
}

#[pyclass(name=NetGraphMsgHandler)]
pub struct PyNetGraphMsgHandler {
    inner: NetGraphMsgHandler<Box<PyAccess>, Box<LDKLogger>>,
}

#[pymethods]
impl PyNetGraphMsgHandler {
    #[new]
    fn new(chain_access: Option<PyAccess>, l: LDKLogger) -> Self {
        PyNetGraphMsgHandler {
            inner: NetGraphMsgHandler::new(
                match chain_access {
                    Some(x) => Some(Box::new(x)),
                    None => None,
                },
                Box::new(l),
            ),
        }
    }

    #[staticmethod]
    fn from_net_graph(
        chain_access: Option<PyAccess>,
        logger: LDKLogger,
        network_graph: PyNetworkGraph,
    ) -> Self {
        PyNetGraphMsgHandler {
            inner: NetGraphMsgHandler::from_net_graph(
                match chain_access {
                    Some(x) => Some(Box::new(x)),
                    None => None,
                },
                Box::new(logger),
                network_graph.inner,
            ),
        }
    }

    #[getter]
    fn get_graph(&self) -> PyNetworkGraph {
        PyNetworkGraph {
            inner: self.inner.read_locked_graph().graph().clone(),
        }
    }
}

#[pyclass(name=DirectionalChannelInfo)]
#[derive(Clone)]
pub struct PyDirectionalChannelInfo {
    inner: DirectionalChannelInfo,
}

#[pymethods]
impl PyDirectionalChannelInfo {
    #[new]
    fn new(
        last_update: u32,
        enabled: bool,
        cltv_expiry_delta: u16,
        htlc_minimum_msat: u64,
        htlc_maximum_msat: Option<u64>,
        fees: PyRoutingFees,
        last_update_message: Option<PyChannelUpdate>,
    ) -> Self {
        PyDirectionalChannelInfo {
            inner: DirectionalChannelInfo {
                last_update,
                enabled,
                cltv_expiry_delta,
                htlc_minimum_msat,
                htlc_maximum_msat,
                fees: fees.inner,
                last_update_message: match last_update_message {
                    Some(x) => Some(x.inner),
                    None => None,
                },
            },
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match DirectionalChannelInfo::read(&mut data) {
            Ok(x) => Ok(PyDirectionalChannelInfo { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }

    #[getter]
    fn get_last_update(&self) -> u32 {
        self.inner.last_update
    }

    #[getter]
    fn get_enabled(&self) -> bool {
        self.inner.enabled
    }

    #[getter]
    fn get_cltv_expiry_delta(&self) -> u16 {
        self.inner.cltv_expiry_delta
    }

    #[getter]
    fn get_htlc_minimum_msat(&self) -> u64 {
        self.inner.htlc_minimum_msat
    }

    #[getter]
    fn get_htlc_maximum_msat(&self) -> Option<u64> {
        self.inner.htlc_maximum_msat
    }

    #[getter]
    fn get_fees(&self) -> PyRoutingFees {
        PyRoutingFees {
            inner: self.inner.fees,
        }
    }

    #[getter]
    fn get_last_update_message(&self) -> Option<PyChannelUpdate> {
        match &self.inner.last_update_message {
            Some(x) => Some(PyChannelUpdate { inner: x.clone() }),
            None => None,
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyDirectionalChannelInfo {
    fn __str__(&self) -> String {
        format!("{}", self.inner)
    }
}

#[pyclass(name=ChannelInfo)]
#[derive(Clone)]
pub struct PyChannelInfo {
    inner: ChannelInfo,
}

#[pymethods]
impl PyChannelInfo {
    #[new]
    fn new(
        features: PyChannelFeatures,
        node_one: PyPublicKey,
        one_to_two: Option<PyDirectionalChannelInfo>,
        node_two: PyPublicKey,
        two_to_one: Option<PyDirectionalChannelInfo>,
        capacity_sats: Option<u64>,
        announcement_message: Option<PyChannelAnnouncement>,
    ) -> Self {
        PyChannelInfo {
            inner: ChannelInfo {
                features: features.inner,
                node_one: node_one.inner,
                one_to_two: match one_to_two {
                    Some(x) => Some(x.inner),
                    None => None,
                },
                node_two: node_two.inner,
                two_to_one: match two_to_one {
                    Some(x) => Some(x.inner),
                    None => None,
                },
                capacity_sats,
                announcement_message: match announcement_message {
                    Some(x) => Some(x.inner),
                    None => None,
                },
            },
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match ChannelInfo::read(&mut data) {
            Ok(x) => Ok(PyChannelInfo { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }

    #[getter]
    fn get_features(&self) -> PyChannelFeatures {
        PyChannelFeatures {
            inner: self.inner.features.clone(),
        }
    }

    #[getter]
    fn get_node_one(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.node_one,
        }
    }

    #[getter]
    fn get_one_to_two(&self) -> Option<PyDirectionalChannelInfo> {
        match &self.inner.one_to_two {
            Some(x) => Some(PyDirectionalChannelInfo { inner: x.clone() }),
            None => None,
        }
    }

    #[getter]
    fn get_node_two(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.node_two,
        }
    }

    #[getter]
    fn get_two_to_one(&self) -> Option<PyDirectionalChannelInfo> {
        match &self.inner.two_to_one {
            Some(x) => Some(PyDirectionalChannelInfo { inner: x.clone() }),
            None => None,
        }
    }

    #[getter]
    fn get_capacity_sats(&self) -> Option<u64> {
        self.inner.capacity_sats
    }

    #[getter]
    fn get_announcement_message(&self) -> Option<PyChannelAnnouncement> {
        match &self.inner.announcement_message {
            Some(x) => Some(PyChannelAnnouncement { inner: x.clone() }),
            None => None,
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyChannelInfo {
    fn __str__(&self) -> String {
        format!("{}", self.inner)
    }
}

#[pyclass(name=RoutingFees)]
#[derive(Clone, PartialEq, Eq)]
pub struct PyRoutingFees {
    inner: RoutingFees,
}

#[pymethods]
impl PyRoutingFees {
    #[new]
    fn new(base_msat: u32, proportional_millionths: u32) -> Self {
        PyRoutingFees {
            inner: RoutingFees {
                base_msat,
                proportional_millionths,
            },
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match RoutingFees::read(&mut data) {
            Ok(x) => Ok(PyRoutingFees { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }

    #[getter]
    fn get_base_msat(&self) -> u32 {
        self.inner.base_msat
    }

    #[getter]
    fn get_proportional_millionths(&self) -> u32 {
        self.inner.proportional_millionths
    }
}

#[pyproto]
impl PyObjectProtocol for PyRoutingFees {
    fn __richcmp__(&self, other: PyRoutingFees, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
    }
}

#[pyclass(name=NodeAnnouncementInfo)]
#[derive(Clone)]
pub struct PyNodeAnnouncementInfo {
    inner: NodeAnnouncementInfo,
}

#[pymethods]
impl PyNodeAnnouncementInfo {
    #[new]
    fn new(
        features: PyNodeFeatures,
        last_update: u32,
        rgb: [u8; 3],
        alias: [u8; 32],
        addresses: Vec<PyNetAddress>,
        announcement_message: Option<PyNodeAnnouncement>,
    ) -> Self {
        let mut native_addresses = vec![];
        for address in addresses.iter() {
            native_addresses.push(address.inner.clone())
        }

        PyNodeAnnouncementInfo {
            inner: NodeAnnouncementInfo {
                features: features.inner,
                last_update,
                rgb,
                alias,
                addresses: native_addresses,
                announcement_message: match announcement_message {
                    Some(x) => Some(x.inner),
                    None => None,
                },
            },
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match NodeAnnouncementInfo::read(&mut data) {
            Ok(x) => Ok(PyNodeAnnouncementInfo { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }

    #[getter]
    fn get_features(&self) -> PyNodeFeatures {
        PyNodeFeatures {
            inner: self.inner.features.clone(),
        }
    }

    #[getter]
    fn get_last_update(&self) -> u32 {
        self.inner.last_update
    }

    #[getter]
    fn get_rgb(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.rgb).into()
    }

    #[getter]
    fn get_alias(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.alias).into()
    }

    #[getter]
    fn get_addresses(&self) -> Vec<PyNetAddress> {
        let mut foreign_addresses = vec![];
        for address in self.inner.addresses.iter() {
            foreign_addresses.push(PyNetAddress {
                inner: address.clone(),
            })
        }

        foreign_addresses
    }

    #[getter]
    fn get_announcement_message(&self) -> Option<PyNodeAnnouncement> {
        match &self.inner.announcement_message {
            Some(x) => Some(PyNodeAnnouncement { inner: x.clone() }),
            None => None,
        }
    }
}

#[pyclass(name=NodeInfo)]
#[derive(Clone)]
pub struct PyNodeInfo {
    inner: NodeInfo,
}

#[pymethods]
impl PyNodeInfo {
    #[new]
    fn new(
        channels: Vec<u64>,
        lowest_inbound_channel_fees: Option<PyRoutingFees>,
        announcement_info: Option<PyNodeAnnouncementInfo>,
    ) -> Self {
        PyNodeInfo {
            inner: NodeInfo {
                channels,
                lowest_inbound_channel_fees: match lowest_inbound_channel_fees {
                    Some(x) => Some(x.inner.clone()),
                    None => None,
                },
                announcement_info: match announcement_info {
                    Some(x) => Some(x.inner),
                    None => None,
                },
            },
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match NodeInfo::read(&mut data) {
            Ok(x) => Ok(PyNodeInfo { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }

    #[getter]
    fn get_channels(&self) -> Vec<u64> {
        self.inner.channels.clone()
    }

    #[getter]
    fn get_lowest_inbound_channel_fees(&self) -> Option<PyRoutingFees> {
        match self.inner.lowest_inbound_channel_fees {
            Some(x) => Some(PyRoutingFees { inner: x }),
            None => None,
        }
    }

    #[getter]
    fn get_announcement_info(&self) -> Option<PyNodeAnnouncementInfo> {
        match &self.inner.announcement_info {
            Some(x) => Some(PyNodeAnnouncementInfo { inner: x.clone() }),
            None => None,
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyNodeInfo {
    fn __str__(&self) -> String {
        format!("{}", self.inner)
    }
}
