use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyObjectProtocol;

use crate::ln::features::PyInitFeatures;
use crate::primitives::PyPublicKey;
use crate::util::events::PyMessageSendEvent;
use crate::{has_trait_bound, process_python_return};

use bitcoin::secp256k1::key::PublicKey;
use lightning::ln::features::InitFeatures;
use lightning::ln::msgs::*;
use lightning::util::events::{MessageSendEvent, MessageSendEventsProvider};
use lightning::util::ser::{Readable, Writeable};

pub fn match_error_action(e: &ErrorAction) -> String {
    match e {
        ErrorAction::DisconnectPeer { .. } => String::from("DisconnectPeer"),
        ErrorAction::IgnoreError { .. } => String::from("IgnoreError"),
        ErrorAction::SendErrorMessage { .. } => String::from("SendErrorMessage"),
    }
}

pub fn match_htlc_fail_chan_update(e: &HTLCFailChannelUpdate) -> String {
    match e {
        HTLCFailChannelUpdate::ChannelUpdateMessage { .. } => String::from("ChannelUpdateMessage"),
        HTLCFailChannelUpdate::ChannelClosed { .. } => String::from("ChannelClosed"),
        HTLCFailChannelUpdate::NodeFailure { .. } => String::from("NodeFailure"),
    }
}

#[pyclass(name=Init)]
#[derive(Clone)]
pub struct PyInit {
    pub inner: Init,
}

#[pymethods]
impl PyInit {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match Init::read(&mut data) {
            Ok(x) => Ok(PyInit { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=ErrorMessage)]
#[derive(Clone)]
pub struct PyErrorMessage {
    pub inner: ErrorMessage,
}

#[pymethods]
impl PyErrorMessage {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match ErrorMessage::read(&mut data) {
            Ok(x) => Ok(PyErrorMessage { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=OpenChannel)]
#[derive(Clone)]
pub struct PyOpenChannel {
    pub inner: OpenChannel,
}

#[pymethods]
impl PyOpenChannel {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match OpenChannel::read(&mut data) {
            Ok(x) => Ok(PyOpenChannel { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=AcceptChannel)]
#[derive(Clone)]
pub struct PyAcceptChannel {
    pub inner: AcceptChannel,
}

#[pymethods]
impl PyAcceptChannel {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match AcceptChannel::read(&mut data) {
            Ok(x) => Ok(PyAcceptChannel { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=FundingCreated)]
#[derive(Clone)]
pub struct PyFundingCreated {
    pub inner: FundingCreated,
}

#[pymethods]
impl PyFundingCreated {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match FundingCreated::read(&mut data) {
            Ok(x) => Ok(PyFundingCreated { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=FundingSigned)]
#[derive(Clone)]
pub struct PyFundingSigned {
    pub inner: FundingSigned,
}

#[pymethods]
impl PyFundingSigned {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match FundingSigned::read(&mut data) {
            Ok(x) => Ok(PyFundingSigned { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=FundingLocked)]
#[derive(Clone)]
pub struct PyFundingLocked {
    pub inner: FundingLocked,
}

#[pymethods]
impl PyFundingLocked {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match FundingLocked::read(&mut data) {
            Ok(x) => Ok(PyFundingLocked { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=Shutdown)]
#[derive(Clone)]
pub struct PyShutdown {
    pub inner: Shutdown,
}

#[pymethods]
impl PyShutdown {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match Shutdown::read(&mut data) {
            Ok(x) => Ok(PyShutdown { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=ClosingSigned)]
#[derive(Clone)]
pub struct PyClosingSigned {
    pub inner: ClosingSigned,
}

#[pymethods]
impl PyClosingSigned {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match ClosingSigned::read(&mut data) {
            Ok(x) => Ok(PyClosingSigned { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=UpdateAddHTLC)]
#[derive(Clone)]
pub struct PyUpdateAddHTLC {
    pub inner: UpdateAddHTLC,
}

#[pymethods]
impl PyUpdateAddHTLC {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match UpdateAddHTLC::read(&mut data) {
            Ok(x) => Ok(PyUpdateAddHTLC { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=UpdateFulfillHTLC)]
#[derive(Clone)]
pub struct PyUpdateFulfillHTLC {
    pub inner: UpdateFulfillHTLC,
}

#[pymethods]
impl PyUpdateFulfillHTLC {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match UpdateFulfillHTLC::read(&mut data) {
            Ok(x) => Ok(PyUpdateFulfillHTLC { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=UpdateFailHTLC)]
#[derive(Clone)]
pub struct PyUpdateFailHTLC {
    pub inner: UpdateFailHTLC,
}

#[pymethods]
impl PyUpdateFailHTLC {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match UpdateFailHTLC::read(&mut data) {
            Ok(x) => Ok(PyUpdateFailHTLC { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=UpdateFailMalformedHTLC)]
#[derive(Clone)]
pub struct PyUpdateFailMalformedHTLC {
    pub inner: UpdateFailMalformedHTLC,
}

#[pymethods]
impl PyUpdateFailMalformedHTLC {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match UpdateFailMalformedHTLC::read(&mut data) {
            Ok(x) => Ok(PyUpdateFailMalformedHTLC { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=CommitmentSigned)]
#[derive(Clone)]
pub struct PyCommitmentSigned {
    pub inner: CommitmentSigned,
}

#[pymethods]
impl PyCommitmentSigned {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match CommitmentSigned::read(&mut data) {
            Ok(x) => Ok(PyCommitmentSigned { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=RevokeAndACK)]
#[derive(Clone)]
pub struct PyRevokeAndACK {
    pub inner: RevokeAndACK,
}

#[pymethods]
impl PyRevokeAndACK {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match RevokeAndACK::read(&mut data) {
            Ok(x) => Ok(PyRevokeAndACK { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=UpdateFee)]
#[derive(Clone)]
pub struct PyUpdateFee {
    pub inner: UpdateFee,
}

#[pymethods]
impl PyUpdateFee {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match UpdateFee::read(&mut data) {
            Ok(x) => Ok(PyUpdateFee { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=DataLossProtect)]
#[derive(Clone)]
pub struct PyDataLossProtect {
    pub inner: DataLossProtect,
}

#[pymethods]
impl PyDataLossProtect {
    #[new]
    fn new(
        your_last_per_commitment_secret: [u8; 32],
        my_current_per_commitment_point: PyPublicKey,
    ) -> Self {
        PyDataLossProtect {
            inner: DataLossProtect {
                your_last_per_commitment_secret,
                my_current_per_commitment_point: my_current_per_commitment_point.inner,
            },
        }
    }
}

#[pyclass(name=ChannelReestablish)]
#[derive(Clone)]
pub struct PyChannelReestablish {
    pub inner: ChannelReestablish,
}

#[pymethods]
impl PyChannelReestablish {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match ChannelReestablish::read(&mut data) {
            Ok(x) => Ok(PyChannelReestablish { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=AnnouncementSignatures)]
#[derive(Clone)]
pub struct PyAnnouncementSignatures {
    pub inner: AnnouncementSignatures,
}

#[pymethods]
impl PyAnnouncementSignatures {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match AnnouncementSignatures::read(&mut data) {
            Ok(x) => Ok(PyAnnouncementSignatures { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

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

    // #[staticmethod]
    // fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
    //     match NetAddress::read(&mut data) {
    //         Ok(x) => Ok(PyNetAddress { inner: x }),
    //         Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
    //     }
    // }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
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

#[pyclass(name=NodeAnnouncement)]
#[derive(Clone)]
pub struct PyNodeAnnouncement {
    pub inner: NodeAnnouncement,
}

#[pymethods]
impl PyNodeAnnouncement {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match NodeAnnouncement::read(&mut data) {
            Ok(x) => Ok(PyNodeAnnouncement { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=ChannelAnnouncement)]
#[derive(Clone)]
pub struct PyChannelAnnouncement {
    pub inner: ChannelAnnouncement,
}

#[pymethods]
impl PyChannelAnnouncement {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match ChannelAnnouncement::read(&mut data) {
            Ok(x) => Ok(PyChannelAnnouncement { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=ChannelUpdate)]
#[derive(Clone)]
pub struct PyChannelUpdate {
    pub inner: ChannelUpdate,
}

#[pymethods]
impl PyChannelUpdate {
    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match ChannelUpdate::read(&mut data) {
            Ok(x) => Ok(PyChannelUpdate { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=ErrorAction)]
#[derive(Clone)]
pub struct PyErrorAction {
    pub inner: ErrorAction,
    pub error_type: String,
}

#[pymethods]
impl PyErrorAction {
    #[staticmethod]
    fn disconnect_peer(msg: Option<PyErrorMessage>) -> Self {
        let e = ErrorAction::DisconnectPeer {
            msg: match msg {
                Some(x) => Some(x.inner),
                None => None,
            },
        };
        PyErrorAction {
            error_type: match_error_action(&e),
            inner: e,
        }
    }

    #[staticmethod]
    fn ignore_error() -> Self {
        let e = ErrorAction::IgnoreError;
        PyErrorAction {
            error_type: match_error_action(&e),
            inner: e,
        }
    }

    #[staticmethod]
    fn send_error_message(msg: PyErrorMessage) -> Self {
        let e = ErrorAction::SendErrorMessage { msg: msg.inner };
        PyErrorAction {
            error_type: match_error_action(&e),
            inner: e,
        }
    }

    #[getter]
    fn get_type(&self) -> String {
        self.error_type.clone()
    }
}

#[pyclass(name=LightningError)]
#[derive(Clone)]
// FIXME: This should be an exception, but currently PyO3 does not allow creating
// exceptions with data fields. This should be covered in the next release
// https://github.com/PyO3/pyo3/issues/295
pub struct PyLightningError {
    pub inner: LightningError,
}

#[pymethods]
impl PyLightningError {
    #[new]
    fn new(err: String, action: PyErrorAction) -> Self {
        PyLightningError {
            inner: LightningError {
                err,
                action: action.inner,
            },
        }
    }

    #[getter]
    fn err(&self) -> String {
        self.inner.err.clone()
    }

    #[getter]
    fn action(&self) -> PyErrorAction {
        PyErrorAction {
            inner: self.inner.action.clone(),
            error_type: match_error_action(&self.inner.action),
        }
    }
}

#[pyclass(name=HTLCFailChannelUpdate)]
#[derive(Clone)]
pub struct PyHTLCFailChannelUpdate {
    pub inner: HTLCFailChannelUpdate,
    pub update_type: String,
}

#[pymethods]
impl PyHTLCFailChannelUpdate {
    #[staticmethod]
    fn channel_update_message(msg: PyChannelUpdate) -> Self {
        let update = HTLCFailChannelUpdate::ChannelUpdateMessage { msg: msg.inner };
        PyHTLCFailChannelUpdate {
            update_type: match_htlc_fail_chan_update(&update),
            inner: update,
        }
    }

    #[staticmethod]
    fn channel_closed(short_channel_id: u64, is_permanent: bool) -> Self {
        let update = HTLCFailChannelUpdate::ChannelClosed {
            short_channel_id,
            is_permanent,
        };
        PyHTLCFailChannelUpdate {
            update_type: match_htlc_fail_chan_update(&update),
            inner: update,
        }
    }

    #[staticmethod]
    fn node_failure(node_id: PyPublicKey, is_permanent: bool) -> Self {
        let update = HTLCFailChannelUpdate::NodeFailure {
            node_id: node_id.inner,
            is_permanent,
        };
        PyHTLCFailChannelUpdate {
            update_type: match_htlc_fail_chan_update(&update),
            inner: update,
        }
    }

    #[getter]
    fn get_type(&self) -> String {
        self.update_type.clone()
    }
}

#[pyclass(name=ChannelMessageHandler)]
#[derive(Clone)]
pub struct PyChannelMessageHandler {
    pub inner: Py<PyAny>,
}

#[pymethods]
impl PyChannelMessageHandler {
    #[new]
    fn new(chan_msg_handler: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(
            &chan_msg_handler,
            vec![
                "get_and_clear_pending_msg_events",
                "handle_open_channel",
                "handle_accept_channel",
                "handle_funding_created",
                "handle_funding_signed",
                "handle_funding_locked",
                "handle_shutdown",
                "handle_closing_signed",
                "handle_update_add_htlc",
                "handle_update_fulfill_htlc",
                "handle_update_fail_htlc",
                "handle_update_fail_malformed_htlc",
                "handle_commitment_signed",
                "handle_revoke_and_ack",
                "handle_update_fee",
                "handle_announcement_signatures",
                "peer_disconnected",
                "peer_connected",
                "handle_channel_reestablish",
                "handle_error",
            ],
        ) {
            Ok(PyChannelMessageHandler {
                inner: chan_msg_handler,
            })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by ChannelMessageHandler"
            )))
        }
    }

    fn get_and_clear_pending_msg_events(&self) -> PyResult<Vec<PyMessageSendEvent>> {
        Python::with_gil(|py| {
            let py_provider = self.inner.as_ref(py);
            process_python_return(py_provider.call_method0("get_and_clear_pending_msg_events"))
        })
    }

    fn handle_open_channel(
        &self,
        their_node_id: PyPublicKey,
        their_features: PyInitFeatures,
        msg: PyOpenChannel,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler
                .call_method1("handle_open_channel", (their_node_id, their_features, msg))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_accept_channel(
        &self,
        their_node_id: PyPublicKey,
        their_features: PyInitFeatures,
        msg: PyAcceptChannel,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1(
                "handle_accept_channel",
                (their_node_id, their_features, msg),
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_funding_created(
        &self,
        their_node_id: PyPublicKey,
        msg: PyFundingCreated,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_funding_created", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_funding_signed(
        &self,
        their_node_id: PyPublicKey,
        msg: PyFundingSigned,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_funding_signed", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_funding_locked(
        &self,
        their_node_id: PyPublicKey,
        msg: PyFundingLocked,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_funding_locked", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_shutdown(&self, their_node_id: PyPublicKey, msg: PyShutdown) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_shutdown", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_closing_signed(
        &self,
        their_node_id: PyPublicKey,
        msg: PyClosingSigned,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_closing_signed", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_update_add_htlc(
        &self,
        their_node_id: PyPublicKey,
        msg: PyUpdateAddHTLC,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_update_add_htlc", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_update_fulfill_htlc(
        &self,
        their_node_id: PyPublicKey,
        msg: PyUpdateFulfillHTLC,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler
                .call_method1("handle_update_fulfill_htlc", (their_node_id, msg))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_update_fail_htlc(
        &self,
        their_node_id: PyPublicKey,
        msg: PyUpdateFailHTLC,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_update_fail_htlc", (their_node_id, msg))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_update_fail_malformed_htlc(
        &self,
        their_node_id: PyPublicKey,
        msg: PyUpdateFailMalformedHTLC,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler
                .call_method1("handle_update_fail_malformed_htlc", (their_node_id, msg))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_commitment_signed(
        &self,
        their_node_id: PyPublicKey,
        msg: PyCommitmentSigned,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_commitment_signed", (their_node_id, msg))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_revoke_and_ack(
        &self,
        their_node_id: PyPublicKey,
        msg: PyRevokeAndACK,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_revoke_and_ack", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_update_fee(&self, their_node_id: PyPublicKey, msg: PyUpdateFee) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_update_fee", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_announcement_signatures(
        &self,
        their_node_id: PyPublicKey,
        msg: PyAnnouncementSignatures,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler
                .call_method1("handle_announcement_signatures", (their_node_id, msg))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn peer_disconnected(
        &self,
        their_node_id: PyPublicKey,
        no_connection_possible: bool,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler
                .call_method1("peer_disconnected", (their_node_id, no_connection_possible))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn peer_connected(&self, their_node_id: PyPublicKey, msg: PyInit) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("peer_disconnected", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_channel_reestablish(
        &self,
        their_node_id: PyPublicKey,
        msg: PyChannelReestablish,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler
                .call_method1("handle_channel_reestablish", (their_node_id, msg))
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_error(&self, their_node_id: PyPublicKey, msg: PyErrorMessage) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_chan_msg_handler = self.inner.as_ref(py);
            match py_chan_msg_handler.call_method1("handle_error", (their_node_id, msg)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }
}

impl MessageSendEventsProvider for PyChannelMessageHandler {
    fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
        let mut native_events: Vec<MessageSendEvent> = vec![];
        for event in self.get_and_clear_pending_msg_events().unwrap().into_iter() {
            native_events.push(event.inner)
        }

        native_events
    }
}

impl ChannelMessageHandler for PyChannelMessageHandler {
    //Channel init

    fn handle_open_channel(
        &self,
        their_node_id: &PublicKey,
        their_features: InitFeatures,
        msg: &OpenChannel,
    ) {
        self.handle_open_channel(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyInitFeatures {
                inner: their_features,
            },
            PyOpenChannel { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_accept_channel(
        &self,
        their_node_id: &PublicKey,
        their_features: InitFeatures,
        msg: &AcceptChannel,
    ) {
        self.handle_accept_channel(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyInitFeatures {
                inner: their_features,
            },
            PyAcceptChannel { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_funding_created(&self, their_node_id: &PublicKey, msg: &FundingCreated) {
        self.handle_funding_created(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyFundingCreated { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_funding_signed(&self, their_node_id: &PublicKey, msg: &FundingSigned) {
        self.handle_funding_signed(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyFundingSigned { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_funding_locked(&self, their_node_id: &PublicKey, msg: &FundingLocked) {
        self.handle_funding_locked(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyFundingLocked { inner: msg.clone() },
        )
        .unwrap()
    }

    // Channel close

    fn handle_shutdown(&self, their_node_id: &PublicKey, msg: &Shutdown) {
        self.handle_shutdown(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyShutdown { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_closing_signed(&self, their_node_id: &PublicKey, msg: &ClosingSigned) {
        self.handle_closing_signed(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyClosingSigned { inner: msg.clone() },
        )
        .unwrap()
    }

    // HTLC handling

    fn handle_update_add_htlc(&self, their_node_id: &PublicKey, msg: &UpdateAddHTLC) {
        self.handle_update_add_htlc(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyUpdateAddHTLC { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_update_fulfill_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFulfillHTLC) {
        self.handle_update_fulfill_htlc(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyUpdateFulfillHTLC { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_update_fail_htlc(&self, their_node_id: &PublicKey, msg: &UpdateFailHTLC) {
        self.handle_update_fail_htlc(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyUpdateFailHTLC { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_update_fail_malformed_htlc(
        &self,
        their_node_id: &PublicKey,
        msg: &UpdateFailMalformedHTLC,
    ) {
        self.handle_update_fail_malformed_htlc(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyUpdateFailMalformedHTLC { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_commitment_signed(&self, their_node_id: &PublicKey, msg: &CommitmentSigned) {
        self.handle_commitment_signed(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyCommitmentSigned { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_revoke_and_ack(&self, their_node_id: &PublicKey, msg: &RevokeAndACK) {
        self.handle_revoke_and_ack(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyRevokeAndACK { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_update_fee(&self, their_node_id: &PublicKey, msg: &UpdateFee) {
        self.handle_update_fee(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyUpdateFee { inner: msg.clone() },
        )
        .unwrap()
    }

    // Channel-to-announce

    fn handle_announcement_signatures(
        &self,
        their_node_id: &PublicKey,
        msg: &AnnouncementSignatures,
    ) {
        self.handle_announcement_signatures(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyAnnouncementSignatures { inner: msg.clone() },
        )
        .unwrap()
    }

    // Connection loss/reestablish

    fn peer_disconnected(&self, their_node_id: &PublicKey, no_connection_possible: bool) {
        self.peer_disconnected(
            PyPublicKey {
                inner: *their_node_id,
            },
            no_connection_possible,
        )
        .unwrap()
    }

    fn peer_connected(&self, their_node_id: &PublicKey, msg: &Init) {
        self.peer_connected(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyInit { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_channel_reestablish(&self, their_node_id: &PublicKey, msg: &ChannelReestablish) {
        self.handle_channel_reestablish(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyChannelReestablish { inner: msg.clone() },
        )
        .unwrap()
    }

    fn handle_error(&self, their_node_id: &PublicKey, msg: &ErrorMessage) {
        self.handle_error(
            PyPublicKey {
                inner: *their_node_id,
            },
            PyErrorMessage { inner: msg.clone() },
        )
        .unwrap()
    }
}

#[pyclass(name=RoutingMessageHandler)]
#[derive(Clone)]
pub struct PyRoutingMessageHandler {
    pub inner: Py<PyAny>,
}

#[pymethods]
impl PyRoutingMessageHandler {
    #[new]
    fn new(rout_msg_handler: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(
            &rout_msg_handler,
            vec![
                "handle_node_announcement",
                "handle_channel_announcement",
                "handle_channel_update",
                "handle_htlc_fail_channel_update",
                "get_next_channel_announcements",
                "get_next_node_announcements",
                "should_request_full_sync",
            ],
        ) {
            Ok(PyRoutingMessageHandler {
                inner: rout_msg_handler,
            })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by RoutingMessageHandler"
            )))
        }
    }

    fn handle_node_announcement(&self, msg: PyNodeAnnouncement) -> PyResult<Py<PyAny>> {
        Python::with_gil(|py| {
            let py_rout_msg_handler = self.inner.as_ref(py);
            match py_rout_msg_handler.call_method1("handle_node_announcement", (msg,)) {
                Ok(x) => Ok(x.into()),
                Err(e) => Err(e),
            }
        })
    }

    fn handle_channel_announcement(&self, msg: PyChannelAnnouncement) -> PyResult<Py<PyAny>> {
        Python::with_gil(|py| {
            let py_rout_msg_handler = self.inner.as_ref(py);
            process_python_return(
                py_rout_msg_handler.call_method1("handle_channel_announcement", (msg,)),
            )
        })
    }

    fn handle_channel_update(&self, msg: PyChannelUpdate) -> PyResult<Py<PyAny>> {
        Python::with_gil(|py| {
            let py_rout_msg_handler = self.inner.as_ref(py);
            process_python_return(py_rout_msg_handler.call_method1("handle_channel_update", (msg,)))
        })
    }

    fn handle_htlc_fail_channel_update(&self, update: PyHTLCFailChannelUpdate) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_rout_msg_handler = self.inner.as_ref(py);
            match py_rout_msg_handler.call_method1("handle_htlc_fail_channel_update", (update,)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn get_next_channel_announcements(
        &self,
        starting_point: u64,
        batch_amount: u8,
    ) -> PyResult<
        Vec<(
            PyChannelAnnouncement,
            Option<PyChannelUpdate>,
            Option<PyChannelUpdate>,
        )>,
    > {
        Python::with_gil(|py| {
            let py_rout_msg_handler = self.inner.as_ref(py);
            process_python_return(py_rout_msg_handler.call_method1(
                "get_next_channel_announcements",
                (starting_point, batch_amount),
            ))
        })
    }

    fn get_next_node_announcements(
        &self,
        starting_point: Option<PyPublicKey>,
        batch_amount: u8,
    ) -> PyResult<Vec<PyNodeAnnouncement>> {
        Python::with_gil(|py| {
            let py_rout_msg_handler = self.inner.as_ref(py);
            process_python_return(py_rout_msg_handler.call_method1(
                "get_next_node_announcements",
                (starting_point, batch_amount),
            ))
        })
    }

    fn should_request_full_sync(&self, node_id: PyPublicKey) -> PyResult<bool> {
        Python::with_gil(|py| {
            let py_rout_msg_handler = self.inner.as_ref(py);
            process_python_return(
                py_rout_msg_handler.call_method1("should_request_full_sync", (node_id,)),
            )
        })
    }
}

// FIXME: The first three methods are pending to finish due to #LightningResult-Exception
// Working irt around for now
impl RoutingMessageHandler for PyRoutingMessageHandler {
    fn handle_node_announcement(&self, msg: &NodeAnnouncement) -> Result<bool, LightningError> {
        let x = self
            .handle_node_announcement(PyNodeAnnouncement { inner: msg.clone() })
            .unwrap();

        Python::with_gil(|py| match x.extract(py) as Result<bool, _> {
            Ok(x) => Ok(x),
            Err(_) => Err((x.extract(py) as Result<PyLightningError, _>)
                .unwrap()
                .inner),
        })
    }

    fn handle_channel_announcement(
        &self,
        msg: &ChannelAnnouncement,
    ) -> Result<bool, LightningError> {
        let x = self
            .handle_channel_announcement(PyChannelAnnouncement { inner: msg.clone() })
            .unwrap();

        Python::with_gil(|py| match x.extract(py) as Result<bool, _> {
            Ok(x) => Ok(x),
            Err(_) => Err((x.extract(py) as Result<PyLightningError, _>)
                .unwrap()
                .inner),
        })
    }

    fn handle_channel_update(&self, msg: &ChannelUpdate) -> Result<bool, LightningError> {
        let x = self
            .handle_channel_update(PyChannelUpdate { inner: msg.clone() })
            .unwrap();

        Python::with_gil(|py| match x.extract(py) as Result<bool, _> {
            Ok(x) => Ok(x),
            Err(_) => Err((x.extract(py) as Result<PyLightningError, _>)
                .unwrap()
                .inner),
        })
    }

    fn handle_htlc_fail_channel_update(&self, update: &HTLCFailChannelUpdate) {
        self.handle_htlc_fail_channel_update(PyHTLCFailChannelUpdate {
            update_type: match_htlc_fail_chan_update(update),
            inner: update.clone(),
        })
        .unwrap()
    }

    fn get_next_channel_announcements(
        &self,
        starting_point: u64,
        batch_amount: u8,
    ) -> Vec<(
        ChannelAnnouncement,
        Option<ChannelUpdate>,
        Option<ChannelUpdate>,
    )> {
        let mut native_announcements: Vec<(
            ChannelAnnouncement,
            Option<ChannelUpdate>,
            Option<ChannelUpdate>,
        )> = vec![];
        let chan_announcements = self
            .get_next_channel_announcements(starting_point, batch_amount)
            .unwrap();
        for (ann, u1, u2) in chan_announcements.into_iter() {
            native_announcements.push((
                ann.inner,
                match u1 {
                    Some(x) => Some(x.inner),
                    None => None,
                },
                match u2 {
                    Some(x) => Some(x.inner),
                    None => None,
                },
            ))
        }
        native_announcements
    }

    fn get_next_node_announcements(
        &self,
        starting_point: Option<&PublicKey>,
        batch_amount: u8,
    ) -> Vec<NodeAnnouncement> {
        let mut native_announcements: Vec<NodeAnnouncement> = vec![];
        let node_announcements = self
            .get_next_node_announcements(
                match starting_point {
                    Some(x) => Some(PyPublicKey { inner: *x }),
                    None => None,
                },
                batch_amount,
            )
            .unwrap();

        for ann in node_announcements.into_iter() {
            native_announcements.push(ann.inner)
        }

        native_announcements
    }

    fn should_request_full_sync(&self, node_id: &PublicKey) -> bool {
        self.should_request_full_sync(PyPublicKey { inner: *node_id })
            .unwrap()
    }
}
