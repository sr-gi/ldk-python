use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::time::Duration;

use lightning::util::events::{Event, MessageSendEvent, MessageSendEventsProvider};

use crate::chain::keysinterface::{match_spendable_output_descriptor, PySpendableOutputDescriptor};
use crate::ln::channelmanager::{PyPaymentHash, PyPaymentPreimage, PyPaymentSecret};
use crate::ln::msgs::*;
use crate::primitives::{PyOutPoint, PyPublicKey, PyScript};
use crate::{has_trait_bound, process_python_return};

pub fn match_event_type(e: &Event) -> String {
    match e {
        Event::FundingGenerationReady { .. } => String::from("FundingGenerationReady"),
        Event::FundingBroadcastSafe { .. } => String::from("FundingBroadcastSafe"),
        Event::PaymentReceived { .. } => String::from("PaymentReceived"),
        Event::PaymentSent { .. } => String::from("PaymentSent"),
        Event::PaymentFailed { .. } => String::from("PaymentFailed"),
        Event::PendingHTLCsForwardable { .. } => String::from("PendingHTLCsForwardable"),
        Event::SpendableOutputs { .. } => String::from("SpendableOutputs"),
    }
}

pub fn match_message_send_event_type(e: &MessageSendEvent) -> String {
    match e {
        MessageSendEvent::SendAcceptChannel { .. } => String::from("SendAcceptChannel"),
        MessageSendEvent::SendOpenChannel { .. } => String::from("SendOpenChannel"),
        MessageSendEvent::SendFundingCreated { .. } => String::from("SendFundingCreated"),
        MessageSendEvent::SendFundingSigned { .. } => String::from("SendFundingSigned"),
        MessageSendEvent::SendFundingLocked { .. } => String::from("SendFundingLocked"),
        MessageSendEvent::SendAnnouncementSignatures { .. } => {
            String::from("SendAnnouncementSignatures")
        }
        MessageSendEvent::UpdateHTLCs { .. } => String::from("UpdateHTLCs"),
        MessageSendEvent::SendRevokeAndACK { .. } => String::from("SendRevokeAndACK"),
        MessageSendEvent::SendClosingSigned { .. } => String::from("SendClosingSigned"),
        MessageSendEvent::SendShutdown { .. } => String::from("SendShutdown"),
        MessageSendEvent::SendChannelReestablish { .. } => String::from("SendChannelReestablish"),
        MessageSendEvent::BroadcastChannelAnnouncement { .. } => {
            String::from("BroadcastChannelAnnouncement")
        }
        MessageSendEvent::BroadcastNodeAnnouncement { .. } => {
            String::from("BroadcastNodeAnnouncement")
        }
        MessageSendEvent::BroadcastChannelUpdate { .. } => String::from("BroadcastChannelUpdate"),
        MessageSendEvent::HandleError { .. } => String::from("HandleError"),
        MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {
            String::from("PaymentFailureNetworkUpdate")
        }
    }
}

#[pyclass(name=Event)]
#[derive(Clone)]
pub struct PyEvent {
    pub inner: Event,
    pub event_type: String,
}

#[pymethods]
impl PyEvent {
    #[staticmethod]
    fn funding_generation_ready(
        temporary_channel_id: [u8; 32],
        channel_value_satoshis: u64,
        output_script: PyScript,
        user_channel_id: u64,
    ) -> Self {
        let event = Event::FundingGenerationReady {
            temporary_channel_id,
            channel_value_satoshis,
            output_script: output_script.inner,
            user_channel_id,
        };
        PyEvent {
            event_type: match_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn funding_broadcasting_safe(funding_txo: PyOutPoint, user_channel_id: u64) -> Self {
        PyEvent {
            inner: Event::FundingBroadcastSafe {
                funding_txo: funding_txo.inner,
                user_channel_id,
            },
            event_type: String::from("FundingBroadcastSafe"),
        }
    }

    #[staticmethod]
    fn payment_received(
        payment_hash: PyPaymentHash,
        payment_secret: Option<PyPaymentSecret>,
        amt: u64,
    ) -> Self {
        let native_payment_secret = match payment_secret {
            Some(x) => Some(x.inner),
            None => None,
        };
        PyEvent {
            inner: Event::PaymentReceived {
                payment_hash: payment_hash.inner,
                payment_secret: native_payment_secret,
                amt,
            },
            event_type: String::from("PaymentReceived"),
        }
    }

    #[staticmethod]
    fn payment_sent(payment_preimage: PyPaymentPreimage) -> Self {
        PyEvent {
            inner: Event::PaymentSent {
                payment_preimage: payment_preimage.inner,
            },
            event_type: String::from("PaymentSent"),
        }
    }

    #[staticmethod]
    fn payment_failed(payment_hash: PyPaymentHash, rejected_by_dest: bool) -> Self {
        PyEvent {
            inner: Event::PaymentFailed {
                payment_hash: payment_hash.inner,
                rejected_by_dest,
            },
            event_type: String::from("PaymentFailed"),
        }
    }

    // FIXME: This may be best with some bind between timedate.timedelta and Duration, leaving it as it for now
    #[staticmethod]
    fn pending_htlcs_forwardable(secs: u64, nanos: u32) -> Self {
        PyEvent {
            inner: Event::PendingHTLCsForwardable {
                time_forwardable: Duration::new(secs, nanos),
            },
            event_type: String::from("PendingHTLCsForwardable"),
        }
    }

    #[staticmethod]
    fn spendable_outputs(outputs: Vec<PySpendableOutputDescriptor>) -> Self {
        let mut native_outputs = vec![];
        for output in outputs.into_iter() {
            native_outputs.push(output.inner)
        }
        PyEvent {
            inner: Event::SpendableOutputs {
                outputs: native_outputs,
            },
            event_type: String::from("SpendableOutputs"),
        }
    }

    #[getter]
    fn get_type(&self) -> String {
        self.event_type.clone()
    }

    // FundingGenerationReady attributes

    #[getter]
    fn get_temporary_channel_id(&self, py: Python) -> PyResult<Py<PyBytes>> {
        match self.inner {
            Event::FundingGenerationReady {
                temporary_channel_id: t,
                ..
            } => Ok(PyBytes::new(py, &t).into()),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have temporary_channel_id",
                self.event_type
            ))),
        }
    }

    #[getter]
    fn get_channel_value_satoshis(&self) -> PyResult<u64> {
        match self.inner {
            Event::FundingGenerationReady {
                channel_value_satoshis: v,
                ..
            } => Ok(v),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have channel_value_satoshis",
                self.event_type
            ))),
        }
    }

    #[getter]
    fn get_output_script(&self) -> PyResult<PyScript> {
        match &self.inner {
            Event::FundingGenerationReady {
                output_script: s, ..
            } => Ok(PyScript { inner: s.clone() }),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have output_script",
                self.event_type
            ))),
        }
    }

    // Attributes shared amongst FundingGenerationReady and FundingBroadcastSafe
    #[getter]
    fn get_user_channel_id(&self) -> PyResult<u64> {
        match self.inner {
            Event::FundingGenerationReady {
                user_channel_id: c, ..
            } => Ok(c),
            Event::FundingBroadcastSafe {
                user_channel_id: i, ..
            } => Ok(i),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have user_channel_id",
                self.event_type
            ))),
        }
    }

    // FundingBroadcastSafe attributes

    #[getter]
    fn get_funding_txo(&self) -> PyResult<PyOutPoint> {
        match self.inner {
            Event::FundingBroadcastSafe { funding_txo: o, .. } => Ok(PyOutPoint { inner: o }),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have funding_txo",
                self.event_type
            ))),
        }
    }

    // PaymentReceived attributes

    // Shared amognst PaymentReceived and PaymentFailed

    #[getter]
    fn get_payment_hash(&self) -> PyResult<PyPaymentHash> {
        match self.inner {
            Event::PaymentReceived {
                payment_hash: h, ..
            } => Ok(PyPaymentHash { inner: h }),
            Event::PaymentFailed {
                payment_hash: h, ..
            } => Ok(PyPaymentHash { inner: h }),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have payment_hash",
                self.event_type
            ))),
        }
    }

    #[getter]
    fn get_payment_secret(&self) -> PyResult<Option<PyPaymentSecret>> {
        match self.inner {
            Event::PaymentReceived {
                payment_secret: s, ..
            } => Ok(match s {
                Some(secret) => Some(PyPaymentSecret { inner: secret }),
                None => None,
            }),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have payment_secret",
                self.event_type
            ))),
        }
    }

    #[getter]
    fn get_amt(&self) -> PyResult<u64> {
        match self.inner {
            Event::PaymentReceived { amt: a, .. } => Ok(a),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have amt",
                self.event_type
            ))),
        }
    }

    // PaymentSent attributes

    #[getter]
    fn get_payment_preimage(&self) -> PyResult<PyPaymentPreimage> {
        match self.inner {
            Event::PaymentSent {
                payment_preimage: p,
            } => Ok(PyPaymentPreimage { inner: p }),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have payment_preimage",
                self.event_type
            ))),
        }
    }

    // PaymentFailed attributes

    #[getter]
    fn get_rejected_by_dest(&self) -> PyResult<bool> {
        match self.inner {
            Event::PaymentFailed {
                rejected_by_dest: r,
                ..
            } => Ok(r),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have rejected_by_dest",
                self.event_type
            ))),
        }
    }

    // PendingHTLCsForwardable attributes

    #[getter]
    fn get_time_forwardable(&self) -> PyResult<(u64, u32)> {
        match self.inner {
            Event::PendingHTLCsForwardable {
                time_forwardable: t,
            } => Ok((t.as_secs(), t.subsec_nanos())),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have time_forwardable",
                self.event_type
            ))),
        }
    }

    // SpendableOutputs attributes

    #[getter]
    fn get_outputs(&self) -> PyResult<Vec<PySpendableOutputDescriptor>> {
        match &self.inner {
            Event::SpendableOutputs { outputs: o } => {
                let mut py_outputs: Vec<PySpendableOutputDescriptor> = vec![];
                for output in o.into_iter() {
                    py_outputs.push(PySpendableOutputDescriptor {
                        inner: output.clone(),
                        output_type: match_spendable_output_descriptor(output),
                    })
                }
                Ok(py_outputs)
            }
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have outputs",
                self.event_type
            ))),
        }
    }
}

#[pyclass(name=MessageSendEvent)]
#[derive(Clone)]
pub struct PyMessageSendEvent {
    pub inner: MessageSendEvent,
    pub event_type: String,
}

#[pymethods]
impl PyMessageSendEvent {
    #[staticmethod]
    fn send_accept_channel(node_id: PyPublicKey, msg: PyAcceptChannel) -> Self {
        let event = MessageSendEvent::SendAcceptChannel {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_open_channel(node_id: PyPublicKey, msg: PyOpenChannel) -> Self {
        let event = MessageSendEvent::SendOpenChannel {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_funding_created(node_id: PyPublicKey, msg: PyFundingCreated) -> Self {
        let event = MessageSendEvent::SendFundingCreated {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_funding_signed(node_id: PyPublicKey, msg: PyFundingSigned) -> Self {
        let event = MessageSendEvent::SendFundingSigned {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_funding_locked(node_id: PyPublicKey, msg: PyFundingLocked) -> Self {
        let event = MessageSendEvent::SendFundingLocked {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_announcement_signatures(node_id: PyPublicKey, msg: PyAnnouncementSignatures) -> Self {
        let event = MessageSendEvent::SendAnnouncementSignatures {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn update_htlcs(node_id: PyPublicKey, updates: PyCommitmentUpdate) -> Self {
        let event = MessageSendEvent::UpdateHTLCs {
            node_id: node_id.inner,
            updates: updates.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_revoke_and_ack(node_id: PyPublicKey, msg: PyRevokeAndACK) -> Self {
        let event = MessageSendEvent::SendRevokeAndACK {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_closing_signed(node_id: PyPublicKey, msg: PyClosingSigned) -> Self {
        let event = MessageSendEvent::SendClosingSigned {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_shutdown(node_id: PyPublicKey, msg: PyShutdown) -> Self {
        let event = MessageSendEvent::SendShutdown {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn send_channel_reestablish(node_id: PyPublicKey, msg: PyChannelReestablish) -> Self {
        let event = MessageSendEvent::SendChannelReestablish {
            node_id: node_id.inner,
            msg: msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn broadcast_channel_announcement(
        msg: PyChannelAnnouncement,
        update_msg: PyChannelUpdate,
    ) -> Self {
        let event = MessageSendEvent::BroadcastChannelAnnouncement {
            msg: msg.inner,
            update_msg: update_msg.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn broadcast_node_announcement(msg: PyNodeAnnouncement) -> Self {
        let event = MessageSendEvent::BroadcastNodeAnnouncement { msg: msg.inner };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn broadcast_channel_update(msg: PyChannelUpdate) -> Self {
        let event = MessageSendEvent::BroadcastChannelUpdate { msg: msg.inner };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn handle_error(node_id: PyPublicKey, action: PyErrorAction) -> Self {
        let event = MessageSendEvent::HandleError {
            node_id: node_id.inner,
            action: action.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[staticmethod]
    fn payment_failure_network_update(update: PyHTLCFailChannelUpdate) -> Self {
        let event = MessageSendEvent::PaymentFailureNetworkUpdate {
            update: update.inner,
        };
        PyMessageSendEvent {
            event_type: match_message_send_event_type(&event),
            inner: event,
        }
    }

    #[getter]
    fn get_type(&self) -> String {
        self.event_type.clone()
    }

    #[getter]
    fn get_node_id(&self) -> PyResult<PyPublicKey> {
        match self.inner {
            MessageSendEvent::SendAcceptChannel { node_id: i, .. }
            | MessageSendEvent::SendOpenChannel { node_id: i, .. }
            | MessageSendEvent::SendFundingCreated { node_id: i, .. }
            | MessageSendEvent::SendFundingSigned { node_id: i, .. }
            | MessageSendEvent::SendFundingLocked { node_id: i, .. }
            | MessageSendEvent::SendAnnouncementSignatures { node_id: i, .. }
            | MessageSendEvent::UpdateHTLCs { node_id: i, .. }
            | MessageSendEvent::SendRevokeAndACK { node_id: i, .. }
            | MessageSendEvent::SendClosingSigned { node_id: i, .. }
            | MessageSendEvent::SendShutdown { node_id: i, .. }
            | MessageSendEvent::SendChannelReestablish { node_id: i, .. }
            | MessageSendEvent::HandleError { node_id: i, .. } => Ok(PyPublicKey { inner: i }),
            MessageSendEvent::BroadcastChannelAnnouncement { .. }
            | MessageSendEvent::BroadcastNodeAnnouncement { .. }
            | MessageSendEvent::BroadcastChannelUpdate { .. }
            | MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {
                Err(exceptions::PyAttributeError::new_err(format!(
                    "{} does not have node_id",
                    self.event_type,
                )))
            }
        }
    }

    // Each msg type is different, so we need to return a  Py<PyAny> here.
    #[getter]
    fn get_msg(&self, py: Python) -> PyResult<Py<PyAny>> {
        match &self.inner {
            MessageSendEvent::SendAcceptChannel { msg: m, .. } => {
                Ok(PyAcceptChannel { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendOpenChannel { msg: m, .. } => {
                Ok(PyOpenChannel { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendFundingCreated { msg: m, .. } => {
                Ok(PyFundingCreated { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendFundingSigned { msg: m, .. } => {
                Ok(PyFundingSigned { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendFundingLocked { msg: m, .. } => {
                Ok(PyFundingLocked { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendAnnouncementSignatures { msg: m, .. } => {
                Ok(PyAnnouncementSignatures { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendRevokeAndACK { msg: m, .. } => {
                Ok(PyRevokeAndACK { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendClosingSigned { msg: m, .. } => {
                Ok(PyClosingSigned { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendShutdown { msg: m, .. } => {
                Ok(PyShutdown { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::SendChannelReestablish { msg: m, .. } => {
                Ok(PyChannelReestablish { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::BroadcastChannelAnnouncement { msg: m, .. } => {
                Ok(PyChannelAnnouncement { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::BroadcastNodeAnnouncement { msg: m, .. } => {
                Ok(PyNodeAnnouncement { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::BroadcastChannelUpdate { msg: m, .. } => {
                Ok(PyChannelUpdate { inner: m.clone() }.into_py(py))
            }
            MessageSendEvent::UpdateHTLCs { .. }
            | MessageSendEvent::HandleError { .. }
            | MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {
                Err(exceptions::PyAttributeError::new_err(format!(
                    "{} does not have msg",
                    self.event_type,
                )))
            }
        }
    }

    #[getter]
    fn get_updates(&self) -> PyResult<PyCommitmentUpdate> {
        match &self.inner {
            MessageSendEvent::UpdateHTLCs { updates: u, .. } => {
                Ok(PyCommitmentUpdate { inner: u.clone() })
            }
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have updates",
                self.event_type
            ))),
        }
    }

    #[getter]
    fn get_update_msg(&self) -> PyResult<PyChannelUpdate> {
        match &self.inner {
            MessageSendEvent::BroadcastChannelAnnouncement { update_msg: u, .. } => {
                Ok(PyChannelUpdate { inner: u.clone() })
            }
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have update_msg",
                self.event_type
            ))),
        }
    }

    #[getter]
    fn get_action(&self) -> PyResult<PyErrorAction> {
        match &self.inner {
            MessageSendEvent::HandleError { action: a, .. } => Ok(PyErrorAction {
                inner: a.clone(),
                error_type: match_error_action(a),
            }),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have action",
                self.event_type
            ))),
        }
    }

    #[getter]
    fn get_update(&self) -> PyResult<PyHTLCFailChannelUpdate> {
        match &self.inner {
            MessageSendEvent::PaymentFailureNetworkUpdate { update: u, .. } => {
                Ok(PyHTLCFailChannelUpdate {
                    inner: u.clone(),
                    update_type: match_htlc_fail_chan_update(u),
                })
            }
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have update",
                self.event_type
            ))),
        }
    }
}

#[pyclass(name=MessageSendEventsProvider)]
#[derive(Clone)]
pub struct PyMessageSendEventsProvider {
    pub inner: Py<PyAny>,
}

#[pymethods]
impl PyMessageSendEventsProvider {
    #[new]
    fn new(provider: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(&provider, vec!["get_and_clear_pending_msg_events"]) {
            Ok(PyMessageSendEventsProvider { inner: provider })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by MessageSendEventsProvider"
            )))
        }
    }

    fn get_and_clear_pending_msg_events(&self) -> PyResult<Vec<PyMessageSendEvent>> {
        Python::with_gil(|py| {
            let py_provider = self.inner.as_ref(py);
            process_python_return(py_provider.call_method0("get_and_clear_pending_msg_events"))
        })
    }
}

impl MessageSendEventsProvider for PyMessageSendEventsProvider {
    fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
        let mut native_events: Vec<MessageSendEvent> = vec![];
        for event in self.get_and_clear_pending_msg_events().unwrap().into_iter() {
            native_events.push(event.inner)
        }

        native_events
    }
}
