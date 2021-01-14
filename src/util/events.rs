use lightning::util::events::Event;
use pyo3::prelude::*;
use std::time::Duration;

use crate::chain::keysinterface::PySpendableOutputDescriptor;
use crate::ln::channelmanager::{PyPaymentHash, PyPaymentPreimage, PyPaymentSecret};
use crate::primitives::{PyOutPoint, PyScript};

pub fn match_event_type(e: &Event) -> String {
    match e {
        Event::FundingGenerationReady {
            temporary_channel_id: _,
            channel_value_satoshis: _,
            output_script: _,
            user_channel_id: _,
        } => String::from("FundingGenerationReady"),
        Event::FundingBroadcastSafe {
            funding_txo: _,
            user_channel_id: _,
        } => String::from("FundingBroadcastSafe"),
        Event::PaymentReceived {
            payment_hash: _,
            payment_secret: _,
            amt: _,
        } => String::from("PaymentReceived"),
        Event::PaymentSent {
            payment_preimage: _,
        } => String::from("PaymentSent"),
        Event::PaymentFailed {
            payment_hash: _,
            rejected_by_dest: _,
        } => String::from("PaymentFailed"),
        Event::PendingHTLCsForwardable {
            time_forwardable: _,
        } => String::from("PendingHTLCsForwardable"),
        Event::SpendableOutputs { outputs: _ } => String::from("SpendableOutputs"),
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
}
