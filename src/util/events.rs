use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::time::Duration;

use lightning::util::events::Event;

use crate::chain::keysinterface::{match_spendable_output_descriptor, PySpendableOutputDescriptor};
use crate::ln::channelmanager::{PyPaymentHash, PyPaymentPreimage, PyPaymentSecret};
use crate::primitives::{PyOutPoint, PyScript};

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
    fn temporary_channel_id(&self, py: Python) -> PyResult<Py<PyBytes>> {
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
    fn channel_value_satoshis(&self) -> PyResult<u64> {
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
    fn output_script(&self) -> PyResult<PyScript> {
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
    fn user_channel_id(&self) -> PyResult<u64> {
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
    fn funding_txo(&self) -> PyResult<PyOutPoint> {
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
    fn payment_hash(&self) -> PyResult<PyPaymentHash> {
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
    fn payment_secret(&self) -> PyResult<Option<PyPaymentSecret>> {
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
    fn amt(&self) -> PyResult<u64> {
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
    fn payment_preimage(&self) -> PyResult<PyPaymentPreimage> {
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
    fn rejected_by_dest(&self) -> PyResult<bool> {
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
    fn time_forwardable(&self) -> PyResult<(u64, u32)> {
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
    fn outputs(&self) -> PyResult<Vec<PySpendableOutputDescriptor>> {
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
