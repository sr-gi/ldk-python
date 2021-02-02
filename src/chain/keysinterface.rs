use std::ops::Deref;

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::ln::chan_utils::PyChannelPublicKeys;
use crate::primitives::{PyNetwork, PyOutPoint, PyPublicKey, PySecretKey, PyTxOut};

use bitcoin::consensus::encode::serialize;
use bitcoin::secp256k1::Secp256k1;

use lightning::chain::keysinterface::{
    InMemoryChannelKeys, KeysManager, SpendableOutputDescriptor,
};

pub fn match_spendable_output_descriptor(o: &SpendableOutputDescriptor) -> String {
    match o {
        SpendableOutputDescriptor::StaticOutput { .. } => String::from("StaticOutput"),
        SpendableOutputDescriptor::DynamicOutputP2WSH { .. } => String::from("DynamicOutputP2WSH"),
        SpendableOutputDescriptor::StaticOutputCounterpartyPayment { .. } => {
            String::from("StaticOutputCounterpartyPayment")
        }
    }
}

#[pyclass(name=SpendableOutputDescriptor)]
#[derive(Clone)]
pub struct PySpendableOutputDescriptor {
    pub inner: SpendableOutputDescriptor,
    pub output_type: String,
}

#[pymethods]
impl PySpendableOutputDescriptor {
    #[staticmethod]
    fn static_output(outpoint: PyOutPoint, output: PyTxOut) -> Self {
        let descriptor = SpendableOutputDescriptor::StaticOutput {
            outpoint: outpoint.inner,
            output: output.inner,
        };
        PySpendableOutputDescriptor {
            output_type: match_spendable_output_descriptor(&descriptor),
            inner: descriptor,
        }
    }

    #[staticmethod]
    fn dynamic_output_pwsh(
        outpoint: PyOutPoint,
        per_commitment_point: PyPublicKey,
        to_self_delay: u16,
        output: PyTxOut,
        key_derivation_params: (u64, u64),
        revocation_pubkey: PyPublicKey,
    ) -> Self {
        let descriptor = SpendableOutputDescriptor::DynamicOutputP2WSH {
            outpoint: outpoint.inner,
            per_commitment_point: per_commitment_point.inner,
            to_self_delay,
            output: output.inner,
            key_derivation_params,
            revocation_pubkey: revocation_pubkey.inner,
        };
        PySpendableOutputDescriptor {
            output_type: match_spendable_output_descriptor(&descriptor),
            inner: descriptor,
        }
    }

    #[staticmethod]
    fn static_output_counterparty_payment(
        outpoint: PyOutPoint,
        output: PyTxOut,
        key_derivation_params: (u64, u64),
    ) -> Self {
        let descriptor = SpendableOutputDescriptor::StaticOutputCounterpartyPayment {
            outpoint: outpoint.inner,
            output: output.inner,
            key_derivation_params,
        };
        PySpendableOutputDescriptor {
            output_type: match_spendable_output_descriptor(&descriptor),
            inner: descriptor,
        }
    }

    #[getter]
    fn get_type(&self) -> String {
        self.output_type.clone()
    }

    // Shared attributes

    #[getter]
    fn outpoint(&self) -> PyOutPoint {
        match self.inner {
            SpendableOutputDescriptor::StaticOutput { outpoint: o, .. } => PyOutPoint { inner: o },
            SpendableOutputDescriptor::DynamicOutputP2WSH { outpoint: o, .. } => {
                PyOutPoint { inner: o }
            }
            SpendableOutputDescriptor::StaticOutputCounterpartyPayment { outpoint: o, .. } => {
                PyOutPoint { inner: o }
            }
        }
    }

    #[getter]
    fn output(&self) -> PyTxOut {
        match &self.inner {
            SpendableOutputDescriptor::StaticOutput { output: o, .. } => {
                PyTxOut { inner: o.clone() }
            }
            SpendableOutputDescriptor::DynamicOutputP2WSH { output: o, .. } => {
                PyTxOut { inner: o.clone() }
            }
            SpendableOutputDescriptor::StaticOutputCounterpartyPayment { output: o, .. } => {
                PyTxOut { inner: o.clone() }
            }
        }
    }

    // DynamicOutputP2WSH attributes

    #[getter]
    fn per_commitment_point(&self) -> PyResult<PyPublicKey> {
        match self.inner {
            SpendableOutputDescriptor::DynamicOutputP2WSH {
                per_commitment_point: p,
                ..
            } => Ok(PyPublicKey { inner: p }),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have per_commitment_point",
                self.output_type
            ))),
        }
    }

    #[getter]
    fn to_self_delay(&self) -> PyResult<u16> {
        match self.inner {
            SpendableOutputDescriptor::DynamicOutputP2WSH {
                to_self_delay: d, ..
            } => Ok(d),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have to_self_delay",
                self.output_type
            ))),
        }
    }

    #[getter]
    fn revocation_pubkey(&self) -> PyResult<PyPublicKey> {
        match self.inner {
            SpendableOutputDescriptor::DynamicOutputP2WSH {
                revocation_pubkey: r,
                ..
            } => Ok(PyPublicKey { inner: r }),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have revocation_pubkey",
                self.output_type
            ))),
        }
    }

    // Attributes shared amongst DynamicOutputP2WSH and StaticOutputCounterpartyPayment

    #[getter]
    fn key_derivation_params(&self) -> PyResult<(u64, u64)> {
        match self.inner {
            SpendableOutputDescriptor::DynamicOutputP2WSH {
                key_derivation_params: p,
                ..
            } => Ok(p),
            SpendableOutputDescriptor::StaticOutputCounterpartyPayment {
                key_derivation_params: p,
                ..
            } => Ok(p),
            _ => Err(exceptions::PyAttributeError::new_err(format!(
                "{} does not have key_derivation_params",
                self.output_type
            ))),
        }
    }
}

#[pyclass(name=InMemoryChannelKeys)]
#[derive(Clone)]
pub struct PyInMemoryChannelKeys {
    pub inner: InMemoryChannelKeys,
}

#[pymethods]
impl PyInMemoryChannelKeys {
    #[new]
    pub fn new(
        funding_key: PySecretKey,
        revocation_base_key: PySecretKey,
        payment_key: PySecretKey,
        delayed_payment_base_key: PySecretKey,
        htlc_base_key: PySecretKey,
        commitment_seed: [u8; 32],
        channel_value_satoshis: u64,
        key_derivation_params: (u64, u64),
    ) -> Self {
        PyInMemoryChannelKeys {
            inner: InMemoryChannelKeys::new(
                &Secp256k1::signing_only(),
                funding_key.inner,
                revocation_base_key.inner,
                payment_key.inner,
                delayed_payment_base_key.inner,
                htlc_base_key.inner,
                commitment_seed,
                channel_value_satoshis,
                key_derivation_params,
            ),
        }
    }

    #[getter]
    fn funding_key(&self) -> PySecretKey {
        PySecretKey {
            inner: self.inner.funding_key,
        }
    }

    #[getter]
    fn revocation_base_key(&self) -> PySecretKey {
        PySecretKey {
            inner: self.inner.revocation_base_key,
        }
    }

    #[getter]
    fn payment_key(&self) -> PySecretKey {
        PySecretKey {
            inner: self.inner.payment_key,
        }
    }
    #[getter]
    fn delayed_payment_base_key(&self) -> PySecretKey {
        PySecretKey {
            inner: self.inner.delayed_payment_base_key,
        }
    }
    #[getter]
    fn htlc_base_key(&self) -> PySecretKey {
        PySecretKey {
            inner: self.inner.htlc_base_key,
        }
    }

    #[getter]
    fn commitment_seed(&self, py: Python) -> PyObject {
        PyBytes::new(py, &serialize(&self.inner.commitment_seed)).into()
    }

    // FIXME: Not completely sure whether this three should be binded or not.
    // The following methods panic if called on accepted channels
    // #PANIC-ERROR
    fn counterparty_pubkeys(&self) -> PyChannelPublicKeys {
        PyChannelPublicKeys {
            inner: self.inner.counterparty_pubkeys().clone(),
        }
    }

    fn counterparty_selected_contest_delay(&self) -> u16 {
        self.inner.counterparty_selected_contest_delay()
    }

    fn holder_selected_contest_delay(&self) -> u16 {
        self.inner.holder_selected_contest_delay()
    }
}

#[pyclass(unsendable, name=KeysManager)]
#[derive(Clone)]
pub struct PyKeysManager {
    pub inner: *mut KeysManager,
}

impl Deref for PyKeysManager {
    type Target = KeysManager;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner }
    }
}

#[pymethods]
impl PyKeysManager {
    #[new]
    fn new(
        seed: [u8; 32],
        network: PyNetwork,
        starting_time_secs: u64,
        starting_time_nanos: u32,
    ) -> Self {
        let km = KeysManager::new(
            &seed,
            network.inner,
            starting_time_secs,
            starting_time_nanos,
        );
        PyKeysManager {
            inner: Box::into_raw(Box::new(km)),
        }
    }

    fn derive_channel_keys(
        &self,
        channel_value_satoshis: u64,
        params_1: u64,
        params_2: u64,
    ) -> PyInMemoryChannelKeys {
        unsafe {
            let chan_keys = self.inner.as_ref().unwrap();
            PyInMemoryChannelKeys {
                inner: chan_keys.derive_channel_keys(channel_value_satoshis, params_1, params_2),
            }
        }
    }
}
