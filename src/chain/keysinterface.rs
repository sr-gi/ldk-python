use std::ops::Deref;
use std::panic;

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::ln::chan_utils::PyChannelPublicKeys;
use crate::primitives::{PyNetwork, PySecretKey};

use bitcoin::consensus::encode::serialize;
use bitcoin::secp256k1::Secp256k1;

use lightning::chain::keysinterface::{InMemoryChannelKeys, KeysManager};

#[pyclass(name=InMemoryChannelKeys)]
#[derive(Clone)]
pub struct PyInMemoryChannelKeys {
    inner: InMemoryChannelKeys,
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

    // FIXME: Not completely sure whether this three should be binded or not. Capturiong the panics for now.

    fn counterparty_pubkeys(&self) -> PyResult<PyChannelPublicKeys> {
        match panic::catch_unwind(|| PyChannelPublicKeys {
            inner: self.inner.counterparty_pubkeys().clone(),
        }) {
            Ok(x) => Ok(x),
            Err(_) => Err(exceptions::PyRuntimeError::new_err(format!(
                "method can only be called for accepted channels"
            ))),
        }
    }

    fn counterparty_selected_contest_delay(&self) -> PyResult<u16> {
        match panic::catch_unwind(|| self.inner.counterparty_selected_contest_delay()) {
            Ok(x) => Ok(x),
            Err(_) => Err(exceptions::PyRuntimeError::new_err(format!(
                "method can only be called for accepted channels"
            ))),
        }
    }

    fn holder_selected_contest_delay(&self) -> PyResult<u16> {
        match panic::catch_unwind(|| self.inner.holder_selected_contest_delay()) {
            Ok(x) => Ok(x),
            Err(_) => Err(exceptions::PyRuntimeError::new_err(format!(
                "method can only be called for accepted channels"
            ))),
        }
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
}
