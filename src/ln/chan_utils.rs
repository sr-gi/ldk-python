use pyo3::prelude::*;

use crate::ln::channelmanager::PyPaymentHash;
use crate::primitives::{PyPublicKey, PySignature, PyTransaction};

use lightning::ln::chan_utils::{
    ChannelPublicKeys, HTLCOutputInCommitment, HolderCommitmentTransaction, TxCreationKeys,
};

#[pyclass(name=ChannelPublicKeys)]
#[derive(Clone)]
pub struct PyChannelPublicKeys {
    pub inner: ChannelPublicKeys,
}

#[pymethods]
impl PyChannelPublicKeys {
    #[new]
    pub fn new(
        funding_pubkey: PyPublicKey,
        revocation_basepoint: PyPublicKey,
        payment_point: PyPublicKey,
        delayed_payment_basepoint: PyPublicKey,
        htlc_basepoint: PyPublicKey,
    ) -> Self {
        PyChannelPublicKeys {
            inner: ChannelPublicKeys {
                funding_pubkey: funding_pubkey.inner,
                revocation_basepoint: revocation_basepoint.inner,
                payment_point: payment_point.inner,
                delayed_payment_basepoint: delayed_payment_basepoint.inner,
                htlc_basepoint: htlc_basepoint.inner,
            },
        }
    }

    #[getter]
    fn funding_pubkey(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.funding_pubkey,
        }
    }

    #[getter]
    fn revocation_basepoint(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.revocation_basepoint,
        }
    }

    #[getter]
    fn payment_point(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.payment_point,
        }
    }

    #[getter]
    fn delayed_payment_basepoint(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.delayed_payment_basepoint,
        }
    }

    #[getter]
    fn htlc_basepoint(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.htlc_basepoint,
        }
    }
}

#[pyclass(name=TxCreationKeys)]
#[derive(Clone)]
pub struct PyTxCreationKeys {
    pub inner: TxCreationKeys,
}

#[pymethods]
impl PyTxCreationKeys {
    #[new]
    pub fn new(
        per_commitment_point: PyPublicKey,
        revocation_key: PyPublicKey,
        broadcaster_htlc_key: PyPublicKey,
        countersignatory_htlc_key: PyPublicKey,
        broadcaster_delayed_payment_key: PyPublicKey,
    ) -> Self {
        PyTxCreationKeys {
            inner: TxCreationKeys {
                per_commitment_point: per_commitment_point.inner,
                revocation_key: revocation_key.inner,
                broadcaster_htlc_key: broadcaster_htlc_key.inner,
                countersignatory_htlc_key: countersignatory_htlc_key.inner,
                broadcaster_delayed_payment_key: broadcaster_delayed_payment_key.inner,
            },
        }
    }

    #[getter]
    fn per_commitment_point(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.per_commitment_point,
        }
    }

    #[getter]
    fn revocation_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.revocation_key,
        }
    }

    #[getter]
    fn broadcaster_htlc_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.broadcaster_htlc_key,
        }
    }

    #[getter]
    fn countersignatory_htlc_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.countersignatory_htlc_key,
        }
    }

    #[getter]
    fn broadcaster_delayed_payment_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.broadcaster_delayed_payment_key,
        }
    }
}

#[pyclass(name=HTLCOutputInCommitment)]
#[derive(Clone)]
pub struct PyHTLCOutputInCommitment {
    inner: HTLCOutputInCommitment,
}

#[pymethods]
impl PyHTLCOutputInCommitment {
    #[new]
    pub fn new(
        offered: bool,
        amount_msat: u64,
        cltv_expiry: u32,
        payment_hash: PyPaymentHash,
        transaction_output_index: Option<u32>,
    ) -> Self {
        PyHTLCOutputInCommitment {
            inner: HTLCOutputInCommitment {
                offered,
                amount_msat,
                cltv_expiry,
                payment_hash: payment_hash.inner,
                transaction_output_index,
            },
        }
    }

    #[getter]
    fn offered(&self) -> bool {
        self.inner.offered
    }

    #[getter]
    fn amount_msat(&self) -> u64 {
        self.inner.amount_msat
    }

    #[getter]
    fn cltv_expiry(&self) -> u32 {
        self.inner.cltv_expiry
    }

    #[getter]
    fn payment_hash(&self) -> PyPaymentHash {
        PyPaymentHash {
            inner: self.inner.payment_hash,
        }
    }

    #[getter]
    fn transaction_output_index(&self) -> Option<u32> {
        self.inner.transaction_output_index
    }
}

#[pyclass(name=HolderCommitmentTransaction)]
#[derive(Clone)]
pub struct PyHolderCommitmentTransaction {
    pub inner: HolderCommitmentTransaction,
}

#[pymethods]
impl PyHolderCommitmentTransaction {
    #[new]
    pub fn new(
        unsigned_tx: PyTransaction,
        counterparty_sig: PySignature,
        holder_funding_key: PyPublicKey,
        counterparty_funding_key: PyPublicKey,
        keys: PyTxCreationKeys,
        feerate_per_kw: u32,
        htlc_data: Vec<(PyHTLCOutputInCommitment, Option<PySignature>)>,
    ) -> Self {
        let mut extracted_htlc_data = Vec::new();
        for py_data in htlc_data.into_iter() {
            match py_data.1 {
                Some(x) => extracted_htlc_data.push((py_data.0.inner, Some(x.inner))),
                None => extracted_htlc_data.push((py_data.0.inner, None)),
            }
        }

        PyHolderCommitmentTransaction {
            inner: HolderCommitmentTransaction::new_missing_holder_sig(
                unsigned_tx.inner,
                counterparty_sig.inner,
                &holder_funding_key.inner,
                &counterparty_funding_key.inner,
                keys.inner,
                feerate_per_kw,
                extracted_htlc_data,
            ),
        }
    }

    #[getter]
    fn unsigned_tx(&self) -> PyTransaction {
        PyTransaction {
            inner: self.inner.unsigned_tx.clone(),
        }
    }

    #[getter]
    fn counterparty_sig(&self) -> PySignature {
        PySignature {
            inner: self.inner.counterparty_sig,
        }
    }

    #[getter]
    fn feerate_per_kw(&self) -> u32 {
        self.inner.feerate_per_kw
    }

    #[getter]
    fn per_htlc(&self) -> Vec<(PyHTLCOutputInCommitment, Option<PySignature>)> {
        let mut py_per_htlc = vec![];
        for htlc_data in self.inner.per_htlc.iter() {
            py_per_htlc.push((
                PyHTLCOutputInCommitment {
                    inner: htlc_data.0.clone(),
                },
                match htlc_data.1 {
                    Some(x) => Some(PySignature { inner: x }),
                    None => None,
                },
            ))
        }
        py_per_htlc
    }
}
