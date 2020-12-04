use pyo3::exceptions;
use pyo3::prelude::*;

use crate::channelmanager::PyPaymentHash;
use crate::primitives::{PyPublicKey, PySignature, PyTransaction};

use lightning::ln::chan_utils::{
    ChannelPublicKeys, HTLCOutputInCommitment, HolderCommitmentTransaction, TxCreationKeys,
};

use bitcoin::secp256k1::Secp256k1;

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
        broadcaster_delayed_payment_base: PyPublicKey,
        broadcaster_htlc_base: PyPublicKey,
        countersignatory_revocation_base: PyPublicKey,
        countersignatory_htlc_base: PyPublicKey,
    ) -> PyResult<Self> {
        match TxCreationKeys::derive_new(
            &Secp256k1::new(),
            &per_commitment_point.inner,
            &broadcaster_delayed_payment_base.inner,
            &broadcaster_htlc_base.inner,
            &countersignatory_revocation_base.inner,
            &countersignatory_htlc_base.inner,
        ) {
            Ok(x) => Ok(PyTxCreationKeys { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
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
}

#[pymodule]
/// Keys manager module for LDK.
fn chan_utils(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyChannelPublicKeys>()?;
    Ok(())
}
