use pyo3::prelude::*;

use crate::primitives::PyPublicKey;

use lightning::ln::chan_utils::ChannelPublicKeys;

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

#[pymodule]
/// Keys manager module for LDK.
fn chan_utils(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyChannelPublicKeys>()?;
    Ok(())
}
