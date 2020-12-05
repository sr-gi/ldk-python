use pyo3::prelude::*;

use lightning::ln::channelmanager::PaymentHash;

#[pyclass(name=PaymentHash)]
#[derive(Clone)]
pub struct PyPaymentHash {
    pub inner: PaymentHash,
}

#[pymethods]
impl PyPaymentHash {
    #[new]
    pub fn new(data: [u8; 32]) -> Self {
        PyPaymentHash {
            inner: PaymentHash(data),
        }
    }
}
