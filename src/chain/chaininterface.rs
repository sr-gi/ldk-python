use pyo3::prelude::*;

use crate::primitives::PyTransaction;
use crate::process_python_return;

use bitcoin::blockdata::transaction::Transaction;

use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};

#[pyclass(name=FeeEstimator)]
#[derive(Clone)]
pub struct PyFeeEstimator {
    pub inner: Py<PyAny>,
}

#[pymethods]
impl PyFeeEstimator {
    #[new]
    fn new(fee_estimator: Py<PyAny>) -> Self {
        PyFeeEstimator {
            inner: fee_estimator,
        }
    }

    #[text_signature = "($self, confirmation_target)"]
    fn get_est_sat_per_1000_weight(&self, confirmation_target: String) -> PyResult<u32> {
        Python::with_gil(|py| {
            let py_fee_estimator = self.inner.as_ref(py);
            process_python_return(
                py_fee_estimator
                    .call_method1("get_est_sat_per_1000_weight", (confirmation_target,)),
            )
        })
    }
}

impl FeeEstimator for PyFeeEstimator {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        let target = match confirmation_target {
            // FIXME: This could be improved if there's a clean way to go cast enum keys to String.
            ConfirmationTarget::Background => String::from("Background"),
            ConfirmationTarget::Normal => String::from("Normal"),
            ConfirmationTarget::HighPriority => String::from("HighPriority"),
        };
        self.get_est_sat_per_1000_weight(target).unwrap()
    }
}

#[pyclass(name=BroadcasterInterface)]
#[derive(Clone)]
pub struct PyBroadcasterInterface {
    pub inner: Py<PyAny>,
}

#[pymethods]
impl PyBroadcasterInterface {
    #[new]
    fn new(broadcaster_interface: Py<PyAny>) -> Self {
        PyBroadcasterInterface {
            inner: broadcaster_interface,
        }
    }

    #[text_signature = "($self, confirmation_target)"]
    fn broadcast_transaction(&self, transaction: PyTransaction) {
        Python::with_gil(|py| {
            let broadcast_interface = self.inner.as_ref(py);
            let _: PyResult<PyTransaction> = process_python_return(
                broadcast_interface.call_method1("broadcast_transaction", (transaction,)),
            );
        })
    }
}

impl BroadcasterInterface for PyBroadcasterInterface {
    fn broadcast_transaction(&self, tx: &Transaction) {
        self.broadcast_transaction(PyTransaction { inner: tx.clone() })
    }
}
