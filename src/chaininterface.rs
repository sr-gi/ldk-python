use pyo3::prelude::*;

use crate::binding_utils::process_python_return;

use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};

#[pyclass(name=FeeEstimator)]
pub struct PyFeeEstimator {
    inner: Py<PyAny>,
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

#[pymodule]
/// Chain interface module for LDK.
fn chaininterface(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyFeeEstimator>()?;
    Ok(())
}
