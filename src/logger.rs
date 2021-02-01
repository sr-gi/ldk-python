use pyo3::exceptions;
use pyo3::prelude::*;

use crate::has_trait_bound;

use lightning::util::logger::{Level, Logger, Record};

#[pyclass]
#[text_signature = "(logger, /)"]
#[derive(Clone)]
/// Logger interface. The constructor requires a class implementing, at least, the ``log(message: str, level: str)`` method.
pub struct LDKLogger {
    pub inner: Py<PyAny>,
}

#[pymethods]
impl LDKLogger {
    #[new]
    fn new(logger: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(&logger, vec!["log"]) {
            Ok(LDKLogger { inner: logger })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by Logger"
            )))
        }
    }

    #[text_signature = "($self, record, level)"]
    fn log(&self, record: String, level: String) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_logger = self.inner.as_ref(py);
            match py_logger.call_method1("log", (record, level)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    #[text_signature = "($self, record)"]
    fn error(&self, record: String) -> PyResult<()> {
        self.log(record, Level::Error.to_string())
    }

    #[text_signature = "($self, record)"]
    fn warn(&self, record: String) -> PyResult<()> {
        self.log(record, Level::Warn.to_string())
    }

    #[text_signature = "($self, record)"]
    fn info(&self, record: String) -> PyResult<()> {
        self.log(record, Level::Info.to_string())
    }

    #[text_signature = "($self, record)"]
    fn debug(&self, record: String) -> PyResult<()> {
        self.log(record, Level::Debug.to_string())
    }

    #[text_signature = "($self, record)"]
    fn trace(&self, record: String) -> PyResult<()> {
        self.log(record, Level::Trace.to_string())
    }
}

impl Logger for LDKLogger {
    fn log(&self, record: &Record) {
        let message = format!("{}", record.args);
        self.log(message, record.level.to_string()).unwrap()
    }
}
