
use pyo3::prelude::*;

use lightning::util::logger::{Record, Logger, Level};

#[pyclass]
#[text_signature = "(logger, /)"]
/// Logger interface. The constructor requires a class implementing, at least, the ``log(message: str, level: str)`` method.
pub struct LDKLogger {
    inner: Py<PyAny>,
}

#[pymethods]
impl LDKLogger {
    #[new]
    fn new(logger: Py<PyAny>) -> Self {
        LDKLogger{inner: logger}
    }

    #[text_signature = "($self, record, level)"]
    fn log(&self, record: String, level: String) {
        Python::with_gil(|py| {
            let py_logger = self.inner.as_ref(py);
            let message = format!("{}", record);
            match py_logger.call_method("log", (message, level,), None){
                Ok(_) => (),
                Err(error) => error.print(py)
            };
        })
    }


    #[text_signature = "($self, record)"]
    fn error(&self, record: String) {
        self.log(record, Level::Error.to_string())
    }

    #[text_signature = "($self, record)"]
    fn warn(&self, record: String) {
        self.log(record, Level::Warn.to_string())
    }

    #[text_signature = "($self, record)"]
    fn info(&self, record: String) {
        self.log(record, Level::Info.to_string())
    }

    #[text_signature = "($self, record)"]
    fn debug(&self, record: String) {
        self.log(record, Level::Debug.to_string())
    }

    #[text_signature = "($self, record)"]
    fn trace(&self, record: String) {
        self.log(record, Level::Trace.to_string())
    }
}

impl Logger for LDKLogger {
    fn log(&self, record: &Record) {
        Python::with_gil(|py| {
            let py_logger = self.inner.as_ref(py);
            let message = format!("{}", record.args);
            match py_logger.call_method("log", (message, record.level.to_string()), None){
                Ok(_) => (),
                Err(error) => error.print(py)
            };
        })
    }
}


#[pymodule]
/// Loggin library for LDK.
fn logger(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LDKLogger>()?;
    Ok(())
}