use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use lightning::util::logger::{Level, Logger, Record};

#[pyclass]
#[text_signature = "(logger, /)"]
#[derive(Clone)]
/// Logger interface. The constructor requires a class implementing, at least, the ``log(message: str, level: str)`` method.
pub struct LDKLogger {
    inner: Py<PyAny>,
}

#[pymethods]
impl LDKLogger {
    #[new]
    fn new(logger: Py<PyAny>) -> Self {
        LDKLogger { inner: logger }
    }

    #[text_signature = "($self, record, level)"]
    fn log(&self, record: String, level: String) {
        Python::with_gil(|py| {
            let py_logger = self.inner.as_ref(py);
            match py_logger.call_method1("log", (record, level)) {
                Ok(_) => (),
                Err(error) => error.print(py),
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
        let message = format!("{}", record.args);
        self.log(message, record.level.to_string())
    }
}

#[pymodule]
/// Loggin module for LDK.
fn logger(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LDKLogger>()?;
    m.add_function(wrap_pyfunction!(ldk_test_logger_trait, m)?)
        .unwrap();
    Ok(())
}

// Temorary tests, until we find a better place for them

#[pyfunction]
/// Function that can be called from Python to tests that the trait bounds work
fn ldk_test_logger_trait(logger: LDKLogger, message: String) {
    inner_test(
        logger,
        &Record::new(
            Level::Debug,
            format_args!("{}", message),
            module_path!(),
            file!(),
            line!(),
        ),
    )
}

/// Actual test, should show the data in Python
fn inner_test<L: Logger>(logger: L, r: &Record) {
    logger.log(&r)
}
