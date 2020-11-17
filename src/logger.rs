
use pyo3::prelude::*;

use lightning::util::logger::{Record, Logger};

#[pyclass]
pub struct LDKLogger {
    inner: Py<PyAny>,
}

#[pymethods]
impl LDKLogger {
    #[new]
    fn new(logger: Py<PyAny>) -> Self {
        LDKLogger{inner: logger}
    }

    // This may not be necessary given we don't need to log from python using the wrapper
    // fn log(&self, record: String) {
    //     // figure out how to deal with this
    //     let message = format_args!("");
    //     let r = Record::new(Level::Info, message, module_path!(), file!(), line!());
    //     Logger::log(self, &r)
    // }
}

impl Logger for LDKLogger {
    fn log(&self, record: &Record) {
        Python::with_gil(|py| {
            let py_logger = self.inner.as_ref(py);
            let message = format!("{:<5} [{} : {}, {}] {}", record.level.to_string(), record.module_path, record.file, record.line, record.args);
            match py_logger.call_method("log", (message,), None){
                Ok(_) => (),
                Err(error) => error.print(py)
            };
        })
    }
}


#[pymodule]
fn logger(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LDKLogger>()?;
    Ok(())
}