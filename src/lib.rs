use pyo3::prelude::*;

pub mod binding_utils;
pub mod chaininterface;
pub mod chan_utils;
pub mod channelmanager;
pub mod keysinterface;
pub mod logger;
pub mod primitives;

/// LDK bindings for Python
#[pymodule]
fn ldk_python(_: Python, _: &PyModule) -> PyResult<()> {
    Ok(())
}
