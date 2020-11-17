use pyo3::prelude::*;

pub mod primitives;
pub mod logger;


/// LDK bindings for Python
#[pymodule]
fn ldk_python(_: Python, _: &PyModule) -> PyResult<()> {
    Ok(())
}
