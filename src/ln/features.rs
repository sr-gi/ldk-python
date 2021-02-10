use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use lightning::ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};
use lightning::util::ser::{Readable, Writeable};

#[pyclass(name=InitFeatures)]
#[derive(Clone)]
pub struct PyInitFeatures {
    pub inner: InitFeatures,
}

#[pymethods]
impl PyInitFeatures {
    #[new]
    pub fn new() -> Self {
        PyInitFeatures {
            inner: InitFeatures::empty(),
        }
    }

    #[staticmethod]
    pub fn known() -> Self {
        PyInitFeatures {
            inner: InitFeatures::known(),
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match InitFeatures::read(&mut data) {
            Ok(x) => Ok(PyInitFeatures { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=ChannelFeatures)]
#[derive(Clone)]
pub struct PyChannelFeatures {
    pub inner: ChannelFeatures,
}

#[pymethods]
impl PyChannelFeatures {
    #[new]
    pub fn new() -> Self {
        PyChannelFeatures {
            inner: ChannelFeatures::empty(),
        }
    }

    #[staticmethod]
    pub fn known() -> Self {
        PyChannelFeatures {
            inner: ChannelFeatures::known(),
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match ChannelFeatures::read(&mut data) {
            Ok(x) => Ok(PyChannelFeatures { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}

#[pyclass(name=NodeFeatures)]
#[derive(Clone)]
pub struct PyNodeFeatures {
    pub inner: NodeFeatures,
}

#[pymethods]
impl PyNodeFeatures {
    #[new]
    pub fn new() -> Self {
        PyNodeFeatures {
            inner: NodeFeatures::empty(),
        }
    }

    #[staticmethod]
    pub fn known() -> Self {
        PyNodeFeatures {
            inner: NodeFeatures::known(),
        }
    }

    #[staticmethod]
    fn from_bytes(mut data: &[u8]) -> PyResult<Self> {
        match NodeFeatures::read(&mut data) {
            Ok(x) => Ok(PyNodeFeatures { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.encode()).into()
    }
}
