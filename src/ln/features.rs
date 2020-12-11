use pyo3::prelude::*;

use lightning::ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};

#[pyclass(name=InitFeatures)]
#[derive(Clone)]
pub struct PyInitFeatures {
    pub inner: InitFeatures,
}

// FIXME: add from bytes
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
}

#[pyclass(name=ChannelFeatures)]
#[derive(Clone)]
pub struct PyChannelFeatures {
    pub inner: ChannelFeatures,
}

// FIXME: add from bytes
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
}

#[pyclass(name=NodeFeatures)]
#[derive(Clone)]
pub struct PyNodeFeatures {
    pub inner: NodeFeatures,
}

// FIXME: add from bytes
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
}
