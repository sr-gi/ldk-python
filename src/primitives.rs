use pyo3::prelude::*;
use pyo3::PyObjectProtocol;
use pyo3::exceptions;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::secp256k1::key::{SecretKey, PublicKey};
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::secp256k1::constants::{SECRET_KEY_SIZE, PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE};


#[pyclass(name=SecretKey)]
pub struct PySecretKey {
    inner: SecretKey
}


#[pymethods]
impl PySecretKey {
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        if data.len() != SECRET_KEY_SIZE {
            Err(exceptions::PyValueError::new_err(format!("Data must be {}-byte long", SECRET_KEY_SIZE)))
        } else {
            let sk = match SecretKey::from_slice(data) {
                Ok(x) => Ok(PySecretKey{inner: x}),
                Err(error) => Err(exceptions::PyValueError::new_err(format!("{}", error))),
            };
            sk
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PySecretKey {
    fn __str__(&self) -> PyResult<String>   {
        Ok(format!("{:#x}", self.inner))
    }
}

#[pyclass(name=PublicKey)]
pub struct PyPublicKey {
    inner: PublicKey
}

#[pymethods]
impl PyPublicKey {
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        if data.len() != PUBLIC_KEY_SIZE && data.len() != UNCOMPRESSED_PUBLIC_KEY_SIZE {
            Err(exceptions::PyValueError::new_err(format!("Data must be {} or {} bytes long", PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE)))
        } else {
            let pk = match PublicKey::from_slice(data) {
                Ok(x) => Ok(PyPublicKey{inner: x}),
                Err(error) => Err(exceptions::PyValueError::new_err(format!("{}", error))),
            };
            pk
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyPublicKey {
    fn __str__(&self) -> PyResult<String>   {
        Ok(format!("{:#x}", self.inner))
    }
}

#[pyclass(name=BlockHeader)]
pub struct PyBlockHeader {
    inner: BlockHeader
}

#[pymethods]
impl PyBlockHeader {
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        if data.len() != 80 {
            Err(exceptions::PyValueError::new_err(format!("Data must be 80-byte long")))
        } else {
            let header = match  deserialize(&data) {
                Ok(x) => Ok(PyBlockHeader{inner: x}),
                Err(error) => Err(exceptions::PyValueError::new_err(format!("{}", error))),
            };
            header
        }
    }

    #[getter]
    fn version(&self) -> u32 {
        self.inner.version
    }

    #[getter]
    fn prev_blockhash(&self) -> String {
        self.inner.prev_blockhash.to_string()
    }

    #[getter]
    fn merkle_root(&self) -> String {
        self.inner.merkle_root.to_string()
    }

    #[getter]
    fn time(&self) -> u32 {
        self.inner.time
    }

    #[getter]
    fn bits(&self) -> u32 {
        self.inner.bits
    }

    #[getter]
    fn nonce(&self) -> u32 {
        self.inner.nonce
    }
}

#[pyproto]
impl PyObjectProtocol for PyBlockHeader {
    fn __str__(&self) -> PyResult<String>   {
        Ok(serialize_hex(&self.inner))
    }
}

#[pymodule]
fn primitives(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PySecretKey>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyBlockHeader>()?;
    Ok(())
}
