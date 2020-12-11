use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyObjectProtocol;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
use bitcoin::hash_types::Txid;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::constants::{PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE};
use bitcoin::secp256k1::key::{PublicKey, SecretKey};
use bitcoin::secp256k1::Signature;

use lightning::chain::transaction::OutPoint;

#[pyclass(name=SecretKey)]
#[derive(Clone)]
pub struct PySecretKey {
    pub inner: SecretKey,
}

#[pymethods]
impl PySecretKey {
    #[new]
    pub fn new(data: [u8; 32]) -> PyResult<Self> {
        let sk = match SecretKey::from_slice(&data) {
            Ok(x) => Ok(PySecretKey { inner: x }),
            Err(error) => Err(exceptions::PyValueError::new_err(format!("{}", error))),
        };
        sk
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner[..]).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PySecretKey {
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{:#x}", self.inner))
    }
}

#[pyclass(name=PublicKey)]
#[derive(Clone)]
pub struct PyPublicKey {
    pub inner: PublicKey,
}

#[pymethods]
impl PyPublicKey {
    #[new]
    pub fn new(data: &[u8]) -> PyResult<Self> {
        if data.len() != PUBLIC_KEY_SIZE && data.len() != UNCOMPRESSED_PUBLIC_KEY_SIZE {
            Err(exceptions::PyValueError::new_err(format!(
                "Data must be {} or {} bytes long",
                PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE
            )))
        } else {
            let pk = match PublicKey::from_slice(data) {
                Ok(x) => Ok(PyPublicKey { inner: x }),
                Err(error) => Err(exceptions::PyValueError::new_err(format!("{}", error))),
            };
            pk
        }
    }

    #[args(compressed = "true")]
    fn serialize(&self, py: Python, compressed: bool) -> Py<PyBytes> {
        if compressed {
            PyBytes::new(py, &self.inner.serialize()).into()
        } else {
            PyBytes::new(py, &self.inner.serialize_uncompressed()).into()
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyPublicKey {
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{:#x}", self.inner))
    }
}

#[pyclass(name=Signature)]
#[derive(Clone)]
pub struct PySignature {
    pub inner: Signature,
}

#[pyclass(name=BlockHeader)]
pub struct PyBlockHeader {
    inner: BlockHeader,
}

#[pymethods]
impl PyBlockHeader {
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        if data.len() != 80 {
            Err(exceptions::PyValueError::new_err(format!(
                "Data must be 80-byte long"
            )))
        } else {
            let header = match deserialize(&data) {
                Ok(x) => Ok(PyBlockHeader { inner: x }),
                Err(error) => Err(exceptions::PyValueError::new_err(format!("{}", error))),
            };
            header
        }
    }

    #[getter]
    fn version(&self) -> i32 {
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

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner)).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyBlockHeader {
    fn __str__(&self) -> PyResult<String> {
        Ok(serialize_hex(&self.inner))
    }
}

#[pyclass(name=Script)]
#[derive(Clone)]
pub struct PyScript {
    pub inner: Script,
}

#[pymethods]
impl PyScript {
    #[new]
    pub fn new(data: Vec<u8>) -> Self {
        PyScript {
            inner: Script::from(data),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, self.inner.as_bytes()).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyScript {
    fn __str__(&self) -> PyResult<String> {
        Ok(serialize_hex(&self.inner))
    }
}

#[pyclass(name=TxId)]
#[derive(Clone)]
pub struct PyTxId {
    pub inner: Txid,
}

#[pymethods]
impl PyTxId {
    #[new]
    pub fn new(data: [u8; 32]) -> Self {
        PyTxId {
            inner: deserialize(&data).unwrap(),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner)).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyTxId {
    fn __str__(&self) -> PyResult<String> {
        Ok(serialize_hex(&self.inner))
    }
}

#[pyclass(name=OutPoint)]
#[derive(Clone)]
pub struct PyOutPoint {
    pub inner: OutPoint,
}

#[pymethods]
impl PyOutPoint {
    #[new]
    pub fn new(txid: PyTxId, index: u16) -> Self {
        PyOutPoint {
            inner: OutPoint {
                txid: txid.inner,
                index,
            },
        }
    }

    #[staticmethod]
    pub fn from_bytes(txid: [u8; 32], index: u16) -> Self {
        PyOutPoint::new(PyTxId::new(txid), index)
    }

    #[getter]
    fn txid(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner.txid)).into()
    }

    #[getter]
    fn index(&self) -> u16 {
        self.inner.index
    }

    pub fn to_channel_id(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner.to_channel_id())).into()
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner.into_bitcoin_outpoint())).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyOutPoint {
    fn __str__(&self) -> PyResult<String> {
        Ok(serialize_hex(&self.inner.into_bitcoin_outpoint()))
    }
}

#[pyclass(name=Transaction)]
#[derive(Clone)]
pub struct PyTransaction {
    pub inner: Transaction,
}

#[pymethods]
impl PyTransaction {
    #[new]
    pub fn new(data: &[u8]) -> Self {
        PyTransaction {
            inner: deserialize(data).unwrap(),
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyTransaction {
    fn __str__(&self) -> PyResult<String> {
        Ok(serialize_hex(&self.inner))
    }
}

#[pyclass(name=Network)]
#[derive(Clone)]
pub struct PyNetwork {
    pub inner: Network,
}

#[pymethods]
impl PyNetwork {
    #[staticmethod]
    pub fn mainnet() -> Self {
        PyNetwork {
            inner: Network::Bitcoin,
        }
    }

    #[staticmethod]
    pub fn testnet() -> Self {
        PyNetwork {
            inner: Network::Testnet,
        }
    }

    #[staticmethod]
    pub fn regtest() -> Self {
        PyNetwork {
            inner: Network::Regtest,
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyNetwork {
    fn __str__(&self) -> &str {
        match self.inner {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        }
    }
}
