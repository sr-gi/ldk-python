use std::str;

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyObjectProtocol;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
use bitcoin::hash_types::Txid;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1;
use bitcoin::secp256k1::constants::{PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE};
use bitcoin::secp256k1::key::{PublicKey, SecretKey};

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

    fn sign(&self, message: String) -> PyResult<PySignature> {
        let message_hash = sha256::Hash::hash(message.as_bytes());
        let message_hash = secp256k1::Message::from_slice(&message_hash);
        match message_hash {
            Ok(x) => Ok(PySignature {
                inner: secp256k1::Secp256k1::new().sign(&x, &self.inner),
            }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
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

    #[staticmethod]
    pub fn from_secret_key(sk: PySecretKey) -> Self {
        PyPublicKey {
            inner: PublicKey::from_secret_key(&secp256k1::Secp256k1::signing_only(), &sk.inner),
        }
    }

    fn verify(&self, message: String, signature: PySignature) -> PyResult<bool> {
        let message_hash = sha256::Hash::hash(message.as_bytes());
        let message_hash = secp256k1::Message::from_slice(&message_hash);
        match message_hash {
            Ok(x) => match secp256k1::Secp256k1::new().verify(&x, &signature.inner, &self.inner) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            },
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
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
    pub inner: secp256k1::Signature,
}

#[pymethods]
impl PySignature {
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        match secp256k1::Signature::from_der(data) {
            Ok(x) => Ok(PySignature { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    #[staticmethod]
    fn from_compact(data: &[u8]) -> PyResult<Self> {
        match secp256k1::Signature::from_compact(data) {
            Ok(x) => Ok(PySignature { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    fn serialize_der(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.serialize_der()).into()
    }
    fn serialize_compact(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.serialize_compact()).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PySignature {
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.inner))
    }
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

    // Serialize prepends the length to the Script
    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner)).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyScript {
    // str prepends the length to the Script
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
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        if data.len() != 36 {
            return Err(exceptions::PyValueError::new_err(format!(
                "Outpoint data must be 36-bytes long"
            )));
        }

        match deserialize::<BitcoinOutPoint>(data) {
            Ok(x) => Ok(PyOutPoint::new(PyTxId { inner: x.txid }, x.vout as u16)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
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
    pub fn new(data: &[u8]) -> PyResult<Self> {
        match deserialize(data) {
            Ok(x) => Ok(PyTransaction { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!(
                "Cannot build transaction, {}",
                e
            ))),
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
