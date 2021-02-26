use std::str;

use pyo3::class::basic::CompareOp;
use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyObjectProtocol;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::OutPoint as BitcoinOutPoint;
use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
use bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
use bitcoin::hash_types::{BlockHash, Txid};
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
    fn __str__(&self) -> String {
        format!("{:#x}", self.inner)
    }

    fn __richcmp__(&self, other: PySecretKey, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
    }
}

#[pyclass(name=PublicKey)]
#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
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
    fn __str__(&self) -> String {
        format!("{:#x}", self.inner)
    }

    fn __richcmp__(&self, other: PyPublicKey, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
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
    fn __str__(&self) -> String {
        format!("{}", self.inner)
    }

    fn __richcmp__(&self, other: PySignature, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
    }
}

#[pyclass(name=BlockHeader)]
#[derive(Clone)]
pub struct PyBlockHeader {
    pub inner: BlockHeader,
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
    fn get_version(&self) -> i32 {
        self.inner.version
    }

    #[getter]
    fn get_prev_blockhash(&self) -> String {
        self.inner.prev_blockhash.to_string()
    }

    #[getter]
    fn get_merkle_root(&self) -> String {
        self.inner.merkle_root.to_string()
    }

    #[getter]
    fn get_time(&self) -> u32 {
        self.inner.time
    }

    #[getter]
    fn get_bits(&self) -> u32 {
        self.inner.bits
    }

    #[getter]
    fn get_nonce(&self) -> u32 {
        self.inner.nonce
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner)).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyBlockHeader {
    fn __str__(&self) -> String {
        serialize_hex(&self.inner)
    }

    fn __richcmp__(&self, other: PyBlockHeader, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
    }
}

#[pyclass(name=BlockHash)]
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PyBlockHash {
    pub inner: BlockHash,
}

#[pymethods]
impl PyBlockHash {
    #[new]
    pub fn new(data: [u8; 32]) -> Self {
        PyBlockHash {
            inner: deserialize(&data).unwrap(),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner)).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyBlockHash {
    fn __str__(&self) -> String {
        serialize_hex(&self.inner)
    }

    fn __richcmp__(&self, other: PyBlockHash, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
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
    fn __str__(&self) -> String {
        serialize_hex(&self.inner)
    }

    fn __richcmp__(&self, other: PyScript, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
    }
}

#[pyclass(name=TxId)]
#[derive(Clone, Eq, PartialEq, Hash)]
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
    fn __str__(&self) -> String {
        serialize_hex(&self.inner)
    }

    fn __richcmp__(&self, other: PyTxId, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
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
        if data.len() != 34 {
            return Err(exceptions::PyValueError::new_err(format!(
                "Outpoint data must be 34-bytes long"
            )));
        }

        // We'll use the Bitcoin create to deserialize, so outpoints are expected
        // to be u32 instead of u16.
        let mut filled_data = data.to_vec();
        filled_data.extend([0, 0].iter());

        match deserialize::<BitcoinOutPoint>(&filled_data) {
            Ok(x) => Ok(PyOutPoint::new(PyTxId { inner: x.txid }, x.vout as u16)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    #[getter]
    fn get_txid(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner.txid)).into()
    }

    #[getter]
    fn get_index(&self) -> u16 {
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
    fn __str__(&self) -> String {
        serialize_hex(&self.inner.into_bitcoin_outpoint())
    }

    fn __richcmp__(&self, other: PyOutPoint, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
    }
}

#[pyclass(name=TxIn)]
#[derive(Clone)]
pub struct PyTxIn {
    pub inner: TxIn,
}

#[pymethods]
impl PyTxIn {
    #[new]
    fn new(
        previous_output: PyOutPoint,
        script_sig: PyScript,
        sequence: u32,
        witness: Vec<Vec<u8>>,
    ) -> Self {
        PyTxIn {
            inner: TxIn {
                previous_output: previous_output.inner.into_bitcoin_outpoint(),
                script_sig: script_sig.inner,
                sequence,
                witness,
            },
        }
    }

    #[staticmethod]
    /// Note that the witness field is *not* deserialized with the rest of the TxIn. Data must be provided without witness.
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        match deserialize::<TxIn>(data) {
            Ok(x) => Ok(PyTxIn { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    #[getter]
    fn get_previous_output(&self) -> PyOutPoint {
        PyOutPoint {
            inner: OutPoint {
                txid: self.inner.previous_output.txid,
                index: self.inner.previous_output.vout as u16,
            },
        }
    }

    #[getter]
    fn get_script_sig(&self) -> PyScript {
        PyScript {
            inner: self.inner.script_sig.clone(),
        }
    }

    #[getter]
    fn get_sequence(&self) -> u32 {
        self.inner.sequence
    }

    #[getter]
    fn get_witness(&self, py: Python) -> Vec<Py<PyBytes>> {
        let mut w = vec![];
        for witness in self.inner.witness.iter() {
            w.push(PyBytes::new(py, &witness).into())
        }
        w
    }

    /// Note that the witness field is *not* serialized with the rest of the TxIn.
    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner)).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyTxIn {
    fn __str__(&self) -> String {
        serialize_hex(&self.inner)
    }

    fn __richcmp__(&self, other: PyTxIn, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
    }
}

#[pyclass(name=TxOut)]
#[derive(Clone)]
pub struct PyTxOut {
    pub inner: TxOut,
}

#[pymethods]
impl PyTxOut {
    #[new]
    fn new(value: u64, script_pubkey: PyScript) -> Self {
        PyTxOut {
            inner: TxOut {
                value,
                script_pubkey: script_pubkey.inner,
            },
        }
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        match deserialize::<TxOut>(data) {
            Ok(x) => Ok(PyTxOut { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    #[getter]
    fn get_value(&self) -> u64 {
        self.inner.value
    }

    #[getter]
    fn get_script_pubkey(&self) -> PyScript {
        PyScript {
            inner: self.inner.script_pubkey.clone(),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner)).into()
    }
}

#[pyproto]
impl PyObjectProtocol for PyTxOut {
    fn __str__(&self) -> String {
        serialize_hex(&self.inner)
    }

    fn __richcmp__(&self, other: PyTxOut, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
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
    fn new(version: i32, lock_time: u32, input: Vec<PyTxIn>, output: Vec<PyTxOut>) -> Self {
        let mut ins = vec![];
        for i in input.iter() {
            ins.push(i.inner.clone())
        }

        let mut outs = vec![];
        for o in output.iter() {
            outs.push(o.inner.clone())
        }

        PyTransaction {
            inner: Transaction {
                version,
                lock_time,
                input: ins,
                output: outs,
            },
        }
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        match deserialize(data) {
            Ok(x) => Ok(PyTransaction { inner: x }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!(
                "Cannot build transaction, {}",
                e
            ))),
        }
    }

    #[getter]
    fn get_version(&self) -> i32 {
        self.inner.version
    }

    #[getter]
    fn get_lock_time(&self) -> u32 {
        self.inner.lock_time
    }

    #[getter]
    fn get_input(&self) -> Vec<PyTxIn> {
        let mut ins = vec![];
        for i in self.inner.input.iter() {
            ins.push(PyTxIn { inner: i.clone() })
        }
        ins
    }

    #[getter]
    fn get_output(&self) -> Vec<PyTxOut> {
        let mut outs = vec![];
        for o in self.inner.output.iter() {
            outs.push(PyTxOut { inner: o.clone() })
        }
        outs
    }

    fn txid(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner.txid())).into()
    }

    fn nxid(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner.ntxid())).into()
    }

    fn wxid(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner.wtxid())).into()
    }

    fn get_size(&self) -> usize {
        self.inner.get_size()
    }

    fn get_weight(&self) -> usize {
        self.inner.get_weight()
    }

    fn is_coinbase(&self) -> bool {
        self.inner.is_coin_base()
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &serialize(&self.inner)).into()
    }

    // FIXME: Missing methods: signature_hash, verify,
}

#[pyproto]
impl PyObjectProtocol for PyTransaction {
    fn __str__(&self) -> String {
        serialize_hex(&self.inner)
    }

    fn __richcmp__(&self, other: PyTransaction, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
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

    fn __richcmp__(&self, other: PyNetwork, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.inner == other.inner),
            CompareOp::Ne => Ok(self.inner != other.inner),
            _ => Ok(false),
        }
    }
}
