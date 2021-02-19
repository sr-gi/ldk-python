use pyo3::create_exception;
use pyo3::exceptions;
use pyo3::prelude::*;

use crate::chain::channelmonitor::{
    PermanentChannelMonitorUpdateErr, PyChannelMonitorUpdate, PyInMemoryKeysChannelMonitor,
    PyMonitorEvent, TemporaryChannelMonitorUpdateErr,
};

use crate::has_trait_bound;
use crate::primitives::{PyBlockHash, PyOutPoint, PyScript, PyTxId, PyTxOut};
use crate::process_python_return;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::TxOut;
use bitcoin::hash_types::{BlockHash, Txid};
use lightning::chain;
use lightning::chain::channelmonitor::{
    ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr, MonitorEvent,
};
use lightning::chain::keysinterface::InMemoryChannelKeys;
use lightning::chain::transaction::OutPoint;
use lightning::chain::{Access, Filter, Watch};

pub mod chaininterface;
pub mod chainmonitor;
pub mod channelmonitor;
pub mod keysinterface;

pub fn match_access_error(e: chain::AccessError) -> PyErr {
    match e {
        chain::AccessError::UnknownChain => UnknownChain::new_err(""),
        chain::AccessError::UnknownTx => UnknownTx::new_err(""),
    }
}

pub fn process_python_monitor_return(result: PyResult<()>) -> Result<(), ChannelMonitorUpdateErr> {
    Python::with_gil(|py| match result {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.is_instance::<TemporaryChannelMonitorUpdateErr>(py) {
                Err(ChannelMonitorUpdateErr::TemporaryFailure)
            } else if e.is_instance::<PermanentChannelMonitorUpdateErr>(py) {
                Err(ChannelMonitorUpdateErr::PermanentFailure)
            } else {
                panic!("Unrecorgnized ChannelMonitorUpdateErr")
            }
        }
    })
}

create_exception!(chain, AccessError, pyo3::exceptions::PyException);
create_exception!(chain, UnknownChain, AccessError);
create_exception!(chain, UnknownTx, AccessError);

#[pyclass(name=Access)]
#[derive(Clone)]
pub struct PyAccess {
    inner: Py<PyAny>,
}

#[pymethods]
impl PyAccess {
    #[new]
    fn new(access: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(&access, vec!["get_utxo"]) {
            Ok(PyAccess { inner: access })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by Access"
            )))
        }
    }

    fn get_utxo(&self, genesis_hash: PyBlockHash, short_channel_id: u64) -> PyResult<PyTxOut> {
        Python::with_gil(|py| {
            let py_access = self.inner.as_ref(py);
            process_python_return(
                py_access.call_method1("get_utxo", (genesis_hash, short_channel_id)),
            )
        })
    }
}

impl Access for PyAccess {
    fn get_utxo(
        &self,
        genesis_hash: &BlockHash,
        short_channel_id: u64,
    ) -> Result<TxOut, chain::AccessError> {
        match self.get_utxo(
            PyBlockHash {
                inner: *genesis_hash,
            },
            short_channel_id,
        ) {
            Ok(x) => Ok(x.inner),
            Err(e) => Python::with_gil(|py| {
                if e.is_instance::<UnknownChain>(py) {
                    Err(chain::AccessError::UnknownChain)
                } else if e.is_instance::<UnknownTx>(py) {
                    Err(chain::AccessError::UnknownTx)
                } else {
                    panic! {"Unknown AccessError"}
                }
            }),
        }
    }
}

#[pyclass(name=Watch)]
#[derive(Clone)]
pub struct PyWatch {
    inner: Py<PyAny>,
}

#[pymethods]
impl PyWatch {
    #[new]
    fn new(watch: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(
            &watch,
            vec![
                "watch_channel",
                "update_channel",
                "release_pending_monitor_events",
            ],
        ) {
            Ok(PyWatch { inner: watch })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by Watch"
            )))
        }
    }

    fn watch_channel(
        &self,
        funding_txo: PyOutPoint,
        monitor: PyInMemoryKeysChannelMonitor,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_watch = self.inner.as_ref(py);
            match py_watch.call_method1("watch_channel", (funding_txo, monitor)) {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.is_instance::<TemporaryChannelMonitorUpdateErr>(py)
                        || e.is_instance::<PermanentChannelMonitorUpdateErr>(py)
                    {
                        Err(e)
                    } else {
                        Err(exceptions::PyValueError::new_err(format!(
                            "Unrecorgnized ChannelMonitorUpdateErr -> {}",
                            e
                        )))
                    }
                }
            }
        })
    }

    fn update_channel(
        &self,
        funding_txo: PyOutPoint,
        update: PyChannelMonitorUpdate,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_watch = self.inner.as_ref(py);
            match py_watch.call_method1("update_channel", (funding_txo, update)) {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.is_instance::<TemporaryChannelMonitorUpdateErr>(py)
                        || e.is_instance::<PermanentChannelMonitorUpdateErr>(py)
                    {
                        Err(e)
                    } else {
                        Err(exceptions::PyValueError::new_err(format!(
                            "Unrecorgnized ChannelMonitorUpdateErr -> {}",
                            e
                        )))
                    }
                }
            }
        })
    }

    fn release_pending_monitor_events(&self) -> PyResult<Vec<PyMonitorEvent>> {
        Python::with_gil(|py| {
            let py_watch = self.inner.as_ref(py);
            let r: PyResult<Vec<PyMonitorEvent>> =
                process_python_return(py_watch.call_method0("release_pending_monitor_events"));
            r
        })
    }
}

impl Watch for PyWatch {
    type Keys = InMemoryChannelKeys;

    fn watch_channel(
        &self,
        funding_txo: OutPoint,
        monitor: ChannelMonitor<Self::Keys>,
    ) -> Result<(), ChannelMonitorUpdateErr> {
        let mut mut_monitor = monitor;
        process_python_monitor_return(self.watch_channel(
            PyOutPoint { inner: funding_txo },
            PyInMemoryKeysChannelMonitor {
                inner: &mut mut_monitor,
            },
        ))
    }

    fn update_channel(
        &self,
        funding_txo: OutPoint,
        update: ChannelMonitorUpdate,
    ) -> Result<(), ChannelMonitorUpdateErr> {
        process_python_monitor_return(self.update_channel(
            PyOutPoint { inner: funding_txo },
            PyChannelMonitorUpdate { inner: update },
        ))
    }

    fn release_pending_monitor_events(&self) -> Vec<MonitorEvent> {
        let mut monitor_events = Vec::new();
        for py_data in self.release_pending_monitor_events().unwrap().into_iter() {
            monitor_events.push(py_data.inner)
        }
        monitor_events
    }
}

#[pyclass(name=Filter)]
#[derive(Clone)]
pub struct PyFilter {
    inner: Py<PyAny>,
}

#[pymethods]
impl PyFilter {
    #[new]
    fn new(filter: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(&filter, vec!["register_tx", "register_output"]) {
            Ok(PyFilter { inner: filter })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by Filter"
            )))
        }
    }

    fn register_tx(&self, txid: PyTxId, script_pubkey: PyScript) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_filter = self.inner.as_ref(py);
            match py_filter.call_method1("register_tx", (txid, script_pubkey)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn register_output(&self, outpoint: PyOutPoint, script_pubkey: PyScript) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_filter = self.inner.as_ref(py);
            match py_filter.call_method1("register_output", (outpoint, script_pubkey)) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }
}

impl Filter for PyFilter {
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        self.register_tx(
            PyTxId { inner: *txid },
            PyScript {
                inner: script_pubkey.clone(),
            },
        )
        .unwrap();
    }

    fn register_output(&self, outpoint: &OutPoint, script_pubkey: &Script) {
        self.register_output(
            PyOutPoint { inner: *outpoint },
            PyScript {
                inner: script_pubkey.clone(),
            },
        )
        .unwrap();
    }
}
