use std::collections::HashMap;
use std::ops::Deref;

use pyo3::create_exception;
use pyo3::exceptions;
use pyo3::prelude::*;

use crate::chain::chaininterface::{PyBroadcasterInterface, PyFeeEstimator};
use crate::chain::keysinterface::PyInMemoryChannelKeys;
use crate::chain::process_python_monitor_return;
use crate::has_trait_bound;
use crate::ln::chan_utils::PyHolderCommitmentTransaction;
use crate::logger::LDKLogger;
use crate::primitives::{
    PyBlockHeader, PyOutPoint, PyPublicKey, PyScript, PyTransaction, PyTxId, PyTxOut,
};
use crate::util::events::{match_event_type, PyEvent};

use bitcoin::blockdata::script::Script;
use lightning::chain::channelmonitor::{
    ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr, MonitorEvent, Persist,
};
use lightning::chain::keysinterface::InMemoryChannelKeys;
use lightning::chain::transaction::OutPoint;

#[pyclass(unsendable, name=InMemoryKeysChannelMonitor)]
#[derive(Clone)]
pub struct PyInMemoryKeysChannelMonitor {
    pub inner: *mut ChannelMonitor<InMemoryChannelKeys>,
}

impl Deref for PyInMemoryKeysChannelMonitor {
    type Target = ChannelMonitor<InMemoryChannelKeys>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner }
    }
}

#[pymethods]
impl PyInMemoryKeysChannelMonitor {
    #[new]
    fn new(
        keys: PyInMemoryChannelKeys,
        shutdown_pubkey: PyPublicKey,
        on_counterparty_tx_csv: u16,
        destination_script: PyScript,
        funding_info: (PyOutPoint, PyScript),
        counterparty_htlc_base_key: PyPublicKey,
        counterparty_delayed_payment_base_key: PyPublicKey,
        on_holder_tx_csv: u16,
        funding_redeemscript: PyScript,
        channel_value_satoshis: u64,
        commitment_transaction_number_obscure_factor: u64,
        initial_holder_commitment_tx: PyHolderCommitmentTransaction,
    ) -> Self {
        let mut cm = ChannelMonitor::new(
            keys.inner,
            &shutdown_pubkey.inner,
            on_counterparty_tx_csv,
            &destination_script.inner,
            (funding_info.0.inner, funding_info.1.inner),
            &counterparty_htlc_base_key.inner,
            &counterparty_delayed_payment_base_key.inner,
            on_holder_tx_csv,
            funding_redeemscript.inner,
            channel_value_satoshis,
            commitment_transaction_number_obscure_factor,
            initial_holder_commitment_tx.inner,
        );
        PyInMemoryKeysChannelMonitor { inner: &mut cm }
    }
}

#[pymethods]
impl PyInMemoryKeysChannelMonitor {
    // FIXME: serialize_for_disk is missing, but looks like that method won't be longer available in 0.0.13. Double check and implement otherwise.

    fn update_monitor(
        &mut self,
        updates: PyChannelMonitorUpdate,
        broadcaster: PyBroadcasterInterface,
        fee_estimator: PyFeeEstimator,
        logger: LDKLogger,
    ) -> PyResult<()> {
        let cm = unsafe { self.inner.as_mut().unwrap() };

        match cm.update_monitor(
            &updates.inner,
            &Box::new(broadcaster),
            &Box::new(fee_estimator),
            &Box::new(logger),
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MonitorUpdateErr::new_err(e.0)),
        }
    }

    fn get_latest_update_id(&self) -> u64 {
        unsafe { self.inner.as_ref().unwrap().get_latest_update_id() }
    }

    fn get_dummy_funding_txo(&self) -> (PyOutPoint, PyScript) {
        let cm = unsafe { self.inner.as_ref().unwrap() };
        let (outpoint, script) = cm.get_funding_txo();
        (
            PyOutPoint { inner: *outpoint },
            PyScript {
                inner: Script::new(),
            },
        )
    }

    fn get_funding_txo(&self) -> (PyOutPoint, PyScript) {
        let cm = unsafe { self.inner.as_ref().unwrap() };
        let (outpoint, script) = cm.get_funding_txo();
        (
            PyOutPoint { inner: *outpoint },
            PyScript {
                inner: script.clone(),
            },
        )
    }

    fn get_outputs_to_watch(&self) -> HashMap<PyTxId, Vec<(u32, PyScript)>> {
        let cm = unsafe { self.inner.as_ref().unwrap() };
        let mut outputs: HashMap<PyTxId, Vec<(u32, PyScript)>> = HashMap::new();

        for (txid, txouts) in cm.get_outputs_to_watch().into_iter() {
            let mut wrapped_txouts = vec![];
            for (value, script) in txouts.into_iter() {
                wrapped_txouts.push((
                    *value,
                    PyScript {
                        inner: script.clone(),
                    },
                ))
            }
            outputs.insert(PyTxId { inner: *txid }, wrapped_txouts);
        }

        outputs
    }

    fn get_and_clear_pending_monitor_events(&mut self) -> Vec<PyMonitorEvent> {
        let cm = unsafe { self.inner.as_mut().unwrap() };
        let mut monitor_events: Vec<PyMonitorEvent> = vec![];
        for event in cm.get_and_clear_pending_monitor_events().into_iter() {
            monitor_events.push(PyMonitorEvent { inner: event })
        }

        monitor_events
    }

    fn get_and_clear_pending_events(&mut self) -> Vec<PyEvent> {
        let cm = unsafe { self.inner.as_mut().unwrap() };
        let mut events: Vec<PyEvent> = vec![];
        for event in cm.get_and_clear_pending_events().iter() {
            events.push(PyEvent {
                inner: event.clone(),
                event_type: match_event_type(event),
            })
        }

        events
    }

    fn get_latest_holder_commitment_txn(&mut self, logger: LDKLogger) -> Vec<PyTransaction> {
        let cm = unsafe { self.inner.as_mut().unwrap() };
        let mut txs: Vec<PyTransaction> = vec![];
        for tx in cm
            .get_latest_holder_commitment_txn(&Box::new(logger))
            .into_iter()
        {
            txs.push(PyTransaction { inner: tx })
        }

        txs
    }

    fn block_connected(
        &mut self,
        header: PyBlockHeader,
        txdata: Vec<(usize, PyTransaction)>,
        height: u32,
        broadcaster: PyBroadcasterInterface,
        fee_estimator: PyFeeEstimator,
        logger: LDKLogger,
    ) -> Vec<(PyTxId, Vec<(u32, PyTxOut)>)> {
        let cm = unsafe { self.inner.as_mut().unwrap() };
        // Foreign txdata -> Native txdata
        let mut native_txdata: Vec<_> = vec![];
        for (i, tx) in txdata.iter() {
            native_txdata.push((*i, &tx.inner))
        }

        // Get native result
        let outs_to_watch = cm.block_connected(
            &header.inner,
            &native_txdata,
            height,
            Box::new(broadcaster),
            Box::new(fee_estimator),
            Box::new(logger),
        );

        // Native result -> Python result
        let mut wrapped_outs_to_watch: Vec<(PyTxId, Vec<(u32, PyTxOut)>)> = vec![];
        for (txid, outputs) in outs_to_watch.into_iter() {
            let mut wrapped_outputs: Vec<(u32, PyTxOut)> = vec![];
            for (index, txout) in outputs {
                wrapped_outputs.push((index, PyTxOut { inner: txout }))
            }
            wrapped_outs_to_watch.push((PyTxId { inner: txid }, wrapped_outputs))
        }

        wrapped_outs_to_watch
    }

    fn block_disconnected(
        &mut self,
        header: PyBlockHeader,
        height: u32,
        broadcaster: PyBroadcasterInterface,
        fee_estimator: PyFeeEstimator,
        logger: LDKLogger,
    ) {
        let cm = unsafe { self.inner.as_mut().unwrap() };
        cm.block_disconnected(
            &header.inner,
            height,
            Box::new(broadcaster),
            Box::new(fee_estimator),
            Box::new(logger),
        )
    }
}

create_exception!(
    channelmonitor,
    MonitorUpdateErr,
    pyo3::exceptions::PyException
);

#[pyclass(name=ChannelMonitorUpdate)]
#[derive(Clone)]
pub struct PyChannelMonitorUpdate {
    pub inner: ChannelMonitorUpdate,
}

create_exception!(
    channelmonitor,
    TemporaryChannelMonitorUpdateErr,
    pyo3::exceptions::PyException
);

create_exception!(
    channelmonitor,
    PermanentChannelMonitorUpdateErr,
    pyo3::exceptions::PyException
);

#[pyclass(name=MonitorEvent)]
#[derive(Clone)]
pub struct PyMonitorEvent {
    pub inner: MonitorEvent,
}

#[pyclass(name=Persist)]
pub struct PyPersist {
    pub inner: Py<PyAny>,
}

#[pymethods]
impl PyPersist {
    #[new]
    fn new(persister: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(
            &persister,
            vec!["update_persisted_channel", "persist_new_channel"],
        ) {
            Ok(PyPersist { inner: persister })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by Persist"
            )))
        }
    }

    fn persist_new_channel(
        &self,
        id: PyOutPoint,
        data: PyInMemoryKeysChannelMonitor,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_persister = self.inner.as_ref(py);
            match py_persister.call_method1("persist_new_channel", (id, data)) {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.is_instance::<TemporaryChannelMonitorUpdateErr>(py)
                        || e.is_instance::<PermanentChannelMonitorUpdateErr>(py)
                    {
                        Err(e)
                    } else {
                        Err(exceptions::PyValueError::new_err(
                            "Unrecorgnized ChannelMonitorUpdateErr",
                        ))
                    }
                }
            }
        })
    }

    fn update_persisted_channel(
        &self,
        id: PyOutPoint,
        update: PyChannelMonitorUpdate,
        data: PyInMemoryKeysChannelMonitor,
    ) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_persister = self.inner.as_ref(py);
            match py_persister.call_method1("update_persisted_channel", (id, update, data)) {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.is_instance::<TemporaryChannelMonitorUpdateErr>(py)
                        || e.is_instance::<PermanentChannelMonitorUpdateErr>(py)
                    {
                        Err(e)
                    } else {
                        Err(exceptions::PyValueError::new_err(
                            "Unrecorgnized ChannelMonitorUpdateErr",
                        ))
                    }
                }
            }
        })
    }
}

impl Persist<InMemoryChannelKeys> for PyPersist {
    fn persist_new_channel(
        &self,
        id: OutPoint,
        data: &ChannelMonitor<InMemoryChannelKeys>,
    ) -> Result<(), ChannelMonitorUpdateErr> {
        process_python_monitor_return(self.persist_new_channel(
            PyOutPoint { inner: id },
            PyInMemoryKeysChannelMonitor {
                inner: (data as *const _) as *mut _,
            },
        ))
    }
    fn update_persisted_channel(
        &self,
        id: OutPoint,
        update: &ChannelMonitorUpdate,
        data: &ChannelMonitor<InMemoryChannelKeys>,
    ) -> Result<(), ChannelMonitorUpdateErr> {
        process_python_monitor_return(self.update_persisted_channel(
            PyOutPoint { inner: id },
            PyChannelMonitorUpdate {
                inner: update.clone(),
            },
            PyInMemoryKeysChannelMonitor {
                inner: (data as *const _) as *mut _,
            },
        ))
    }
}
