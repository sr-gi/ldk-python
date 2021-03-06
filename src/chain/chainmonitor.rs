use pyo3::prelude::*;

use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::channelmonitor::{ChannelMonitorUpdateErr, Persist};
use lightning::chain::keysinterface::InMemoryChannelKeys;
use lightning::chain::Filter;
use lightning::chain::Watch;
use lightning::util::events::EventsProvider;
use lightning::util::logger::Logger;

use crate::chain::chaininterface::{PyBroadcasterInterface, PyFeeEstimator};
use crate::chain::channelmonitor::{
    match_monitor_event, PermanentChannelMonitorUpdateErr, PyChannelMonitorUpdate,
    PyInMemoryKeysChannelMonitor, PyMonitorEvent, PyPersist, TemporaryChannelMonitorUpdateErr,
};
use crate::chain::PyFilter;
use crate::logger::LDKLogger;
use crate::primitives::{PyBlockHeader, PyOutPoint, PyTransaction};
use crate::util::events::{match_event_type, PyEvent};

#[pyclass(unsendable, name=ChainMonitor)]
#[derive(Clone)]
pub struct PyChainMonitor {
    pub inner: *mut ChainMonitor<
        InMemoryChannelKeys,
        Box<dyn Filter>,
        Box<dyn BroadcasterInterface>,
        Box<dyn FeeEstimator>,
        Box<dyn Logger>,
        Box<dyn Persist<InMemoryChannelKeys>>,
    >,
}

#[pymethods]
impl PyChainMonitor {
    #[new]
    fn new(
        chain_source: Option<PyFilter>,
        broadcaster: PyBroadcasterInterface,
        logger: LDKLogger,
        feeest: PyFeeEstimator,
        persister: PyPersist,
    ) -> Self {
        PyChainMonitor {
            inner: Box::into_raw(Box::new(ChainMonitor::new(
                match chain_source {
                    Some(x) => Some(Box::new(x)),
                    None => None,
                },
                Box::new(broadcaster),
                Box::new(logger),
                Box::new(feeest),
                Box::new(persister),
            ))),
        }
    }

    fn block_connected(
        &self,
        header: PyBlockHeader,
        txdata: Vec<(usize, PyTransaction)>,
        height: u32,
    ) {
        //  Python txdata -> Native txdata
        let mut native_txdata: Vec<_> = vec![];
        for (i, tx) in txdata.iter() {
            native_txdata.push((*i, &tx.inner))
        }

        let cm = unsafe { self.inner.as_ref().unwrap() };
        cm.block_connected(&header.inner, &native_txdata, height)
    }

    fn block_disconnected(&self, header: PyBlockHeader, disconnected_height: u32) {
        let cm = unsafe { self.inner.as_ref().unwrap() };
        cm.block_disconnected(&header.inner, disconnected_height)
    }

    fn watch_channel(
        &self,
        funding_outpoint: PyOutPoint,
        monitor: PyInMemoryKeysChannelMonitor,
    ) -> PyResult<()> {
        let chain_monitor = unsafe { self.inner.as_ref().unwrap() };
        let channel_monitor = unsafe { Box::from_raw(monitor.inner) };
        match chain_monitor.watch_channel(funding_outpoint.inner, *channel_monitor) {
            Ok(_) => Ok(()),
            Err(e) => match e {
                ChannelMonitorUpdateErr::TemporaryFailure => {
                    Err(TemporaryChannelMonitorUpdateErr::new_err(""))
                }
                ChannelMonitorUpdateErr::PermanentFailure => {
                    Err(PermanentChannelMonitorUpdateErr::new_err(""))
                }
            },
        }
    }

    fn update_channel(
        &self,
        funding_txo: PyOutPoint,
        update: PyChannelMonitorUpdate,
    ) -> PyResult<()> {
        let cm = unsafe { self.inner.as_ref().unwrap() };
        match cm.update_channel(funding_txo.inner, update.inner) {
            Ok(_) => Ok(()),
            Err(e) => match e {
                ChannelMonitorUpdateErr::TemporaryFailure => {
                    Err(TemporaryChannelMonitorUpdateErr::new_err(""))
                }
                ChannelMonitorUpdateErr::PermanentFailure => {
                    Err(PermanentChannelMonitorUpdateErr::new_err(""))
                }
            },
        }
    }

    fn release_pending_monitor_events(&self) -> Vec<PyMonitorEvent> {
        let cm = unsafe { self.inner.as_ref().unwrap() };
        let mut py_monitor_events = Vec::new();
        for event in cm.release_pending_monitor_events().into_iter() {
            py_monitor_events.push(PyMonitorEvent {
                event_type: match_monitor_event(&event),
                inner: event,
            })
        }
        py_monitor_events
    }

    fn get_and_clear_pending_events(&self) -> Vec<PyEvent> {
        let cm = unsafe { self.inner.as_ref().unwrap() };
        let mut py_events: Vec<PyEvent> = vec![];
        for event in cm.get_and_clear_pending_events().into_iter() {
            py_events.push(PyEvent {
                event_type: match_event_type(&event),
                inner: event,
            })
        }
        py_events
    }
}
