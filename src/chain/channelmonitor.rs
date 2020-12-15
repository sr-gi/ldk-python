use std::ops::Deref;

use pyo3::create_exception;
use pyo3::prelude::*;

use crate::chain::chaininterface::{PyBroadcasterInterface, PyFeeEstimator};
use crate::logger::LDKLogger;

use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, MonitorEvent};
use lightning::chain::keysinterface::InMemoryChannelKeys;

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
    fn update_monitor(
        &mut self,
        updates: PyChannelMonitorUpdate,
        broadcaster: PyBroadcasterInterface,
        fee_estimator: PyFeeEstimator,
        logger: LDKLogger,
    ) -> PyResult<()> {
        unsafe {
            match self.inner.as_mut().unwrap().update_monitor(
                &updates.inner,
                &Box::new(broadcaster),
                &Box::new(fee_estimator),
                &Box::new(logger),
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(MonitorUpdateErr::new_err(e.0)),
            }
        }
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
