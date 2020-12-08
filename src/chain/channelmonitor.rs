use pyo3::create_exception;
use pyo3::prelude::*;

use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, MonitorEvent};
use lightning::chain::keysinterface::InMemoryChannelKeys;

#[pyclass(name=InMemoryKeysChannelMonitor)]
//#[derive(Clone)]
pub struct PyInMemoryKeysChannelMonitor {
    inner: ChannelMonitor<InMemoryChannelKeys>,
}

#[pyclass(name=ChannelMonitorUpdate)]
#[derive(Clone)]
pub struct PyChannelMonitorUpdate {
    inner: ChannelMonitorUpdate,
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
