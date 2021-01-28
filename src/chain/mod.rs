use pyo3::exceptions;
use pyo3::prelude::*;

use crate::chain::channelmonitor::{
    PermanentChannelMonitorUpdateErr, PyChannelMonitorUpdate, PyInMemoryKeysChannelMonitor,
    PyMonitorEvent, TemporaryChannelMonitorUpdateErr,
};

use crate::has_trait_bound;
use crate::primitives::PyOutPoint;
use crate::process_python_return;

use lightning::chain::channelmonitor::{
    ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr, MonitorEvent,
};
use lightning::chain::keysinterface::InMemoryChannelKeys;
use lightning::chain::transaction::OutPoint;
use lightning::chain::Watch;

pub mod chaininterface;
pub mod channelmonitor;
pub mod keysinterface;

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
