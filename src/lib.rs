use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::wrap_pymodule;

pub mod chain;
pub mod ln;
pub mod logger;
pub mod primitives;
pub mod routing;
pub mod util;

pub fn has_trait_bound(class: &Py<PyAny>, methods: Vec<&str>) -> bool {
    let mut results = vec![];
    Python::with_gil(|py| {
        for method in methods.into_iter() {
            let is_callable = match class.as_ref(py).getattr(method) {
                Ok(x) => x.is_callable(),
                Err(_) => false,
            };
            results.push(is_callable);
        }
    });
    results.iter().all(|&x| x == true)
}

pub fn process_python_return<'a, T: FromPyObject<'a>>(
    pyresult: PyResult<&'a PyAny>,
) -> PyResult<T> {
    match pyresult {
        Ok(x) => {
            let inner: Option<T> = x.extract()?;
            match inner {
                Some(x) => Ok(x),
                None => Err(exceptions::PyTypeError::new_err(format!(
                    "Expected a return of type {} from the Python binded method, recieved {}",
                    std::any::type_name::<T>(),
                    x
                ))),
            }
        }
        Err(e) => Err(e),
    }
}

#[pymodule]
/// Primitives module for LDK
fn primitives(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<primitives::PySecretKey>()?;
    m.add_class::<primitives::PyPublicKey>()?;
    m.add_class::<primitives::PySignature>()?;
    m.add_class::<primitives::PyBlockHeader>()?;
    m.add_class::<primitives::PyScript>()?;
    m.add_class::<primitives::PyTxId>()?;
    m.add_class::<primitives::PyOutPoint>()?;
    m.add_class::<primitives::PyTxIn>()?;
    m.add_class::<primitives::PyTxOut>()?;
    m.add_class::<primitives::PyTransaction>()?;
    m.add_class::<primitives::PyNetwork>()?;
    Ok(())
}

#[pymodule]
/// Loggin module for LDK
pub fn logger(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<logger::LDKLogger>()?;
    Ok(())
}

// CHAIN

#[pymodule]
/// Chain module for LDK
fn chain(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<chain::PyWatch>()?;
    m.add_class::<chain::PyFilter>()?;
    Ok(())
}

#[pymodule]
/// Chain interface module for LDK
fn chaininterface(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<chain::chaininterface::PyFeeEstimator>()?;
    m.add_class::<chain::chaininterface::PyBroadcasterInterface>()?;
    Ok(())
}

#[pymodule]
/// Chain monitor module for LDK
fn chainmonitor(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<chain::chainmonitor::PyChainMonitor>()?;
    Ok(())
}

#[pymodule]
/// Channel monitor module for LDK.
fn channelmonitor(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<chain::channelmonitor::PyInMemoryKeysChannelMonitor>()?;
    m.add_class::<chain::channelmonitor::PyChannelMonitorUpdate>()?;
    m.add(
        "MonitorUpdateErr",
        py.get_type::<chain::channelmonitor::MonitorUpdateErr>(),
    )?;
    m.add(
        "TemporaryChannelMonitorUpdateErr",
        py.get_type::<chain::channelmonitor::TemporaryChannelMonitorUpdateErr>(),
    )?;
    m.add(
        "PermanentChannelMonitorUpdateErr",
        py.get_type::<chain::channelmonitor::PermanentChannelMonitorUpdateErr>(),
    )?;
    m.add_class::<chain::channelmonitor::PyMonitorEvent>()?;
    m.add_class::<chain::channelmonitor::PyHTLCUpdate>()?;
    m.add_class::<chain::channelmonitor::PyPersist>()?;
    Ok(())
}

#[pymodule]
/// Keys manager module for LDK
fn keysinterface(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<chain::keysinterface::PySpendableOutputDescriptor>()?;
    m.add_class::<chain::keysinterface::PyKeysManager>()?;
    m.add_class::<chain::keysinterface::PyInMemoryChannelKeys>()?;
    Ok(())
}

// LN

#[pymodule]
/// Channel utils module for LDK.
fn chan_utils(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ln::chan_utils::PyChannelPublicKeys>()?;
    m.add_class::<ln::chan_utils::PyTxCreationKeys>()?;
    m.add_class::<ln::chan_utils::PyHTLCOutputInCommitment>()?;
    m.add_class::<ln::chan_utils::PyHolderCommitmentTransaction>()?;
    Ok(())
}

#[pymodule]
/// Channel manager module for LDK.
fn channelmanager(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ln::channelmanager::PyPaymentPreimage>()?;
    m.add_class::<ln::channelmanager::PyPaymentSecret>()?;
    m.add_class::<ln::channelmanager::PyPaymentHash>()?;
    m.add_class::<ln::channelmanager::PyChannelDetails>()?;
    m.add_class::<ln::channelmanager::PyChannelManager>()?;
    m.add(
        "PaymentSendFailure",
        py.get_type::<ln::channelmanager::PaymentSendFailure>(),
    )?;
    m.add(
        "ParameterError",
        py.get_type::<ln::channelmanager::ParameterError>(),
    )?;
    m.add(
        "PathParameterError",
        py.get_type::<ln::channelmanager::PathParameterError>(),
    )?;
    m.add(
        "AllFailedRetrySafe",
        py.get_type::<ln::channelmanager::AllFailedRetrySafe>(),
    )?;
    m.add(
        "PartialFailure",
        py.get_type::<ln::channelmanager::PartialFailure>(),
    )?;
    Ok(())
}

#[pymodule]
/// Features module for LDK.
fn features(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ln::features::PyInitFeatures>()?;
    m.add_class::<ln::features::PyChannelFeatures>()?;
    m.add_class::<ln::features::PyNodeFeatures>()?;
    Ok(())
}

#[pymodule]
/// Messages module for LDK.
fn msgs(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ln::msgs::PyNetAddress>()?;
    Ok(())
}

// Routing

#[pymodule]
/// Router module for LDK.
fn router(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<routing::router::PyRouteHop>()?;
    m.add_class::<routing::router::PyRoute>()?;
    Ok(())
}

// Util

#[pymodule]
/// Configuration module for LDK.
fn config(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<util::config::PyChannelHandshakeConfig>()?;
    m.add_class::<util::config::PyChannelHandshakeLimits>()?;
    m.add_class::<util::config::PyChannelConfig>()?;
    m.add_class::<util::config::PyUserConfig>()?;
    Ok(())
}

#[pymodule]
/// Errors module for LDK.
fn errors(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("APIError", py.get_type::<util::errors::APIError>())?;
    m.add(
        "APIMisuseError",
        py.get_type::<util::errors::APIMisuseError>(),
    )?;
    m.add(
        "FeeRateTooHigh",
        py.get_type::<util::errors::FeeRateTooHigh>(),
    )?;
    m.add("RouteError", py.get_type::<util::errors::RouteError>())?;
    m.add(
        "ChannelUnavailable",
        py.get_type::<util::errors::ChannelUnavailable>(),
    )?;
    m.add(
        "MonitorUpdateFailed",
        py.get_type::<util::errors::MonitorUpdateFailed>(),
    )?;
    Ok(())
}

#[pymodule]
/// Events module for LDK.
fn events(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<util::events::PyEvent>()?;
    Ok(())
}

/// LDK bindings for Python
#[pymodule]
fn ldk_python(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(primitives))?;
    m.add_wrapped(wrap_pymodule!(logger))?;
    m.add_wrapped(wrap_pymodule!(chain))?;
    m.add_wrapped(wrap_pymodule!(chaininterface))?;
    m.add_wrapped(wrap_pymodule!(chainmonitor))?;
    m.add_wrapped(wrap_pymodule!(channelmonitor))?;
    m.add_wrapped(wrap_pymodule!(keysinterface))?;
    m.add_wrapped(wrap_pymodule!(chan_utils))?;
    m.add_wrapped(wrap_pymodule!(channelmanager))?;
    m.add_wrapped(wrap_pymodule!(features))?;
    m.add_wrapped(wrap_pymodule!(msgs))?;
    m.add_wrapped(wrap_pymodule!(router))?;
    m.add_wrapped(wrap_pymodule!(config))?;
    m.add_wrapped(wrap_pymodule!(errors))?;
    m.add_wrapped(wrap_pymodule!(events))?;
    Ok(())
}
