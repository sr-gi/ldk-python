use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::wrap_pymodule;

pub mod chain;
pub mod ln;
pub mod logger;
pub mod primitives;

pub fn process_python_return<'a, T: FromPyObject<'a>>(
    pyresult: PyResult<&'a PyAny>,
) -> Result<T, PyErr> {
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
    m.add_class::<primitives::PyTransaction>()?;
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
/// Chain interface interface module for LDK
fn chaininterface(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<chain::chaininterface::PyFeeEstimator>()?;
    m.add_class::<chain::chaininterface::PyBroadcasterInterface>()?;
    Ok(())
}

#[pymodule]
/// Keys manager module for LDK
fn keysinterface(_: Python, m: &PyModule) -> PyResult<()> {
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
fn channelmanager(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ln::channelmanager::PyPaymentHash>()?;
    Ok(())
}

/// LDK bindings for Python
#[pymodule]
fn ldk_python(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(primitives))?;
    m.add_wrapped(wrap_pymodule!(logger))?;
    m.add_wrapped(wrap_pymodule!(chaininterface))?;
    m.add_wrapped(wrap_pymodule!(keysinterface))?;
    m.add_wrapped(wrap_pymodule!(chan_utils))?;
    m.add_wrapped(wrap_pymodule!(channelmanager))?;
    Ok(())
}
