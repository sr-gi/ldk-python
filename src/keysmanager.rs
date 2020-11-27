use pyo3::exceptions;
use pyo3::prelude::*;

use bitcoin::network::constants::Network;

use lightning::chain::keysinterface::KeysManager;

#[pyclass(name=KeysManager)]
pub struct PyKeysManager {
    inner: KeysManager,
}

#[pymethods]
impl PyKeysManager {
    #[new]
    fn new(
        seed: &[u8],
        network: &str,
        starting_time_secs: u64,
        starting_time_nanos: u32,
    ) -> PyResult<Self> {
        let net = match network {
            "bitcoin" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(exceptions::PyValueError::new_err(format!(
                "Unrecognized network: {}",
                network
            ))),
        };

        if seed.len() != 32 {
            return Err(exceptions::PyValueError::new_err(format!(
                "Expected 32-byte seed, received a {}-byte one",
                seed.len()
            )));
        }

        let mut s: [u8; 32] = Default::default();
        s.copy_from_slice(&seed[0..32]);

        match net {
            Ok(x) => Ok(PyKeysManager {
                inner: KeysManager::new(&s, x, starting_time_secs, starting_time_nanos),
            }),
            Err(e) => Err(e),
        }
    }
}

#[pymodule]
/// Keys manager module for LDK.
fn keysmanager(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyKeysManager>()?;
    Ok(())
}
