use pyo3::prelude::*;

use crate::ln::features::{PyChannelFeatures, PyNodeFeatures};
use crate::primitives::PyPublicKey;

use lightning::routing::router::{Route, RouteHop};

#[pyclass(name=RouteHop)]
#[derive(Clone)]
pub struct PyRouteHop {
    pub inner: RouteHop,
}

#[pymethods]
impl PyRouteHop {
    #[new]
    pub fn new(
        pubkey: PyPublicKey,
        node_features: PyNodeFeatures,
        short_channel_id: u64,
        channel_features: PyChannelFeatures,
        fee_msat: u64,
        cltv_expiry_delta: u32,
    ) -> Self {
        PyRouteHop {
            inner: RouteHop {
                pubkey: pubkey.inner,
                node_features: node_features.inner,
                short_channel_id,
                channel_features: channel_features.inner,
                fee_msat,
                cltv_expiry_delta,
            },
        }
    }

    #[getter]
    fn get_pubkey(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.pubkey,
        }
    }

    #[getter]
    fn get_node_features(&self) -> PyNodeFeatures {
        PyNodeFeatures {
            inner: self.inner.node_features.clone(),
        }
    }

    #[getter]
    fn get_short_channel_id(&self) -> u64 {
        self.inner.short_channel_id
    }

    #[getter]
    fn get_channel_features(&self) -> PyChannelFeatures {
        PyChannelFeatures {
            inner: self.inner.channel_features.clone(),
        }
    }

    #[getter]
    fn get_fee_msat(&self) -> u64 {
        self.inner.fee_msat
    }

    #[getter]
    fn get_cltv_expiry_delta(&self) -> u32 {
        self.inner.cltv_expiry_delta
    }
}

#[pyclass(name=Route)]
#[derive(Clone)]
pub struct PyRoute {
    pub inner: Route,
}

#[pymethods]
impl PyRoute {
    #[new]
    pub fn new(paths: Vec<Vec<PyRouteHop>>) -> Self {
        let mut native_paths = vec![];
        for path in paths.into_iter() {
            let mut native_route = vec![];
            for hop in path.into_iter() {
                native_route.push(hop.inner)
            }
            native_paths.push(native_route)
        }
        PyRoute {
            inner: Route {
                paths: native_paths,
            },
        }
    }

    #[getter]
    fn get_paths(&self) -> Vec<Vec<PyRouteHop>> {
        let mut routes = vec![];

        for path in self.inner.paths.iter() {
            let mut hops = vec![];
            for hop in path.iter() {
                hops.push(PyRouteHop { inner: hop.clone() });
            }
            routes.push(hops);
        }
        routes
    }
}
