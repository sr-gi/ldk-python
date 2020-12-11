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
}
