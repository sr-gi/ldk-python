use pyo3::prelude::*;

use lightning::util::config::{
    ChannelConfig, ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig,
};

#[pyclass(name=ChannelHandshakeConfig)]
#[derive(Clone)]
pub struct PyChannelHandshakeConfig {
    pub inner: ChannelHandshakeConfig,
}

#[pymethods]
impl PyChannelHandshakeConfig {
    #[new]
    pub fn new(minimum_depth: u32, our_to_self_delay: u16, our_htlc_minimum_msat: u64) -> Self {
        PyChannelHandshakeConfig {
            inner: ChannelHandshakeConfig {
                minimum_depth,
                our_to_self_delay,
                our_htlc_minimum_msat,
            },
        }
    }

    #[staticmethod]
    pub fn default() -> PyChannelHandshakeConfig {
        PyChannelHandshakeConfig {
            inner: ChannelHandshakeConfig::default(),
        }
    }
}

#[pyclass(name=ChannelHandshakeLimits)]
#[derive(Clone)]
pub struct PyChannelHandshakeLimits {
    pub inner: ChannelHandshakeLimits,
}

#[pymethods]
impl PyChannelHandshakeLimits {
    #[new]
    pub fn new(
        min_funding_satoshis: u64,
        max_htlc_minimum_msat: u64,
        min_max_htlc_value_in_flight_msat: u64,
        max_channel_reserve_satoshis: u64,
        min_max_accepted_htlcs: u16,
        min_dust_limit_satoshis: u64,
        max_dust_limit_satoshis: u64,
        max_minimum_depth: u32,
        force_announced_channel_preference: bool,
        their_to_self_delay: u16,
    ) -> Self {
        PyChannelHandshakeLimits {
            inner: ChannelHandshakeLimits {
                min_funding_satoshis,
                max_htlc_minimum_msat,
                min_max_htlc_value_in_flight_msat,
                max_channel_reserve_satoshis,
                min_max_accepted_htlcs,
                min_dust_limit_satoshis,
                max_dust_limit_satoshis,
                max_minimum_depth,
                force_announced_channel_preference,
                their_to_self_delay,
            },
        }
    }

    #[staticmethod]
    pub fn default() -> PyChannelHandshakeLimits {
        PyChannelHandshakeLimits {
            inner: ChannelHandshakeLimits::default(),
        }
    }
}

#[pyclass(name=ChannelConfig)]
#[derive(Clone)]
pub struct PyChannelConfig {
    pub inner: ChannelConfig,
}

#[pymethods]
impl PyChannelConfig {
    #[new]
    pub fn new(
        fee_proportional_millionths: u32,
        announced_channel: bool,
        commit_upfront_shutdown_pubkey: bool,
    ) -> Self {
        PyChannelConfig {
            inner: ChannelConfig {
                fee_proportional_millionths,
                announced_channel,
                commit_upfront_shutdown_pubkey,
            },
        }
    }

    #[staticmethod]
    pub fn default() -> PyChannelConfig {
        PyChannelConfig {
            inner: ChannelConfig::default(),
        }
    }
}

#[pyclass(name=UserConfig)]
#[derive(Clone)]
pub struct PyUserConfig {
    pub inner: UserConfig,
}

#[pymethods]
impl PyUserConfig {
    #[new]
    pub fn new(
        own_channel_config: PyChannelHandshakeConfig,
        peer_channel_config_limits: PyChannelHandshakeLimits,
        channel_options: PyChannelConfig,
    ) -> Self {
        PyUserConfig {
            inner: UserConfig {
                own_channel_config: own_channel_config.inner,
                peer_channel_config_limits: peer_channel_config_limits.inner,
                channel_options: channel_options.inner,
            },
        }
    }

    #[staticmethod]
    pub fn default() -> PyUserConfig {
        PyUserConfig {
            inner: UserConfig::default(),
        }
    }
}
