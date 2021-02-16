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

    #[getter]
    fn get_minimum_depth(&self) -> u32 {
        self.inner.minimum_depth
    }

    #[getter]
    fn get_our_to_self_delay(&self) -> u16 {
        self.inner.our_to_self_delay
    }

    #[getter]
    fn get_our_htlc_minimum_msat(&self) -> u64 {
        self.inner.our_htlc_minimum_msat
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

    #[getter]
    fn get_min_funding_satoshis(&self) -> u64 {
        self.inner.min_funding_satoshis
    }

    #[getter]
    fn get_max_htlc_minimum_msat(&self) -> u64 {
        self.inner.max_htlc_minimum_msat
    }

    #[getter]
    fn get_min_max_htlc_value_in_flight_msat(&self) -> u64 {
        self.inner.min_max_htlc_value_in_flight_msat
    }

    #[getter]
    fn get_max_channel_reserve_satoshis(&self) -> u64 {
        self.inner.max_channel_reserve_satoshis
    }

    #[getter]
    fn get_min_max_accepted_htlcs(&self) -> u16 {
        self.inner.min_max_accepted_htlcs
    }

    #[getter]
    fn get_min_dust_limit_satoshis(&self) -> u64 {
        self.inner.min_dust_limit_satoshis
    }

    #[getter]
    fn get_max_dust_limit_satoshis(&self) -> u64 {
        self.inner.max_dust_limit_satoshis
    }

    #[getter]
    fn get_max_minimum_depth(&self) -> u32 {
        self.inner.max_minimum_depth
    }

    #[getter]
    fn get_force_announced_channel_preference(&self) -> bool {
        self.inner.force_announced_channel_preference
    }

    #[getter]
    fn get_their_to_self_delay(&self) -> u16 {
        self.inner.their_to_self_delay
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

    #[getter]
    fn get_fee_proportional_millionths(&self) -> u32 {
        self.inner.fee_proportional_millionths
    }

    #[getter]
    fn get_announced_channel(&self) -> bool {
        self.inner.announced_channel
    }

    #[getter]
    fn get_commit_upfront_shutdown_pubkey(&self) -> bool {
        self.inner.commit_upfront_shutdown_pubkey
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

    #[getter]
    fn get_own_channel_config(&self) -> PyChannelHandshakeConfig {
        PyChannelHandshakeConfig {
            // FIXME: Remove clone once #769 is merged
            inner: self.inner.own_channel_config.clone(),
        }
    }

    #[getter]
    fn get_peer_channel_config_limits(&self) -> PyChannelHandshakeLimits {
        PyChannelHandshakeLimits {
            inner: self.inner.peer_channel_config_limits,
        }
    }

    #[getter]
    fn get_channel_options(&self) -> PyChannelConfig {
        PyChannelConfig {
            inner: self.inner.channel_options,
        }
    }
}
