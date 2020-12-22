use pyo3::create_exception;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::chain::chaininterface::{PyBroadcasterInterface, PyFeeEstimator};
use crate::chain::keysinterface::PyKeysManager;
use crate::chain::PyWatch;
use crate::ln::features::PyInitFeatures;
use crate::ln::msgs::PyNetAddress;
use crate::logger::LDKLogger;
use crate::primitives::{PyNetwork, PyOutPoint, PyPublicKey};
use crate::routing::router::PyRoute;
use crate::util::config::PyUserConfig;
use crate::util::errors::match_api_error;

use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::keysinterface::InMemoryChannelKeys;
use lightning::ln::channelmanager as CM;
use lightning::ln::channelmanager::{
    ChannelDetails, ChannelManager, PaymentHash, PaymentPreimage, PaymentSecret,
};
use lightning::util::logger::Logger;

// Generic error for sent payments. Other payment errors inherint from this one
create_exception!(
    channelmanager,
    PaymentSendFailure,
    pyo3::exceptions::PyException
);
create_exception!(errors, ParameterError, PaymentSendFailure);
create_exception!(errors, PathParameterError, PaymentSendFailure);
create_exception!(errors, AllFailedRetrySafe, PaymentSendFailure);
create_exception!(errors, PartialFailure, PaymentSendFailure);

pub fn match_payment_error(e: CM::PaymentSendFailure) -> PyErr {
    match e {
        CM::PaymentSendFailure::ParameterError(_) => ParameterError::new_err(format!("{:?}", e)),
        CM::PaymentSendFailure::PathParameterError(_) => {
            PathParameterError::new_err(format!("{:?}", e))
        }
        CM::PaymentSendFailure::AllFailedRetrySafe(_) => {
            AllFailedRetrySafe::new_err(format!("{:?}", e))
        }
        CM::PaymentSendFailure::PartialFailure(_) => PartialFailure::new_err(format!("{:?}", e)),
    }
}

#[pyclass(name=PaymentPreimage)]
#[derive(Clone)]
pub struct PyPaymentPreimage {
    pub inner: PaymentPreimage,
}

#[pymethods]
impl PyPaymentPreimage {
    #[new]
    pub fn new(data: [u8; 32]) -> Self {
        PyPaymentPreimage {
            inner: PaymentPreimage(data),
        }
    }
}

#[pyclass(name=PaymentSecret)]
#[derive(Clone)]
pub struct PyPaymentSecret {
    pub inner: PaymentSecret,
}

#[pymethods]
impl PyPaymentSecret {
    #[new]
    pub fn new(data: [u8; 32]) -> Self {
        PyPaymentSecret {
            inner: PaymentSecret(data),
        }
    }
}

#[pyclass(name=PaymentHash)]
#[derive(Clone)]
pub struct PyPaymentHash {
    pub inner: PaymentHash,
}

#[pymethods]
impl PyPaymentHash {
    #[new]
    pub fn new(data: [u8; 32]) -> Self {
        PyPaymentHash {
            inner: PaymentHash(data),
        }
    }

    fn serialize(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.0).into()
    }
}

#[pyclass(name=ChannelDetails)]
#[derive(Clone)]
pub struct PyChannelDetails {
    pub inner: ChannelDetails,
}

#[pymethods]
impl PyChannelDetails {
    #[new]
    pub fn new(
        channel_id: [u8; 32],
        short_channel_id: Option<u64>,
        remote_network_id: PyPublicKey,
        counterparty_features: PyInitFeatures,
        channel_value_satoshis: u64,
        user_id: u64,
        outbound_capacity_msat: u64,
        inbound_capacity_msat: u64,
        is_live: bool,
    ) -> Self {
        PyChannelDetails {
            inner: ChannelDetails {
                channel_id,
                short_channel_id,
                remote_network_id: remote_network_id.inner,
                counterparty_features: counterparty_features.inner,
                channel_value_satoshis,
                user_id,
                outbound_capacity_msat,
                inbound_capacity_msat,
                is_live,
            },
        }
    }
}

#[pyclass(unsendable, name=ChannelManager)]
pub struct PyChannelManager {
    pub inner: ChannelManager<
        InMemoryChannelKeys,
        Box<PyWatch>,
        Box<dyn BroadcasterInterface>,
        PyKeysManager,
        Box<dyn FeeEstimator>,
        Box<dyn Logger>,
    >,
}

#[pymethods]
impl PyChannelManager {
    #[new]
    fn new(
        network: PyNetwork,
        fee_est: PyFeeEstimator,
        chain_monitor: PyWatch,
        tx_broadcaster: PyBroadcasterInterface,
        logger: LDKLogger,
        keys_manager: PyKeysManager,
        config: PyUserConfig,
        current_blockchain_height: usize,
    ) -> Self {
        PyChannelManager {
            inner: ChannelManager::new(
                network.inner,
                Box::new(fee_est),
                Box::new(chain_monitor),
                Box::new(tx_broadcaster),
                Box::new(logger),
                keys_manager,
                config.inner,
                current_blockchain_height,
            ),
        }
    }

    pub fn create_channel(
        &self,
        their_network_key: PyPublicKey,
        channel_value_satoshis: u64,
        push_msat: u64,
        user_id: u64,
        override_config: Option<PyUserConfig>,
    ) -> PyResult<()> {
        let native_override_config = match override_config {
            Some(x) => Some(x.inner),
            None => None,
        };

        match self.inner.create_channel(
            their_network_key.inner,
            channel_value_satoshis,
            push_msat,
            user_id,
            native_override_config,
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(match_api_error(&e)),
        }
    }

    pub fn list_channels(&self) -> Vec<PyChannelDetails> {
        let mut channels = vec![];
        for channel in self.inner.list_channels().into_iter() {
            channels.push(PyChannelDetails { inner: channel })
        }
        channels
    }

    pub fn list_usable_channels(&self) -> Vec<PyChannelDetails> {
        let mut channels = vec![];
        for channel in self.inner.list_usable_channels().into_iter() {
            channels.push(PyChannelDetails { inner: channel })
        }
        channels
    }

    pub fn close_channel(&self, channel_id: [u8; 32]) -> PyResult<()> {
        match self.inner.close_channel(&channel_id) {
            Ok(_) => Ok(()),
            Err(e) => Err(match_api_error(&e)),
        }
    }

    pub fn force_close_channel(&self, channel_id: [u8; 32]) {
        self.inner.force_close_channel(&channel_id)
    }

    pub fn force_close_all_channels(&self) {
        self.inner.force_close_all_channels()
    }

    pub fn send_payment(
        &self,
        route: &PyRoute,
        payment_hash: PyPaymentHash,
        payment_secret: Option<PyPaymentSecret>,
    ) -> PyResult<()> {
        let native_payment_secret = match payment_secret {
            Some(x) => Some(x.inner),
            None => None,
        };
        match self
            .inner
            .send_payment(&route.inner, payment_hash.inner, &native_payment_secret)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(match_payment_error(e)),
        }
    }

    pub fn funding_transaction_generated(
        &self,
        temporary_channel_id: [u8; 32],
        funding_txo: PyOutPoint,
    ) {
        self.inner
            .funding_transaction_generated(&temporary_channel_id, funding_txo.inner)
    }

    pub fn broadcast_node_announcement(
        &self,
        rgb: [u8; 3],
        alias: [u8; 32],
        addresses: Vec<PyNetAddress>,
    ) {
        let mut native_addresses = vec![];
        for address in addresses.into_iter() {
            native_addresses.push(address.inner)
        }
        self.inner
            .broadcast_node_announcement(rgb, alias, native_addresses)
    }

    pub fn process_pending_htlc_forwards(&self) {
        self.inner.process_pending_htlc_forwards()
    }

    pub fn timer_chan_freshness_every_min(&self) {
        self.inner.timer_chan_freshness_every_min()
    }

    pub fn fail_htlc_backwards(
        &self,
        payment_hash: &PyPaymentHash,
        payment_secret: Option<PyPaymentSecret>,
    ) -> bool {
        let native_payment_secret = match payment_secret {
            Some(x) => Some(x.inner),
            None => None,
        };
        self.inner
            .fail_htlc_backwards(&payment_hash.inner, &native_payment_secret)
    }

    pub fn claim_funds(
        &self,
        payment_preimage: PyPaymentPreimage,
        payment_secret: Option<PyPaymentSecret>,
        expected_amount: u64,
    ) -> bool {
        let native_payment_secret = match payment_secret {
            Some(x) => Some(x.inner),
            None => None,
        };
        self.inner.claim_funds(
            payment_preimage.inner,
            &native_payment_secret,
            expected_amount,
        )
    }

    pub fn get_our_node_id(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.get_our_node_id(),
        }
    }

    pub fn channel_monitor_updated(
        &self,
        funding_txo: &PyOutPoint,
        highest_applied_update_id: u64,
    ) {
        self.inner
            .channel_monitor_updated(&funding_txo.inner, highest_applied_update_id)
    }
}
