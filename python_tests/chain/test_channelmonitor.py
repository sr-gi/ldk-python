import pytest
from conftest import Empty, get_random_bytes, get_random_pk_bytes, get_random_int

from python_tests.test_logger import Logger
from python_tests.chain.test_keysinterface import in_mem_chan_keys
from python_tests.ln.test_chan_utils import holder_commitment_tx_data
from python_tests.chain.test_chaininterface import Broadcaster, FeeEst

from ldk_python.logger import LDKLogger
from ldk_python.chain.chaininterface import BroadcasterInterface, FeeEstimator
from ldk_python.ln.chan_utils import HolderCommitmentTransaction
from ldk_python.primitives import OutPoint, PublicKey, Script
from ldk_python.chain.channelmonitor import *


@pytest.fixture()
def holder_commitment_tx(holder_commitment_tx_data):
    tx, counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data = holder_commitment_tx_data

    return HolderCommitmentTransaction(tx, counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data)


# CHANNEL MONITOR


@pytest.fixture
def channel_monitor(in_mem_chan_keys, holder_commitment_tx):
    shutdown_pk = PublicKey(get_random_pk_bytes())
    on_counterparty_tx_csv = 20
    destination_script = Script(get_random_bytes((40)))
    funding_info = (OutPoint.from_bytes(get_random_bytes(36)), Script(get_random_bytes(50)))
    counterparty_htlc_base_key = PublicKey(get_random_pk_bytes())
    counterparty_delayed_payment_base_key = PublicKey(get_random_pk_bytes())
    on_holder_tx_csv = 30
    funding_redeemscript = Script(get_random_bytes(40))
    channel_value_satoshis = 42
    commitment_transaction_number_obscure_factor = 10

    return InMemoryKeysChannelMonitor(
        in_mem_chan_keys,
        shutdown_pk,
        on_counterparty_tx_csv,
        destination_script,
        funding_info,
        counterparty_htlc_base_key,
        counterparty_delayed_payment_base_key,
        on_holder_tx_csv,
        funding_redeemscript,
        channel_value_satoshis,
        commitment_transaction_number_obscure_factor,
        holder_commitment_tx,
    )


def test_channel_monitor(channel_monitor):
    assert isinstance(channel_monitor, InMemoryKeysChannelMonitor)


# def test_update_monitor(channel_monitor):
#     broadcaster = BroadcasterInterface(Broadcaster())
#     fee_estimator = FeeEstimator(FeeEst())
#     logger = LDKLogger(Logger())

#     channel_monitor.update_monitor(None, broadcaster, fee_estimator, logger)


def test_get_latest_update_id(channel_monitor):
    print(channel_monitor.get_latest_update_id())


def test_get_funding_txo(channel_monitor):
    # FIXME: CHECK WHY SCRIPT IS DIFFERENT
    funding_txo = channel_monitor.get_funding_txo()


def test_get_outputs_to_watch(channel_monitor):
    outputs = channel_monitor.get_outputs_to_watch()
    print(outputs)


# FIXME: There's no constructor con ChannelMonitor since they are internally created by the ChannelManager, so not testing this atm.
# I may add a constructor just to make sure everything is OK.

# PERSIST
class Persister:
    def persist_new_channel(id, data):
        pass

    def update_persisted_channel(id, update, data):
        pass


def test_persist():
    assert isinstance(Persist(Persister()), Persist)


def test_persist_empty():
    with pytest.raises(TypeError, match="Not all required methods are implemented"):
        Persist(Empty())


# def test_persist_new_channel():
#     persister = Persist(Persister())
#     persister.persist_new_channel(OutPoint.from_bytes(get_random_bytes(36)), 1)
