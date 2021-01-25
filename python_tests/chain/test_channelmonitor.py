import pytest
from conftest import Empty, get_random_bytes, get_random_pk_bytes, get_random_int

from python_tests.test_logger import Logger
from python_tests.chain.test_keysinterface import in_mem_chan_keys
from python_tests.ln.test_chan_utils import holder_commitment_tx_data
from python_tests.chain.test_chaininterface import Broadcaster, FeeEst

from ldk_python.logger import LDKLogger
from ldk_python.chain.chaininterface import BroadcasterInterface, FeeEstimator
from ldk_python.ln.chan_utils import HolderCommitmentTransaction
from ldk_python.primitives import OutPoint, PublicKey, Script, Transaction, BlockHeader
from ldk_python.chain.channelmonitor import *


@pytest.fixture()
def holder_commitment_tx(holder_commitment_tx_data):
    tx, counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data = holder_commitment_tx_data

    return HolderCommitmentTransaction(tx, counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data)


@pytest.fixture()
def channel_monitor_update_data():
    return bytes.fromhex(
        "000000000000000100000000000000010300000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )


# CHANNEL MONITOR
@pytest.fixture
def channel_monitor_data(in_mem_chan_keys, holder_commitment_tx):
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

    return {
        "in_mem_chan_keys": in_mem_chan_keys,
        "shutdown_pk": shutdown_pk,
        "on_counterparty_tx_csv": on_counterparty_tx_csv,
        "destination_script": destination_script,
        "funding_info": funding_info,
        "counterparty_htlc_base_key": counterparty_htlc_base_key,
        "counterparty_delayed_payment_base_key": counterparty_delayed_payment_base_key,
        "on_holder_tx_csv": on_holder_tx_csv,
        "funding_redeemscript": funding_redeemscript,
        "channel_value_satoshis": channel_value_satoshis,
        "commitment_transaction_number_obscure_factor": commitment_transaction_number_obscure_factor,
        "holder_commitment_tx": holder_commitment_tx,
    }


@pytest.fixture
def channel_monitor(channel_monitor_data):
    return InMemoryKeysChannelMonitor(
        channel_monitor_data.get("in_mem_chan_keys"),
        channel_monitor_data.get("shutdown_pk"),
        channel_monitor_data.get("on_counterparty_tx_csv"),
        channel_monitor_data.get("destination_script"),
        channel_monitor_data.get("funding_info"),
        channel_monitor_data.get("counterparty_htlc_base_key"),
        channel_monitor_data.get("counterparty_delayed_payment_base_key"),
        channel_monitor_data.get("on_holder_tx_csv"),
        channel_monitor_data.get("funding_redeemscript"),
        channel_monitor_data.get("channel_value_satoshis"),
        channel_monitor_data.get("commitment_transaction_number_obscure_factor"),
        channel_monitor_data.get("holder_commitment_tx"),
    )


def test_channel_monitor(channel_monitor):
    assert isinstance(channel_monitor, InMemoryKeysChannelMonitor)


def test_update_monitor(channel_monitor, channel_monitor_update_data):
    update = ChannelMonitorUpdate.from_bytes(channel_monitor_update_data)
    broadcaster = BroadcasterInterface(Broadcaster())
    fee_estimator = FeeEstimator(FeeEst())
    logger = LDKLogger(Logger())

    channel_monitor.update_monitor(update, broadcaster, fee_estimator, logger)


def test_get_latest_update_id(channel_monitor):
    # There hasn't been any update, so the id should be 0.
    assert channel_monitor.get_latest_update_id() == 0


def test_get_funding_txo(channel_monitor, channel_monitor_data):
    funding_txo = channel_monitor.get_funding_txo()
    funding_info = channel_monitor_data.get("funding_info")
    for i in range(len(funding_txo)):
        assert funding_info[i].serialize() == funding_txo[i].serialize()


def test_get_outputs_to_watch(channel_monitor, channel_monitor_data):
    # Channel is in the initial state, so outputs_to_watch must match the founding info
    outputs = channel_monitor.get_outputs_to_watch()
    funding_info = channel_monitor_data.get("funding_info")
    assert len(outputs) == 1

    for txid, outs in outputs.items():
        assert len(outs) == 1
        out = outs[0]
        txid.serialize() == funding_info[0].txid
        funding_info[0].index == out[0]
        funding_info[1].serialize == out[1].serialize()


def test_get_and_clear_pending_monitor_events(channel_monitor):
    # There should be no monitor pending events
    assert channel_monitor.get_and_clear_pending_monitor_events() == []


def test_get_and_clear_pending_events(channel_monitor):
    # There should be no pending events
    assert channel_monitor.get_and_clear_pending_events() == []


# FIXME: cannot seem to be able to capture pyo3_runtime.PanicException, comment out till next version
def test_get_latest_holder_commitment_txn(channel_monitor):
    #     # Not the best UX at the moment, but looks like this may change for 0.0.13.
    #     with pytest.raises(Exception, match="must accept before signing"):
    #         channel_monitor.get_latest_holder_commitment_txn(LDKLogger(Logger()))
    pass


def test_block_connected(channel_monitor, tx):
    block_header = BlockHeader(get_random_bytes(80))
    txdata = [(len(tx), Transaction.from_bytes(tx))]
    height = 1
    broadcaster = BroadcasterInterface(Broadcaster())
    fee_estimator = FeeEstimator(FeeEst())
    logger = LDKLogger(Logger())

    outs_to_watch = channel_monitor.block_connected(block_header, txdata, height, broadcaster, fee_estimator, logger)

    # The data is completely made up, so there should be no outputs to watch
    assert outs_to_watch == []


def test_block_disconnected(channel_monitor, tx):
    block_header = BlockHeader(get_random_bytes(80))
    height = 1
    broadcaster = BroadcasterInterface(Broadcaster())
    fee_estimator = FeeEstimator(FeeEst())
    logger = LDKLogger(Logger())

    channel_monitor.block_disconnected(block_header, height, broadcaster, fee_estimator, logger)


# EXCEPTIONS

# Test that all exceptions can be created


def test_monitor_update_err():
    monitor_update_err = MonitorUpdateErr()
    assert isinstance(monitor_update_err, MonitorUpdateErr) and isinstance(monitor_update_err, Exception)


def test_temp_chann_monitor_err():
    monitor_update_err = TemporaryChannelMonitorUpdateErr()
    assert isinstance(monitor_update_err, TemporaryChannelMonitorUpdateErr) and isinstance(
        monitor_update_err, Exception
    )


def test_perm_chann_monitor_err():
    monitor_update_err = PermanentChannelMonitorUpdateErr()
    assert isinstance(monitor_update_err, PermanentChannelMonitorUpdateErr) and isinstance(
        monitor_update_err, Exception
    )


# CHANNEL MONITOR UPDATE
def test_channel_monitor_update_serde(channel_monitor_update_data):
    chanel_monitor_update = ChannelMonitorUpdate.from_bytes(channel_monitor_update_data)
    assert isinstance(chanel_monitor_update, ChannelMonitorUpdate)
    assert chanel_monitor_update.serialize() == channel_monitor_update_data


# PERSIST
class Persister:
    def persist_new_channel(self, id, data):
        pass

    def update_persisted_channel(self, id, update, data):
        pass


def test_persist():
    assert isinstance(Persist(Persister()), Persist)


def test_persist_empty():
    with pytest.raises(TypeError, match="Not all required methods are implemented"):
        Persist(Empty())


def test_persist_new_channel(channel_monitor):
    persister = Persist(Persister())
    outpoint = OutPoint.from_bytes(get_random_bytes(36))
    persister.persist_new_channel(outpoint, channel_monitor)


def test_update_persisted_channel(channel_monitor, channel_monitor_update_data):
    persister = Persist(Persister())
    outpoint = OutPoint.from_bytes(get_random_bytes(36))
    update = ChannelMonitorUpdate.from_bytes(channel_monitor_update_data)
    persister.update_persisted_channel(outpoint, update, channel_monitor)