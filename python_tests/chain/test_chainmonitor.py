import pytest

from ldk_python.chain import Filter
from ldk_python.logger import LDKLogger
from ldk_python.chain.chainmonitor import *
from ldk_python.chain.channelmonitor import Persist, ChannelMonitorUpdate, PermanentChannelMonitorUpdateErr
from ldk_python.primitives import BlockHeader, Transaction, OutPoint
from ldk_python.chain.chaininterface import BroadcasterInterface, FeeEstimator


from conftest import get_random_bytes
from python_tests.chain.test_chain import F
from python_tests.test_logger import Logger
from python_tests.chain.test_channelmonitor import (
    Persister,
    channel_monitor,
    channel_monitor_data,
    holder_commitment_tx,
    channel_monitor_update_data,
)
from python_tests.chain.test_keysinterface import in_mem_chan_keys
from python_tests.ln.test_chan_utils import holder_commitment_tx_data
from python_tests.chain.test_chaininterface import Broadcaster, FeeEst


@pytest.fixture
def chain_monitor(in_mem_chan_keys):
    chain_source = Filter(F())
    broadcaster = BroadcasterInterface(Broadcaster())
    fee_estimator = FeeEstimator(FeeEst())
    logger = LDKLogger(Logger())
    persister = Persist(Persister())

    return ChainMonitor(chain_source, broadcaster, logger, fee_estimator, persister)


def test_chain_monitor(chain_monitor):
    assert isinstance(chain_monitor, ChainMonitor)


def test_block_connected(chain_monitor, tx):
    block_header = BlockHeader(get_random_bytes(80))
    txdata = [(len(tx), Transaction.from_bytes(tx))]
    height = 42

    chain_monitor.block_connected(block_header, txdata, height)


def test_block_disconnected(chain_monitor):
    block_header = BlockHeader(get_random_bytes(80))
    height = 43

    chain_monitor.block_disconnected(block_header, height)


def test_watch_channel(chain_monitor, channel_monitor):
    outpoint = OutPoint.from_bytes(get_random_bytes(34))

    chain_monitor.watch_channel(outpoint, channel_monitor)


def test_update_channel(chain_monitor, channel_monitor, channel_monitor_update_data):
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    update = ChannelMonitorUpdate.from_bytes(channel_monitor_update_data)

    # First watch the channel
    chain_monitor.watch_channel(outpoint, channel_monitor)

    # Then update
    chain_monitor.update_channel(outpoint, update)


def test_update_channel_unknown_channel(chain_monitor, channel_monitor_update_data):
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    update = ChannelMonitorUpdate.from_bytes(channel_monitor_update_data)

    # Update without having watched the channel
    with pytest.raises(PermanentChannelMonitorUpdateErr):
        chain_monitor.update_channel(outpoint, update)


def test_release_pending_monitor_events(chain_monitor):
    assert chain_monitor.release_pending_monitor_events() == []


def test_get_and_clear_pending_events(chain_monitor):
    assert chain_monitor.get_and_clear_pending_events() == []
