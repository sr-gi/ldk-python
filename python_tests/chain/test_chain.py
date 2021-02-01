import pytest
from conftest import Empty, get_random_bytes

from python_tests.chain.test_keysinterface import in_mem_chan_keys
from python_tests.chain.test_channelmonitor import (
    channel_monitor,
    channel_monitor_data,
    holder_commitment_tx,
    holder_commitment_tx_data,
    channel_monitor_update_data,
)

from ldk_python.chain import Watch, Filter
from ldk_python.primitives import OutPoint, TxId, Script
from ldk_python.chain.channelmonitor import (
    ChannelMonitorUpdate,
    TemporaryChannelMonitorUpdateErr,
    PermanentChannelMonitorUpdateErr,
)


# WATCH


class W:
    def watch_channel(self, funding_txo, monitor):
        print("Watching channel")

    def update_channel(self, funding_txo, update):
        print("Updating channel")

    def release_pending_monitor_events(self):
        print("Releasing pending events from channel")
        return []


class WWithErrors:
    def watch_channel(self, funding_txo, monitor):
        raise TemporaryChannelMonitorUpdateErr()

    def update_channel(self, funding_txo, update):
        raise PermanentChannelMonitorUpdateErr()

    def release_pending_monitor_events(self):
        pass


def test_watch():
    assert isinstance(Watch(W()), Watch)
    assert isinstance(Watch(WWithErrors()), Watch)


def test_watch_wrong_trait():
    with pytest.raises(TypeError, match="Not all required methods are implemented"):
        Watch(Empty())


def test_watch_channel(channel_monitor):
    watcher = Watch(W())
    outpoint = OutPoint.from_bytes(get_random_bytes(34))

    watcher.watch_channel(outpoint, channel_monitor)


def test_update_channel(channel_monitor_update_data):
    watcher = Watch(W())
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    update = ChannelMonitorUpdate.from_bytes(channel_monitor_update_data)

    watcher.update_channel(outpoint, update)


def test_release_pending_monitor_events():
    watcher = Watch(W())

    # We've defined the dummy Watch implementation to return an empty list
    assert watcher.release_pending_monitor_events() == []


# FILTER


class F:
    def register_tx(self, txid, script_pubkey):
        print("Registering transaction")

    def register_output(self, outpoint, script_pubkey):
        print("Updating channel")


def test_filter():
    assert isinstance(Filter(F()), Filter)


def test_filter_wrong_trait():
    with pytest.raises(TypeError, match="Not all required methods are implemented"):
        Filter(Empty())


def test_register_tx():
    f = Filter(F())
    txid = TxId(get_random_bytes(32))
    script = Script(get_random_bytes(50))
    f.register_tx(txid, script)


def test_register_output():
    f = Filter(F())
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    script = Script(get_random_bytes(50))
    f.register_output(outpoint, script)
