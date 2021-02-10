import pytest
from ldk_python.ln.features import *


# FIXME: Features seem not to offer an extensive API atm.
# Not even the flags can be checked outside the crate.
# Test that the objects can be built at least.


@pytest.fixture
def init_features_bytes():
    return bytes.fromhex("000302922a")


def test_init_features_empty():
    assert isinstance(InitFeatures(), InitFeatures)


def test_init_features_known():
    assert isinstance(InitFeatures.known(), InitFeatures)


def test_init_features_from_bytes(init_features_bytes):
    assert isinstance(InitFeatures.from_bytes(init_features_bytes), InitFeatures)


def test_init_features_serialize(init_features_bytes):
    assert InitFeatures.known().serialize() == InitFeatures.from_bytes(init_features_bytes).serialize()


@pytest.fixture
def channel_features_bytes():
    return bytes.fromhex("0000")


def test_channel_features_empty():
    assert isinstance(ChannelFeatures(), ChannelFeatures)


def test_channel_features_known():
    assert isinstance(ChannelFeatures.known(), ChannelFeatures)


def test_channel_features_from_bytes(channel_features_bytes):
    assert isinstance(ChannelFeatures.from_bytes(channel_features_bytes), ChannelFeatures)


def test_channel_features_serialize(channel_features_bytes):
    assert ChannelFeatures.known().serialize() == ChannelFeatures.from_bytes(channel_features_bytes).serialize()


@pytest.fixture
def node_features_bytes():
    return bytes.fromhex("0003029222")


def test_node_features_empty():
    assert isinstance(NodeFeatures(), NodeFeatures)


def test_node_features_known():
    assert isinstance(NodeFeatures.known(), NodeFeatures)


def test_node_features_from_bytes(node_features_bytes):
    assert isinstance(NodeFeatures.from_bytes(node_features_bytes), NodeFeatures)


def test_node_features_serialize(node_features_bytes):
    assert NodeFeatures.known().serialize() == NodeFeatures.from_bytes(node_features_bytes).serialize()
