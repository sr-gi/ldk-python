from ldk_python.ln.features import *


# FIXME: Features seem not to offer an extensive API atm.
# Not even the flags can be checked outside the crate.
# Test that the objects can be built at least.


def test_init_features_empty():
    assert isinstance(InitFeatures(), InitFeatures)


def test_init_features_known():
    assert isinstance(InitFeatures.known(), InitFeatures)


def test_channel_features_empty():
    assert isinstance(ChannelFeatures(), ChannelFeatures)


def test_channel_features_known():
    assert isinstance(ChannelFeatures.known(), ChannelFeatures)


def test_node_features_empty():
    assert isinstance(NodeFeatures(), NodeFeatures)


def test_node_features_known():
    assert isinstance(NodeFeatures.known(), NodeFeatures)