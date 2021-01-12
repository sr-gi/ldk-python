import pytest
from conftest import get_random_pk_bytes, get_random_bytes, get_random_int

from ldk_python.primitives import PublicKey
from ldk_python.ln.features import NodeFeatures, ChannelFeatures
from ldk_python.routing.router import Route, RouteHop

# ROUTE HOP TESTS


@pytest.fixture()
def route_hop():
    return get_rand_route_hop()


def get_rand_route_hop():
    pubkey = PublicKey(get_random_pk_bytes())
    node_features = NodeFeatures()
    short_channel_id = get_random_int(2)
    channel_features = ChannelFeatures()
    fee_msat = 1000
    cltv_expiry_delta = 20

    return RouteHop(pubkey, node_features, short_channel_id, channel_features, fee_msat, cltv_expiry_delta)


def test_route_hop(route_hop):
    assert isinstance(route_hop, RouteHop)


def test_route_hop_getters():
    # FIXME: Features content cannot be tested since it cannot be serialized and the flags cannot be accessed
    # Try back once bindings are switched to work with references intead of values
    pubkey = PublicKey(get_random_pk_bytes())
    node_features = NodeFeatures()
    short_channel_id = get_random_int(2)
    channel_features = ChannelFeatures()
    fee_msat = 1000
    cltv_expiry_delta = 20

    rh = RouteHop(pubkey, node_features, short_channel_id, channel_features, fee_msat, cltv_expiry_delta)

    assert rh.pubkey.serialize() == pubkey.serialize()
    assert rh.short_channel_id == short_channel_id
    assert rh.fee_msat == fee_msat
    assert rh.cltv_expiry_delta == cltv_expiry_delta


# ROUTE TESTS


def test_route():
    hops = [[get_rand_route_hop() for _ in range(10)]]

    assert isinstance(Route(hops), Route)


def test_route_getters():
    hops = [[get_rand_route_hop() for _ in range(10)]]

    for local_route, remote_route in zip(hops, Route(hops).paths):
        for remote_hop, local_hop in zip(local_route, remote_route):
            assert remote_hop.pubkey.serialize() == local_hop.pubkey.serialize()
            assert remote_hop.short_channel_id == local_hop.short_channel_id
            assert remote_hop.fee_msat == local_hop.fee_msat
            assert remote_hop.cltv_expiry_delta == local_hop.cltv_expiry_delta
