import pytest

from conftest import get_random_pk_bytes, get_random_int, get_random_bytes
from python_tests.ln.test_msgs import (
    node_announcement_bytes,
    unsigned_node_announcement_bytes,
    channel_announcement_bytes,
    unsigned_channel_announcement_bytes,
    channel_update_bytes,
    unsigned_channel_update_bytes,
)
from python_tests.chain.test_chain import A
from python_tests.test_logger import Logger

from ldk_python.chain import Access
from ldk_python.logger import LDKLogger
from ldk_python.primitives import PublicKey
from ldk_python.routing.network_graph import *
from ldk_python.ln.msgs import (
    NodeAnnouncement,
    UnsignedNodeAnnouncement,
    ChannelAnnouncement,
    UnsignedChannelAnnouncement,
    LightningError,
    ChannelUpdate,
    UnsignedChannelUpdate,
    NetAddress,
)
from ldk_python.ln.features import ChannelFeatures, NodeFeatures


# NETWORK GRAPH
@pytest.fixture
def net_graph_bytes():
    return bytes.fromhex(
        "000000000000000100000000000000000000035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c00035c4e0dec7215e26833938730e5e505aa62504da85ba57106a46b5a2404fc9d8e0000fd01af94e4f56141247d9023a0c8348cc4ca51d81759ff7dac8c9b63291ce6121293bd664d6b9cfb35da16063df08f8a3999a2f25d120f2b421b8b9afe330ceb335e52ee99a10706edf8487ac6e5f55e013a412f18948a3b0a523fbf61a9c54f70eeb87923bb1a447d91e62abca107bc653b02d91db2f23acb7579c666d8c17129df0460f4bf077bb9c211946a28c2ddd87b448f08e3c8d8f481b09f94cbc8c13cc26e3126fc33163be0dea116219f89dd97a441f29f19b1ae82f7859ab78fb7527a72f15e89e18acd40b58ec3ca4276a36e1bf4873530584304d92c505455476f709b421f91fca1db725396c8e5cd0ecba0fe6b087748b7ad4a697cdcd80428359b73000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea3309000000000000000000000000035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c035c4e0dec7215e26833938730e5e505aa62504da85ba57106a46b5a2404fc9d8e02ba72a6e8ba53e8b971ad0c9823968aef4d78ce8af255ab43dff83003c902fb8d0216345bf831164a03758eaea5e8b66fee2be7710b8f190ee880249032a29ed66e0000000000000002035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c0000000000000001000000000000000000c50003029222000001f400000000000000000000000000000000000000000000000000000000000000000000000000000000000000905e398f34f8576a841121ae5e25703be9bd757d857562465a5a86cf8ab831694346fb6c201ea4bab3fd1914719a7cf044dd0f841e28e89a0b295c024e9750b8880003029222000001f4035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c00000000000000000000000000000000000000000000000000000000000000000000000000035c4e0dec7215e26833938730e5e505aa62504da85ba57106a46b5a2404fc9d8e000000000000000100000000000000000000"
    )


def test_network_graph():
    assert isinstance(NetworkGraph(), NetworkGraph)


def test_network_graph_from_bytes(net_graph_bytes):
    assert isinstance(NetworkGraph.from_bytes(net_graph_bytes), NetworkGraph)


def test_network_graph_serialize(net_graph_bytes):
    net_graph = NetworkGraph.from_bytes(net_graph_bytes)
    assert net_graph.serialize() == net_graph_bytes


def test_network_graph_getters():
    net_graph = NetworkGraph()

    assert net_graph.channels == {}
    assert net_graph.nodes == {}

    # This is not exactly a getter perse (like getting an attribute), but its a Rust getter, so let's add it here too.
    pk = PublicKey(get_random_pk_bytes())
    assert net_graph.get_addresses(pk) is None


def test_network_graph_update_node_from_announcement(node_announcement_bytes, channel_announcement_bytes):
    node_announcement = NodeAnnouncement.from_bytes(node_announcement_bytes)
    net_graph = NetworkGraph()

    # Update node needs a channel announcement first
    chan_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    net_graph.update_channel_from_announcement(chan_announcement)

    # Check it does not fail
    r = net_graph.update_node_from_announcement(node_announcement)
    assert r is None


def test_network_graph_update_node_from_announcement_err(node_announcement_bytes):
    node_announcement = NodeAnnouncement.from_bytes(node_announcement_bytes)
    net_graph = NetworkGraph()

    # Check it does not fail
    r = net_graph.update_node_from_announcement(node_announcement)
    assert isinstance(r, LightningError)
    assert r.err == "No existing channels for node_announcement"


def test_network_graph_update_node_from_unsigned_announcement_err(unsigned_node_announcement_bytes):
    unsig_node_announcement = UnsignedNodeAnnouncement.from_bytes(unsigned_node_announcement_bytes)
    net_graph = NetworkGraph()

    # Check it does not fail
    r = net_graph.update_node_from_unsigned_announcement(unsig_node_announcement)
    assert isinstance(r, LightningError)
    assert r.err == "No existing channels for node_announcement"


def test_network_graph_update_node_from_unsigned_announcement_err(
    unsigned_node_announcement_bytes, unsigned_channel_announcement_bytes
):
    unsig_node_announcement = UnsignedNodeAnnouncement.from_bytes(unsigned_node_announcement_bytes)
    net_graph = NetworkGraph()

    # Update node needs a channel announcement first
    chan_announcement = UnsignedChannelAnnouncement.from_bytes(unsigned_channel_announcement_bytes)
    net_graph.update_channel_from_unsigned_announcement(chan_announcement)

    # Check it does not fail
    r = net_graph.update_node_from_unsigned_announcement(unsig_node_announcement)
    assert r is None


def test_network_graph_update_channel_from_announcement(channel_announcement_bytes):
    chan_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    net_graph = NetworkGraph()

    # Check it does not fail
    net_graph.update_channel_from_announcement(chan_announcement)
    # Check both nodes and the channel was added
    assert len(net_graph.nodes) == 2
    assert len(net_graph.channels) == 1


def test_network_graph_update_channel_from_unsigned_announcement(unsigned_channel_announcement_bytes):
    unsig_chan_announcement = UnsignedChannelAnnouncement.from_bytes(unsigned_channel_announcement_bytes)
    net_graph = NetworkGraph()

    # Check it does not fail
    net_graph.update_channel_from_unsigned_announcement(unsig_chan_announcement)
    # Check both nodes and the channel was added
    assert len(net_graph.nodes) == 2
    assert len(net_graph.channels) == 1


def test_network_graph_close_channel_from_update_non_existing():
    net_graph = NetworkGraph()

    # Check that the channel count does not change
    assert len(net_graph.channels) == 0
    net_graph.close_channel_from_update(42, True)
    assert len(net_graph.channels) == 0


def test_network_graph_close_channel_from_update(channel_announcement_bytes):
    net_graph = NetworkGraph()

    chan_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    net_graph.update_channel_from_announcement(chan_announcement)

    # Check that the channel count decreases
    assert len(net_graph.channels) == 1
    net_graph.close_channel_from_update(0, True)
    assert len(net_graph.channels) == 0


def test_network_graph_update_channel(channel_update_bytes, channel_announcement_bytes):
    chan_update = ChannelUpdate.from_bytes(channel_update_bytes)
    net_graph = NetworkGraph()

    # Update channel needs a channel announcement first
    chan_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    net_graph.update_channel_from_announcement(chan_announcement)

    # Check it does not fail
    r = net_graph.update_channel(chan_update)
    assert r is None


def test_network_graph_update_channel_err(channel_update_bytes):
    chan_update = ChannelUpdate.from_bytes(channel_update_bytes)
    net_graph = NetworkGraph()

    r = net_graph.update_channel(chan_update)
    assert isinstance(r, LightningError)
    assert r.err == "Couldn't find channel for update"


def test_network_graph_update_channel_unsigned(unsigned_channel_update_bytes, channel_announcement_bytes):
    chan_update = UnsignedChannelUpdate.from_bytes(unsigned_channel_update_bytes)
    net_graph = NetworkGraph()

    # Update channel needs a channel announcement first
    chan_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    net_graph.update_channel_from_announcement(chan_announcement)

    r = net_graph.update_channel_unsigned(chan_update)
    assert r is None


def test_network_graph_update_channel_unsigned_err(unsigned_channel_update_bytes):
    chan_update = UnsignedChannelUpdate.from_bytes(unsigned_channel_update_bytes)
    net_graph = NetworkGraph()

    r = net_graph.update_channel_unsigned(chan_update)
    assert isinstance(r, LightningError)
    assert r.err == "Couldn't find channel for update"


def test_network_graph_str(net_graph_bytes):
    empty_net_graph = NetworkGraph()
    net_graph = NetworkGraph.from_bytes(net_graph_bytes)

    # Check that casting to str and printing does not fail
    print(str(empty_net_graph))
    print(str(net_graph))


# NET GRAPH MSG HANDLER
def test_net_graph_msg_handler():
    access = Access(A())
    logger = LDKLogger(Logger())

    assert isinstance(NetGraphMsgHandler(access, logger), NetGraphMsgHandler)
    assert isinstance(NetGraphMsgHandler(None, logger), NetGraphMsgHandler)


def test_net_graph_msg_handler_from_net_graph(channel_announcement_bytes):
    access = Access(A())
    logger = LDKLogger(Logger())
    net_graph = NetworkGraph()

    assert isinstance(NetGraphMsgHandler.from_net_graph(access, logger, net_graph), NetGraphMsgHandler)
    assert isinstance(NetGraphMsgHandler.from_net_graph(None, logger, net_graph), NetGraphMsgHandler)

    # Check also with a non-empty graph
    chan_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    net_graph.update_channel_from_announcement(chan_announcement)

    assert isinstance(NetGraphMsgHandler.from_net_graph(access, logger, net_graph), NetGraphMsgHandler)
    assert isinstance(NetGraphMsgHandler.from_net_graph(None, logger, net_graph), NetGraphMsgHandler)


def test_net_graph_msg_handler_get_graph(net_graph_bytes):
    access = Access(A())
    logger = LDKLogger(Logger())

    empty_graph_handler = NetGraphMsgHandler.from_net_graph(access, logger, NetworkGraph())
    net_graph_handler = NetGraphMsgHandler.from_net_graph(access, logger, NetworkGraph.from_bytes(net_graph_bytes))

    assert empty_graph_handler.graph.serialize() == bytes(16)
    assert net_graph_handler.graph.serialize() == net_graph_bytes


# DIRECTIONAL CHANNEL INFO


@pytest.fixture()
def directional_channel_info_data():
    last_update = get_random_int(4)
    enabled = True
    cltv_expiry_delta = get_random_int(2)
    htlc_minimum_msat = get_random_int(8)
    htlc_maximum_msat = get_random_int(8)
    fees = RoutingFees(42, 21)
    last_update_message = None

    return {
        "last_update": last_update,
        "enabled": enabled,
        "cltv_expiry_delta": cltv_expiry_delta,
        "htlc_minimum_msat": htlc_minimum_msat,
        "htlc_maximum_msat": htlc_maximum_msat,
        "fees": fees,
        "last_update_message": last_update_message,
    }


@pytest.fixture()
def directional_channel_info(directional_channel_info_data):
    return DirectionalChannelInfo(
        directional_channel_info_data.get("last_update"),
        directional_channel_info_data.get("enabled"),
        directional_channel_info_data.get("cltv_expiry_delta"),
        directional_channel_info_data.get("htlc_minimum_msat"),
        directional_channel_info_data.get("htlc_maximum_msat"),
        directional_channel_info_data.get("fees"),
        directional_channel_info_data.get("last_update_message"),
    )


@pytest.fixture()
def directional_channel_info_bytes():
    return bytes.fromhex("82e2e662017c65eb1167b367a9c37809d4713d60c8a706390000002a0000001500")


def test_node_announcemet_info(directional_channel_info):
    assert isinstance(directional_channel_info, DirectionalChannelInfo)


def test_node_announcemet_info_from_bytes(directional_channel_info_bytes):
    assert isinstance(DirectionalChannelInfo.from_bytes(directional_channel_info_bytes), DirectionalChannelInfo)


def test_node_announcemet_info_from_serialize(directional_channel_info_bytes):
    chan_info = DirectionalChannelInfo.from_bytes(directional_channel_info_bytes)
    assert chan_info.serialize() == directional_channel_info_bytes


def test_node_announcemet_info_getters(directional_channel_info_data, directional_channel_info):
    assert directional_channel_info.last_update == directional_channel_info_data.get("last_update")
    assert directional_channel_info.enabled == directional_channel_info_data.get("enabled")
    assert directional_channel_info.cltv_expiry_delta == directional_channel_info_data.get("cltv_expiry_delta")
    assert directional_channel_info.htlc_minimum_msat == directional_channel_info_data.get("htlc_minimum_msat")
    assert directional_channel_info.htlc_maximum_msat == directional_channel_info_data.get("htlc_maximum_msat")
    assert directional_channel_info.fees.serialize() == directional_channel_info_data.get("fees").serialize()
    assert directional_channel_info.last_update_message == directional_channel_info_data.get("last_update_message")


def test_node_announcemet_info_str(directional_channel_info):
    # Check casting to str and printig does not fail
    print(str(directional_channel_info))


# CHANNEL INFO
@pytest.fixture
def channel_info_data(directional_channel_info, channel_announcement_bytes):
    features = ChannelFeatures.known()
    node_one = PublicKey(get_random_pk_bytes())
    one_to_two = directional_channel_info
    node_two = PublicKey(get_random_pk_bytes())
    two_to_one = directional_channel_info
    capacity_sats = 42000
    announcement_message = ChannelAnnouncement.from_bytes(channel_announcement_bytes)

    return {
        "features": features,
        "node_one": node_one,
        "one_to_two": one_to_two,
        "node_two": node_two,
        "two_to_one": two_to_one,
        "capacity_sats": capacity_sats,
        "announcement_message": announcement_message,
    }


@pytest.fixture
def channel_info(channel_info_data):
    return ChannelInfo(
        channel_info_data.get("features"),
        channel_info_data.get("node_one"),
        channel_info_data.get("one_to_two"),
        channel_info_data.get("node_two"),
        channel_info_data.get("two_to_one"),
        channel_info_data.get("capacity_sats"),
        channel_info_data.get("announcement_message"),
    )


@pytest.fixture
def channel_info_bytes():
    return bytes.fromhex(
        "0000022a21e9287ce30345534a6524ad9303d88b0005e92c4e8c16a9e57752389a205c22c17c6279011846cca5a5a19e4d6e3c09fcbd04c340212ef70000002a000000150003fb7b913e81629f039d54b661b377d51f523479f79a94140efd578116de2b2bc422c17c6279011846cca5a5a19e4d6e3c09fcbd04c340212ef70000002a000000150009000000000000a410fd01af94e4f56141247d9023a0c8348cc4ca51d81759ff7dac8c9b63291ce6121293bd664d6b9cfb35da16063df08f8a3999a2f25d120f2b421b8b9afe330ceb335e52ee99a10706edf8487ac6e5f55e013a412f18948a3b0a523fbf61a9c54f70eeb87923bb1a447d91e62abca107bc653b02d91db2f23acb7579c666d8c17129df0460f4bf077bb9c211946a28c2ddd87b448f08e3c8d8f481b09f94cbc8c13cc26e3126fc33163be0dea116219f89dd97a441f29f19b1ae82f7859ab78fb7527a72f15e89e18acd40b58ec3ca4276a36e1bf4873530584304d92c505455476f709b421f91fca1db725396c8e5cd0ecba0fe6b087748b7ad4a697cdcd80428359b73000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea3309000000000000000000000000035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c035c4e0dec7215e26833938730e5e505aa62504da85ba57106a46b5a2404fc9d8e02ba72a6e8ba53e8b971ad0c9823968aef4d78ce8af255ab43dff83003c902fb8d0216345bf831164a03758eaea5e8b66fee2be7710b8f190ee880249032a29ed66e"
    )


def test_channel_info(channel_info):
    assert isinstance(channel_info, ChannelInfo)


def test_channel_info_from_bytes(channel_info_bytes):
    assert isinstance(ChannelInfo.from_bytes(channel_info_bytes), ChannelInfo)


def test_channel_info_serialize(channel_info_bytes):
    chan_info = ChannelInfo.from_bytes(channel_info_bytes)
    chan_info.serialize() == channel_info_bytes


def test_channel_info_getters(channel_info, channel_info_data):
    assert channel_info.features.serialize() == channel_info_data.get("features").serialize()
    assert channel_info.node_one.serialize() == channel_info_data.get("node_one").serialize()
    assert channel_info.one_to_two.serialize() == channel_info_data.get("one_to_two").serialize()
    assert channel_info.node_two.serialize() == channel_info_data.get("node_two").serialize()
    assert channel_info.two_to_one.serialize() == channel_info_data.get("two_to_one").serialize()
    assert channel_info.capacity_sats == channel_info_data.get("capacity_sats")
    assert channel_info.announcement_message.serialize() == channel_info_data.get("announcement_message").serialize()


def test_channel_info_str(channel_info):
    # Check that casting to str and printing does not fail
    print(str(channel_info))


# ROUTING FEES
@pytest.fixture
def routing_fees_data():
    base_msat = get_random_int(4)
    proportional_millionths = get_random_int(4)

    return {"base_msat": base_msat, "proportional_millionths": proportional_millionths}


@pytest.fixture
def routing_fees(routing_fees_data):
    return RoutingFees(routing_fees_data.get("base_msat"), routing_fees_data.get("proportional_millionths"))


@pytest.fixture
def routing_fees_bytes():
    return bytes.fromhex("30e9c5cceac1c14f")


def test_routing_fees(routing_fees):
    assert isinstance(routing_fees, RoutingFees)
    print(routing_fees.serialize().hex())


def test_routing_fees_from_bytes(routing_fees_bytes):
    assert isinstance(RoutingFees.from_bytes(routing_fees_bytes), RoutingFees)


def test_routing_fees_serialize(routing_fees_bytes):
    routing_fees = RoutingFees.from_bytes(routing_fees_bytes)
    assert routing_fees.serialize() == routing_fees_bytes


def test_routing_fees_getters(routing_fees_data, routing_fees):
    assert routing_fees.base_msat == routing_fees_data.get("base_msat")
    assert routing_fees.proportional_millionths == routing_fees_data.get("proportional_millionths")


# NODE ANNOUNCEMENT INFO
@pytest.fixture
def node_announcement_info_data(node_announcement_bytes):
    features = NodeFeatures.known()
    last_update = get_random_int(4)
    rgb = get_random_bytes(3)
    alias = get_random_bytes(32)
    addresses = [NetAddress.ipv4([127, 0, 0, 1], 1234)]
    announcement_message = NodeAnnouncement.from_bytes(node_announcement_bytes)

    return {
        "features": features,
        "last_update": last_update,
        "rgb": rgb,
        "alias": alias,
        "addresses": addresses,
        "announcement_message": announcement_message,
    }


@pytest.fixture
def node_announcement_info(node_announcement_info_data):
    return NodeAnnouncementInfo(
        node_announcement_info_data.get("features"),
        node_announcement_info_data.get("last_update"),
        node_announcement_info_data.get("rgb"),
        node_announcement_info_data.get("alias"),
        node_announcement_info_data.get("addresses"),
        node_announcement_info_data.get("announcement_message"),
    )


@pytest.fixture
def node_announcement_info_bytes():
    return bytes.fromhex(
        "00030292223d15eef7cda805fe43c49e149818d11759edc372ae22448b0163c1cd9d2b7d247a8333f7b0b7d20000000000000001017f00000104d2905e398f34f8576a841121ae5e25703be9bd757d857562465a5a86cf8ab831694346fb6c201ea4bab3fd1914719a7cf044dd0f841e28e89a0b295c024e9750b8880003029222000001f4035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c00000000000000000000000000000000000000000000000000000000000000000000000000"
    )


def test_node_announcement_info(node_announcement_info):
    assert isinstance(node_announcement_info, NodeAnnouncementInfo)


def test_node_announcement_info_from_bytes(node_announcement_info_bytes):
    assert isinstance(NodeAnnouncementInfo.from_bytes(node_announcement_info_bytes), NodeAnnouncementInfo)


def test_node_announcement_info_serialize(node_announcement_info_bytes):
    node_announcement_info = NodeAnnouncementInfo.from_bytes(node_announcement_info_bytes)
    assert node_announcement_info.serialize() == node_announcement_info_bytes


def test_node_announcement_info_getters(node_announcement_info, node_announcement_info_data):
    node_announcement_info.features.serialize() == node_announcement_info_data.get("features").serialize()
    node_announcement_info.last_update == node_announcement_info_data.get("last_update")
    node_announcement_info.rgb == node_announcement_info_data.get("rgb")
    node_announcement_info.alias == node_announcement_info_data.get("alias")
    for a1, a2 in zip(node_announcement_info.addresses, node_announcement_info_data.get("addresses")):
        assert a1.serialize() == a2.serialize()
    node_announcement_info.announcement_message.serialize() == node_announcement_info_data.get(
        "announcement_message"
    ).serialize()


# NODE INFO
@pytest.fixture
def node_info_data(routing_fees_bytes, node_announcement_info_bytes):
    channels = [get_random_int(8)]
    lowest_inbound_channel_fees = RoutingFees.from_bytes(routing_fees_bytes)
    announcement_info = NodeAnnouncementInfo.from_bytes(node_announcement_info_bytes)

    return {
        "channels": channels,
        "lowest_inbound_channel_fees": lowest_inbound_channel_fees,
        "announcement_info": announcement_info,
    }


@pytest.fixture
def node_info(node_info_data):
    return NodeInfo(
        node_info_data.get("channels"),
        node_info_data.get("lowest_inbound_channel_fees"),
        node_info_data.get("announcement_info"),
    )


@pytest.fixture
def node_info_bytes():
    return bytes.fromhex(
        "00000000000000011ff39849b4e1357d0930e9c5cceac1c14fcc00030292223d15eef7cda805fe43c49e149818d11759edc372ae22448b0163c1cd9d2b7d247a8333f7b0b7d20000000000000001017f00000104d2905e398f34f8576a841121ae5e25703be9bd757d857562465a5a86cf8ab831694346fb6c201ea4bab3fd1914719a7cf044dd0f841e28e89a0b295c024e9750b8880003029222000001f4035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c00000000000000000000000000000000000000000000000000000000000000000000000000"
    )


def test_node_info(node_info):
    assert isinstance(node_info, NodeInfo)


def test_node_info_from_bytes(node_info_bytes):
    assert isinstance(NodeInfo.from_bytes(node_info_bytes), NodeInfo)


def test_node_info_serialize(node_info_bytes):
    node_info = NodeInfo.from_bytes(node_info_bytes)
    assert node_info.serialize() == node_info_bytes


def test_node_info_getters(node_info_data, node_info):
    for c1, c2 in zip(node_info.channels, node_info_data.get("channels")):
        assert c1 == c2
    assert (
        node_info.lowest_inbound_channel_fees.serialize()
        == node_info_data.get("lowest_inbound_channel_fees").serialize()
    )
    assert node_info.announcement_info.serialize() == node_info_data.get("announcement_info").serialize()


def test_node_info_str(node_info):
    # Check that casting to str and printing does not fail
    print(str(node_info))