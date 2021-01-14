import pytest
from random import randint
from conftest import get_random_bytes, get_random_int, get_random_pk_bytes

from python_tests.chain.test_chain import W
from python_tests.test_logger import Logger
from python_tests.chain.test_chaininterface import FeeEst
from python_tests.chain.test_chaininterface import Broadcaster
from python_tests.chain.test_keysinterface import keys_manager

from ldk_python.chain import Watch
from ldk_python.util.errors import *
from ldk_python.logger import LDKLogger
from ldk_python.ln.channelmanager import *
from ldk_python.util.config import UserConfig
from ldk_python.routing.router import Route, RouteHop
from ldk_python.primitives import Network, OutPoint, PublicKey
from ldk_python.ln.features import InitFeatures, NodeFeatures, ChannelFeatures
from ldk_python.chain.chaininterface import FeeEstimator, BroadcasterInterface


def test_exceptions():
    # Test that all expected exceptions ara available and that the inheritance applies.
    payment_send_failure = PaymentSendFailure()
    parameter_error = ParameterError()
    path_parameter_error = PathParameterError()
    all_failed_retry_safe = AllFailedRetrySafe()
    partial_failure = PartialFailure()

    assert isinstance(payment_send_failure, PaymentSendFailure)
    assert isinstance(parameter_error, ParameterError) and isinstance(parameter_error, PaymentSendFailure)
    assert isinstance(path_parameter_error, PathParameterError) and isinstance(path_parameter_error, PaymentSendFailure)
    assert isinstance(all_failed_retry_safe, AllFailedRetrySafe) and isinstance(
        all_failed_retry_safe, PaymentSendFailure
    )
    assert isinstance(partial_failure, PartialFailure) and isinstance(partial_failure, PaymentSendFailure)


# PAYMENT PREIMAGE


def test_payment_preimage():
    assert isinstance(PaymentPreimage(get_random_bytes(32)), PaymentPreimage)


def test_payment_preimage_seralize():
    raw_preimage = get_random_bytes(32)

    assert PaymentPreimage(raw_preimage).serialize() == raw_preimage


def test_payment_preimage_str():
    raw_preimage = get_random_bytes(32)

    assert str(PaymentPreimage(raw_preimage)) == raw_preimage.hex()


# PAYMENT SECRET


def test_payment_secret():
    assert isinstance(PaymentSecret(get_random_bytes(32)), PaymentSecret)


def test_payment_secret_seralize():
    raw_secret = get_random_bytes(32)

    assert PaymentSecret(raw_secret).serialize() == raw_secret


def test_payment_preimage_str():
    raw_secret = get_random_bytes(32)

    assert str(PaymentSecret(raw_secret)) == raw_secret.hex()


# PAYMENT HASH


def test_payment_hash():
    assert isinstance(PaymentHash(get_random_bytes(32)), PaymentHash)


def test_payment_hash_seralize():
    raw_hash = get_random_bytes(32)

    assert PaymentHash(raw_hash).serialize() == raw_hash


def test_payment_hash_str():
    raw_hash = get_random_bytes(32)

    assert str(PaymentHash(raw_hash)) == raw_hash.hex()


# CHANNEL DETAILS


@pytest.fixture
def channel_details_data():
    channel_id = get_random_bytes(32)
    short_channel_id = None
    remote_network_id = PublicKey(get_random_pk_bytes())
    counterparty_features = InitFeatures.known()
    channel_value_satoshis = 100000
    user_id = 42
    outbound_capacity_msat = 1000 * channel_value_satoshis // 2
    inbound_capacity_msat = outbound_capacity_msat
    is_live = True

    return (
        channel_id,
        short_channel_id,
        remote_network_id,
        counterparty_features,
        channel_value_satoshis,
        user_id,
        outbound_capacity_msat,
        inbound_capacity_msat,
        is_live,
    )


def test_channel_details(channel_details_data):
    (
        channel_id,
        short_channel_id,
        remote_network_id,
        counterparty_features,
        channel_value_satoshis,
        user_id,
        outbound_capacity_msat,
        inbound_capacity_msat,
        is_live,
    ) = channel_details_data

    assert isinstance(
        ChannelDetails(
            channel_id,
            short_channel_id,
            remote_network_id,
            counterparty_features,
            channel_value_satoshis,
            user_id,
            outbound_capacity_msat,
            inbound_capacity_msat,
            is_live,
        ),
        ChannelDetails,
    )


def test_test_channel_details_getters(channel_details_data):
    (
        channel_id,
        short_channel_id,
        remote_network_id,
        counterparty_features,
        channel_value_satoshis,
        user_id,
        outbound_capacity_msat,
        inbound_capacity_msat,
        is_live,
    ) = channel_details_data

    channel_details = ChannelDetails(
        channel_id,
        short_channel_id,
        remote_network_id,
        counterparty_features,
        channel_value_satoshis,
        user_id,
        outbound_capacity_msat,
        inbound_capacity_msat,
        is_live,
    )

    assert channel_details.channel_id == channel_id
    assert channel_details.short_channel_id == short_channel_id
    assert channel_details.remote_network_id.serialize() == remote_network_id.serialize()
    # FIXME: Features cannot be compared atm
    # assert channel_details.counterparty_features == counterparty_features
    assert channel_details.channel_value_satoshis == channel_value_satoshis
    assert channel_details.outbound_capacity_msat == outbound_capacity_msat
    assert channel_details.inbound_capacity_msat == inbound_capacity_msat
    assert channel_details.is_live == is_live


# CHANNEL MANAGER


@pytest.fixture()
def fee_estimator():
    return FeeEstimator(FeeEst())


@pytest.fixture()
def watch():
    return Watch(W())


@pytest.fixture()
def broadcaster_interface():
    return BroadcasterInterface(Broadcaster())


@pytest.fixture()
def logger():
    return LDKLogger(Logger())


@pytest.fixture()
def channel_manager(fee_estimator, watch, broadcaster_interface, logger, keys_manager):
    network = Network.regtest()
    config = UserConfig.default()
    current_blockchain_height = 100

    return ChannelManager(
        network,
        fee_estimator,
        watch,
        broadcaster_interface,
        logger,
        keys_manager,
        config,
        current_blockchain_height,
    )


def create_channel(channel_manager):
    their_net_key = PublicKey(get_random_pk_bytes())
    channel_value_satoshis = 16777215
    push_msat = 42
    user_id = get_random_int(8)

    return channel_manager.create_channel(their_net_key, channel_value_satoshis, push_msat, user_id, None)


def create_hop(pk, short_chan_id):
    nfeatures = NodeFeatures.known()
    cfeatures = ChannelFeatures.known()
    fee_msat = 42
    cltv_expiry_delta = 7

    return RouteHop(pk, nfeatures, short_chan_id, cfeatures, fee_msat, cltv_expiry_delta)


def get_random_route(first_hop_pk):
    # Get a random numbert of hops [1-7]
    hops = []
    for i in range(randint(0, 7) + 1):
        pk = PublicKey(get_random_pk_bytes())
        short_chan_id = get_random_int(8)
        hops.append(create_hop(pk, short_chan_id))
    return Route([hops])


def test_channel_manager(channel_manager):
    assert isinstance(channel_manager, ChannelManager)


def test_create_channel(channel_manager):
    # Checks there's no error returned
    assert create_channel(channel_manager) == None


def test_list_channels(channel_manager):
    # List channels with no added channels must be an empty list
    assert channel_manager.list_channels() == []

    # If we add a new channel, it should show up.
    create_channel(channel_manager)
    assert len(channel_manager.list_channels()) == 1
    assert isinstance(channel_manager.list_channels()[0], ChannelDetails)


def test_list_usable_channels(channel_manager):
    # List usable channels with no added channels must be an empty list
    # FIXME: Check how to trigger is_live = True and fill this test
    pass


def test_close_channel(channel_manager):
    create_channel(channel_manager)
    chan_id = channel_manager.list_channels()[0].channel_id
    channel_manager.close_channel(chan_id)
    assert len(channel_manager.list_channels()) == 0


def test_close_channel_non_existent(channel_manager):
    with pytest.raises(ChannelUnavailable):
        channel_manager.close_channel(get_random_bytes(32))


def test_force_close_channel(channel_manager):
    create_channel(channel_manager)
    chan_id = channel_manager.list_channels()[0].channel_id
    channel_manager.force_close_channel(chan_id)
    assert len(channel_manager.list_channels()) == 0


def test_force_close_channel_non_existent(channel_manager):
    # FIXME: Force close does not raise errors if the channel does not exist
    # Check why and if this can be tested as a blackblock then
    # with pytest.raises(ChannelUnavailable):
    #     channel_manager.force_close_channel(get_random_bytes(32))
    pass


def test_force_close_all_channels(channel_manager):
    for i in range(10):
        create_channel(channel_manager)

    assert len(channel_manager.list_channels()) == 10
    channel_manager.force_close_all_channels()
    assert len(channel_manager.list_usable_channels()) == 0


# FIXME: There are multiple tests missing here. May need additional components to test some of the functionality. Leaving it from where they are implemented.