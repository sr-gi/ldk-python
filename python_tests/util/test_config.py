import pytest
from ldk_python.util.config import *


@pytest.fixture
def chan_hs_config_values():
    minimum_depth = 30
    our_to_self_delay = 100
    our_htlc_minimum_msat = 1000
    return minimum_depth, our_to_self_delay, our_htlc_minimum_msat


@pytest.fixture
def chan_hs_config(chan_hs_config_values):
    minimum_depth, our_to_self_delay, our_htlc_minimum_msat = chan_hs_config_values
    return ChannelHandshakeConfig(minimum_depth, our_to_self_delay, our_htlc_minimum_msat)


@pytest.fixture
def chan_hs_limits_values():
    min_funding_satoshis = 200
    max_htlc_minimum_msat = pow(2, 64) // 2
    min_max_htlc_value_in_flight_msat = 500
    max_channel_reserve_satoshis = pow(2, 64) // 2 + 1
    min_max_accepted_htlcs = 5
    min_dust_limit_satoshis = 546 * 2
    max_dust_limit_satoshis = pow(2, 64) // 2 + 2
    max_minimum_depth = 150
    force_announced_channel_preference = True
    their_to_self_delay = 504

    return (
        min_funding_satoshis,
        max_htlc_minimum_msat,
        min_max_htlc_value_in_flight_msat,
        max_channel_reserve_satoshis,
        min_max_accepted_htlcs,
        min_dust_limit_satoshis,
        max_dust_limit_satoshis,
        max_minimum_depth,
        force_announced_channel_preference,
        their_to_self_delay,
    )


@pytest.fixture
def chan_hs_limits(chan_hs_limits_values):
    (
        min_funding_satoshis,
        max_htlc_minimum_msat,
        min_max_htlc_value_in_flight_msat,
        max_channel_reserve_satoshis,
        min_max_accepted_htlcs,
        min_dust_limit_satoshis,
        max_dust_limit_satoshis,
        max_minimum_depth,
        force_announced_channel_preference,
        their_to_self_delay,
    ) = chan_hs_limits_values

    return ChannelHandshakeLimits(
        min_funding_satoshis,
        max_htlc_minimum_msat,
        min_max_htlc_value_in_flight_msat,
        max_channel_reserve_satoshis,
        min_max_accepted_htlcs,
        min_dust_limit_satoshis,
        max_dust_limit_satoshis,
        max_minimum_depth,
        force_announced_channel_preference,
        their_to_self_delay,
    )


@pytest.fixture
def chan_config_values():
    fee_proportional_millionths = 1000
    announced_channel = True
    commit_upfront_shutdown_pubkey = False

    return fee_proportional_millionths, announced_channel, commit_upfront_shutdown_pubkey


@pytest.fixture
def chan_config(chan_config_values):
    fee_proportional_millionths, announced_channel, commit_upfront_shutdown_pubkey = chan_config_values
    return ChannelConfig(fee_proportional_millionths, announced_channel, commit_upfront_shutdown_pubkey)


def test_channel_hs_config(chan_hs_config):
    assert isinstance(chan_hs_config, ChannelHandshakeConfig)


def test_channel_hs_config_default():
    assert isinstance(ChannelHandshakeConfig.default(), ChannelHandshakeConfig)


def test_channel_hs_config_getters(chan_hs_config, chan_hs_config_values):
    minimum_depth, our_to_self_delay, our_htlc_minimum_msat = chan_hs_config_values
    assert chan_hs_config.minimum_depth == minimum_depth
    assert chan_hs_config.our_to_self_delay == our_to_self_delay
    assert our_htlc_minimum_msat == our_htlc_minimum_msat


def test_channel_hs_limits(chan_hs_limits):
    assert isinstance(chan_hs_limits, ChannelHandshakeLimits)


def test_channel_hs_limits_default():
    assert isinstance(ChannelHandshakeLimits.default(), ChannelHandshakeLimits)


def test_channel_hs_climits_getters(chan_hs_limits, chan_hs_limits_values):
    (
        min_funding_satoshis,
        max_htlc_minimum_msat,
        min_max_htlc_value_in_flight_msat,
        max_channel_reserve_satoshis,
        min_max_accepted_htlcs,
        min_dust_limit_satoshis,
        max_dust_limit_satoshis,
        max_minimum_depth,
        force_announced_channel_preference,
        their_to_self_delay,
    ) = chan_hs_limits_values

    assert chan_hs_limits.min_funding_satoshis == min_funding_satoshis
    assert chan_hs_limits.max_htlc_minimum_msat == max_htlc_minimum_msat
    assert chan_hs_limits.min_max_htlc_value_in_flight_msat == min_max_htlc_value_in_flight_msat
    assert chan_hs_limits.max_channel_reserve_satoshis == max_channel_reserve_satoshis
    assert chan_hs_limits.min_max_accepted_htlcs == min_max_accepted_htlcs
    assert chan_hs_limits.min_dust_limit_satoshis == min_dust_limit_satoshis
    assert chan_hs_limits.max_dust_limit_satoshis == max_dust_limit_satoshis
    assert chan_hs_limits.max_minimum_depth == max_minimum_depth
    assert chan_hs_limits.force_announced_channel_preference == force_announced_channel_preference
    assert chan_hs_limits.their_to_self_delay == their_to_self_delay


def test_channel_config(chan_config):
    assert isinstance(chan_config, ChannelConfig)


def test_channel_config_default():
    assert isinstance(ChannelConfig.default(), ChannelConfig)


def test_channel_config_getters(chan_config, chan_config_values):
    fee_proportional_millionths, announced_channel, commit_upfront_shutdown_pubkey = chan_config_values

    assert chan_config.fee_proportional_millionths == fee_proportional_millionths
    assert chan_config.announced_channel == announced_channel
    assert chan_config.commit_upfront_shutdown_pubkey == commit_upfront_shutdown_pubkey


def test_channel_config(chan_hs_config, chan_hs_limits, chan_config):
    assert isinstance(UserConfig(chan_hs_config, chan_hs_limits, chan_config), UserConfig)


def test_channel_config_default():
    assert isinstance(UserConfig.default(), UserConfig)


# FIXME: Can be simplified once equal operations are implemented.
# Currently it copies the internal comparison of each component
def test_channel_config_getters(
    chan_hs_config, chan_hs_limits, chan_config, chan_hs_config_values, chan_hs_limits_values, chan_config_values
):
    user_config = UserConfig(chan_hs_config, chan_hs_limits, chan_config)

    minimum_depth, our_to_self_delay, our_htlc_minimum_msat = chan_hs_config_values
    assert user_config.own_channel_config.minimum_depth == minimum_depth
    assert user_config.own_channel_config.our_to_self_delay == our_to_self_delay
    assert user_config.own_channel_config.our_htlc_minimum_msat == our_htlc_minimum_msat

    (
        min_funding_satoshis,
        max_htlc_minimum_msat,
        min_max_htlc_value_in_flight_msat,
        max_channel_reserve_satoshis,
        min_max_accepted_htlcs,
        min_dust_limit_satoshis,
        max_dust_limit_satoshis,
        max_minimum_depth,
        force_announced_channel_preference,
        their_to_self_delay,
    ) = chan_hs_limits_values

    assert user_config.peer_channel_config_limits.min_funding_satoshis == min_funding_satoshis
    assert user_config.peer_channel_config_limits.max_htlc_minimum_msat == max_htlc_minimum_msat
    assert user_config.peer_channel_config_limits.min_max_htlc_value_in_flight_msat == min_max_htlc_value_in_flight_msat
    assert user_config.peer_channel_config_limits.max_channel_reserve_satoshis == max_channel_reserve_satoshis
    assert user_config.peer_channel_config_limits.min_max_accepted_htlcs == min_max_accepted_htlcs
    assert user_config.peer_channel_config_limits.min_dust_limit_satoshis == min_dust_limit_satoshis
    assert user_config.peer_channel_config_limits.max_dust_limit_satoshis == max_dust_limit_satoshis
    assert user_config.peer_channel_config_limits.max_minimum_depth == max_minimum_depth
    assert (
        user_config.peer_channel_config_limits.force_announced_channel_preference == force_announced_channel_preference
    )
    assert user_config.peer_channel_config_limits.their_to_self_delay == their_to_self_delay

    fee_proportional_millionths, announced_channel, commit_upfront_shutdown_pubkey = chan_config_values

    assert user_config.channel_options.fee_proportional_millionths == fee_proportional_millionths
    assert user_config.channel_options.announced_channel == announced_channel
    assert user_config.channel_options.commit_upfront_shutdown_pubkey == commit_upfront_shutdown_pubkey