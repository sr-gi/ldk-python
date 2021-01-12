import pytest
import time
from ldk_python.chain.keysinterface import *
from ldk_python.primitives import SecretKey, Network
from conftest import get_random_sk_bytes


@pytest.fixture
def in_mem_chan_keys():
    sk = SecretKey(get_random_sk_bytes())
    commitment_seed = get_random_sk_bytes()
    channel_value_satoshis = pow(2, 64) - 1
    key_derivation_params = (0, 1)

    return InMemoryChannelKeys(sk, sk, sk, sk, sk, commitment_seed, channel_value_satoshis, key_derivation_params)


@pytest.fixture
def keys_manager():
    seed = get_random_sk_bytes()
    network = Network.mainnet()
    s_time_sec, s_time_nsec = str(time.time()).split(".")

    return KeysManager(seed, network, int(s_time_sec), int(s_time_nsec))


def test_in_memory_channel_keys(in_mem_chan_keys):
    assert isinstance(in_mem_chan_keys, InMemoryChannelKeys)


def test_in_memory_channel_keys_getters():
    funding_key = SecretKey(get_random_sk_bytes())
    revocation_base_key = SecretKey(get_random_sk_bytes())
    payment_key = SecretKey(get_random_sk_bytes())
    delayed_payment_base_key = SecretKey(get_random_sk_bytes())
    htlc_base_key = SecretKey(get_random_sk_bytes())
    commitment_seed = get_random_sk_bytes()
    channel_value_satoshis = pow(2, 64) - 1
    key_derivation_params = (0, 1)

    in_mem_chan_keys = InMemoryChannelKeys(
        funding_key,
        revocation_base_key,
        payment_key,
        delayed_payment_base_key,
        htlc_base_key,
        commitment_seed,
        channel_value_satoshis,
        key_derivation_params,
    )

    assert in_mem_chan_keys.funding_key.serialize() == funding_key.serialize()
    assert in_mem_chan_keys.revocation_base_key.serialize() == revocation_base_key.serialize()
    assert in_mem_chan_keys.payment_key.serialize() == payment_key.serialize()
    assert in_mem_chan_keys.delayed_payment_base_key.serialize() == delayed_payment_base_key.serialize()
    assert in_mem_chan_keys.htlc_base_key.serialize() == htlc_base_key.serialize()
    assert in_mem_chan_keys.commitment_seed == commitment_seed


# FIXME: I don't think there's any way to call on_accept from outside the crate
# Testing the exceptions work for now at least
def test_counterparty_pubkeys_on_not_accepted(in_mem_chan_keys):
    with pytest.raises(RuntimeError, match="method can only be called for accepted channels"):
        in_mem_chan_keys.counterparty_pubkeys()


def test_counterparty_selected_contest_delay_on_not_accepted(in_mem_chan_keys):
    with pytest.raises(RuntimeError, match="method can only be called for accepted channels"):
        in_mem_chan_keys.counterparty_selected_contest_delay()


def test_holder_selected_contest_delay_on_not_accepted(in_mem_chan_keys):
    with pytest.raises(RuntimeError, match="method can only be called for accepted channels"):
        in_mem_chan_keys.holder_selected_contest_delay()


def test_keys_manager(keys_manager):
    assert isinstance(keys_manager, KeysManager)


def test_derive_channel_keys(keys_manager):
    assert isinstance(keys_manager.derive_channel_keys(1, 2, 3), InMemoryChannelKeys)