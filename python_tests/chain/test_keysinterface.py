import pytest
import time
from ldk_python.chain.keysinterface import *
from ldk_python.primitives import SecretKey, Network, OutPoint, TxOut, Script, PublicKey
from conftest import (
    get_random_sk_bytes,
    get_random_bytes,
    get_random_pk_bytes,
    get_random_int,
    check_not_available_getters,
)


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


# SpendableOutputDescriptor

all_attributes = set(
    [
        "outpoint",
        "output",
        "per_commitment_point",
        "to_self_delay",
        "key_derivation_params",
        "revocation_pubkey",
    ]
)


def test_static_output():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    txout = TxOut(get_random_int(8), Script(get_random_bytes(30)))
    descriptor = SpendableOutputDescriptor.static_output(outpoint, txout)

    assert isinstance(descriptor, SpendableOutputDescriptor) and descriptor.type == "StaticOutput"


def test_static_output_getters():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    txout = TxOut(get_random_int(8), Script(get_random_bytes(30)))
    descriptor = SpendableOutputDescriptor.static_output(outpoint, txout)

    assert descriptor.outpoint == outpoint
    assert descriptor.output == txout

    # Check no other getters are available
    local_attributes = ["outpoint", "output"]

    check_not_available_getters(descriptor, local_attributes, all_attributes)


def test_dynamic_output_pwsh():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    per_commitment_point = PublicKey(get_random_pk_bytes())
    to_self_delay = 20
    txout = TxOut(get_random_int(8), Script(get_random_bytes(30)))
    key_derivation_params = (get_random_int(8), get_random_int(8))
    revocation_pubkey = PublicKey(get_random_pk_bytes())
    descriptor = SpendableOutputDescriptor.dynamic_output_pwsh(
        outpoint, per_commitment_point, to_self_delay, txout, key_derivation_params, revocation_pubkey
    )

    assert isinstance(descriptor, SpendableOutputDescriptor) and descriptor.type == "DynamicOutputP2WSH"


def test_dynamic_output_pwsh_getters():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    per_commitment_point = PublicKey(get_random_pk_bytes())
    to_self_delay = 20
    txout = TxOut(get_random_int(8), Script(get_random_bytes(30)))
    key_derivation_params = (get_random_int(8), get_random_int(8))
    revocation_pubkey = PublicKey(get_random_pk_bytes())
    descriptor = SpendableOutputDescriptor.dynamic_output_pwsh(
        outpoint, per_commitment_point, to_self_delay, txout, key_derivation_params, revocation_pubkey
    )

    assert descriptor.outpoint == outpoint
    assert descriptor.per_commitment_point == per_commitment_point
    assert descriptor.to_self_delay == to_self_delay
    assert descriptor.output == txout
    assert descriptor.key_derivation_params == key_derivation_params
    assert descriptor.revocation_pubkey == revocation_pubkey

    # This one has all atributes, no need to check the ones that are not there


def test_static_output_counterparty_payment():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    txout = TxOut(get_random_int(8), Script(get_random_bytes(30)))
    key_derivation_params = (get_random_int(8), get_random_int(8))
    descriptor = SpendableOutputDescriptor.static_output_counterparty_payment(outpoint, txout, key_derivation_params)

    assert isinstance(descriptor, SpendableOutputDescriptor) and descriptor.type == "StaticOutputCounterpartyPayment"


def test_static_output_counterparty_payment_getters():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    txout = TxOut(get_random_int(8), Script(get_random_bytes(30)))
    key_derivation_params = (get_random_int(8), get_random_int(8))
    descriptor = SpendableOutputDescriptor.static_output_counterparty_payment(outpoint, txout, key_derivation_params)

    assert descriptor.outpoint == outpoint
    assert descriptor.output == txout
    assert descriptor.key_derivation_params == key_derivation_params

    # Check no other getters are available
    local_attributes = ["outpoint", "output", "key_derivation_params"]

    check_not_available_getters(descriptor, local_attributes, all_attributes)


# InMemoryChannelKeys


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

    assert in_mem_chan_keys.funding_key == funding_key
    assert in_mem_chan_keys.revocation_base_key == revocation_base_key
    assert in_mem_chan_keys.payment_key == payment_key
    assert in_mem_chan_keys.delayed_payment_base_key == delayed_payment_base_key
    assert in_mem_chan_keys.htlc_base_key == htlc_base_key
    assert in_mem_chan_keys.commitment_seed == commitment_seed


# FIXME: I don't think there's any way to call on_accept from outside the crate
# Testing the exceptions work for now at least
# #PANIC-ERROR
def test_counterparty_pubkeys_on_not_accepted(in_mem_chan_keys):
    with pytest.raises(BaseException, match="Option::unwrap()"):
        in_mem_chan_keys.counterparty_pubkeys()


def test_counterparty_selected_contest_delay_on_not_accepted(in_mem_chan_keys):
    with pytest.raises(BaseException, match="Option::unwrap()"):
        in_mem_chan_keys.counterparty_selected_contest_delay()


def test_holder_selected_contest_delay_on_not_accepted(in_mem_chan_keys):
    with pytest.raises(BaseException, match="Option::unwrap()"):
        in_mem_chan_keys.holder_selected_contest_delay()


def test_keys_manager(keys_manager):
    assert isinstance(keys_manager, KeysManager)


def test_derive_channel_keys(keys_manager):
    assert isinstance(keys_manager.derive_channel_keys(1, 2, 3), InMemoryChannelKeys)
