import pytest
from conftest import get_random_bytes, get_random_int, check_not_available_getters

from ldk_python.ln.channelmanager import PaymentHash, PaymentPreimage
from ldk_python.primitives import Script, OutPoint, TxOut
from ldk_python.util.events import Event
from ldk_python.chain.keysinterface import SpendableOutputDescriptor

all_attributes = set(
    [
        "temporary_channel_id",
        "channel_value_satoshis",
        "output_script",
        "user_channel_id",
        "funding_txo",
        "payment_hash",
        "payment_secret",
        "amt",
        "payment_preimage",
        "rejected_by_dest",
        "time_forwardable",
        "outputs",
    ]
)


def test_funding_generation_ready():
    temporary_channel_id = get_random_bytes(32)
    channel_value_satoshis = 42
    output_script = Script(get_random_bytes(50))
    user_channel_id = get_random_int(8)
    event = Event.funding_generation_ready(temporary_channel_id, channel_value_satoshis, output_script, user_channel_id)
    assert isinstance(event, Event) and event.type == "FundingGenerationReady"


def test_funding_generation_ready_getters():
    temporary_channel_id = get_random_bytes(32)
    channel_value_satoshis = 42
    output_script = Script(get_random_bytes(50))
    user_channel_id = get_random_int(8)
    event = Event.funding_generation_ready(temporary_channel_id, channel_value_satoshis, output_script, user_channel_id)

    assert event.temporary_channel_id == temporary_channel_id
    assert event.channel_value_satoshis == channel_value_satoshis
    assert event.output_script.serialize() == output_script.serialize()
    assert event.user_channel_id == user_channel_id

    # Check no other getters are available
    local_attributes = ["temporary_channel_id", "channel_value_satoshis", "output_script", "user_channel_id"]
    check_not_available_getters(event, local_attributes, all_attributes)


def test_funding_broadcasting_safe():
    outpoint = OutPoint.from_bytes(get_random_bytes(36))
    user_channel_id = get_random_int(8)
    event = Event.funding_broadcasting_safe(outpoint, user_channel_id)
    assert isinstance(event, Event) and event.type == "FundingBroadcastSafe"


def test_funding_broadcasting_safe_getters():
    outpoint = OutPoint.from_bytes(get_random_bytes(36))
    user_channel_id = get_random_int(8)
    event = Event.funding_broadcasting_safe(outpoint, user_channel_id)

    assert event.funding_txo.serialize() == outpoint.serialize()
    assert event.user_channel_id == user_channel_id

    # Check no other getters are available
    local_attributes = ["funding_txo", "user_channel_id"]
    check_not_available_getters(event, local_attributes, all_attributes)


def test_payment_received():
    payment_hash = PaymentHash(get_random_bytes(32))
    payment_secret = None
    amt = get_random_int(8)
    event = Event.payment_received(payment_hash, payment_secret, amt)
    assert isinstance(event, Event) and event.type == "PaymentReceived"


def test_payment_received_getters():
    payment_hash = PaymentHash(get_random_bytes(32))
    payment_secret = None
    amt = get_random_int(8)
    event = Event.payment_received(payment_hash, payment_secret, amt)

    assert event.payment_hash.serialize() == payment_hash.serialize()
    assert event.payment_secret == payment_secret
    assert event.amt == amt

    # Check no other getters are available
    local_attributes = ["payment_hash", "payment_secret", "amt"]
    check_not_available_getters(event, local_attributes, all_attributes)


def test_payment_sent():
    payment_preimage = PaymentPreimage(get_random_bytes(32))
    event = Event.payment_sent(payment_preimage)
    assert isinstance(event, Event) and event.type == "PaymentSent"


def test_payment_sent_getters():
    payment_preimage = PaymentPreimage(get_random_bytes(32))
    event = Event.payment_sent(payment_preimage)

    assert event.payment_preimage.serialize() == payment_preimage.serialize()

    # Check no other getters are available
    local_attributes = ["payment_preimage"]
    check_not_available_getters(event, local_attributes, all_attributes)


def test_payment_failed():
    payment_hash = PaymentHash(get_random_bytes(32))
    rejected_by_dest = True
    event = Event.payment_failed(payment_hash, rejected_by_dest)
    assert isinstance(event, Event) and event.type == "PaymentFailed"


def test_payment_failed_getters():
    payment_hash = PaymentHash(get_random_bytes(32))
    rejected_by_dest = True
    event = Event.payment_failed(payment_hash, rejected_by_dest)

    assert event.payment_hash.serialize() == payment_hash.serialize()
    assert event.rejected_by_dest == rejected_by_dest

    # Check no other getters are available
    local_attributes = ["payment_hash", "rejected_by_dest"]
    check_not_available_getters(event, local_attributes, all_attributes)


def test_pending_htlcs_forwardable():
    secs = get_random_int(8)
    nanos = get_random_int(4)
    event = Event.pending_htlcs_forwardable(secs, nanos)
    assert isinstance(event, Event) and event.type == "PendingHTLCsForwardable"


def test_pending_htlcs_forwardable():
    secs = get_random_int(8)
    nanos = get_random_int(4)

    # Make sure nanos does not go all the way to seconds
    while nanos > 100000000:
        secs = +1
        nanos -= 100000000

    event = Event.pending_htlcs_forwardable(secs, nanos)
    assert event.time_forwardable == (secs, nanos)

    # Check no other getters are available
    local_attributes = ["time_forwardable"]
    check_not_available_getters(event, local_attributes, all_attributes)


def test_spendable_outputs():
    outpoint = OutPoint.from_bytes(get_random_bytes(36))
    output = TxOut(get_random_int(8), Script(get_random_bytes(50)))
    descriptor = SpendableOutputDescriptor.static_output(outpoint, output)
    event = Event.spendable_outputs([descriptor])
    assert isinstance(event, Event) and event.type == "SpendableOutputs"


def test_spendable_outputs_getters():
    outpoint = OutPoint.from_bytes(get_random_bytes(36))
    output = TxOut(get_random_int(8), Script(get_random_bytes(50)))
    descriptor = SpendableOutputDescriptor.static_output(outpoint, output)
    event = Event.spendable_outputs([descriptor])

    for local_output, binded_output in zip(event.outputs, [descriptor]):
        assert local_output.type == binded_output.type
        assert local_output.outpoint.serialize() == binded_output.outpoint.serialize()
        assert local_output.output.serialize() == binded_output.output.serialize()