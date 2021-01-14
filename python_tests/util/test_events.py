from conftest import get_random_bytes, get_random_int

from ldk_python.ln.channelmanager import PaymentHash
from ldk_python.primitives import Script, OutPoint, TxOut
from ldk_python.util.events import Event
from ldk_python.chain.keysinterface import SpendableOutputDescriptor


def test_funding_generation_ready():
    temporary_channel_id = get_random_bytes(32)
    channel_value_satoshis = 42
    output_script = Script(get_random_bytes(50))
    user_channel_id = get_random_int(8)
    event = Event.funding_generation_ready(temporary_channel_id, channel_value_satoshis, output_script, user_channel_id)
    assert isinstance(event, Event) and event.type == "FundingGenerationReady"


def test_funding_broadcasting_safe():
    outpoint = OutPoint.from_bytes(get_random_bytes(36))
    user_channel_id = get_random_int(8)
    event = Event.funding_broadcasting_safe(outpoint, user_channel_id)
    assert isinstance(event, Event) and event.type == "FundingBroadcastSafe"


def test_payment_received():
    payment_hash = PaymentHash(get_random_bytes(32))
    amt = get_random_int(8)
    event = Event.payment_received(payment_hash, None, amt)
    assert isinstance(event, Event) and event.type == "PaymentReceived"


def test_payment_failed():
    payment_hash = PaymentHash(get_random_bytes(32))
    rejected_by_dest = True
    event = Event.payment_failed(payment_hash, rejected_by_dest)
    assert isinstance(event, Event) and event.type == "PaymentFailed"


def test_pending_htlcs_forwardable():
    secs = get_random_int(8)
    nanos = get_random_int(4)
    event = Event.pending_htlcs_forwardable(secs, nanos)
    assert isinstance(event, Event) and event.type == "PendingHTLCsForwardable"


def test_spendable_outputs():
    outpoint = OutPoint.from_bytes(get_random_bytes(36))
    output = TxOut(get_random_int(8), Script(get_random_bytes(50)))
    descriptor = SpendableOutputDescriptor.static_output(outpoint, output)
    event = Event.spendable_outputs([descriptor])
    assert isinstance(event, Event) and event.type == "SpendableOutputs"
