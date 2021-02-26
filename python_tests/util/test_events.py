import pytest
from conftest import get_random_bytes, get_random_int, check_not_available_getters
from python_tests.ln.test_msgs import *

from ldk_python.ln.channelmanager import PaymentHash, PaymentPreimage
from ldk_python.primitives import Script, OutPoint, TxOut
from ldk_python.util.events import Event, MessageSendEvent
from ldk_python.chain.keysinterface import SpendableOutputDescriptor
from ldk_python.ln.msgs import *

# EVENT
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
    assert event.output_script == output_script
    assert event.user_channel_id == user_channel_id

    # Check no other getters are available
    local_attributes = ["temporary_channel_id", "channel_value_satoshis", "output_script", "user_channel_id"]
    check_not_available_getters(event, local_attributes, all_attributes)


def test_funding_broadcasting_safe():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    user_channel_id = get_random_int(8)
    event = Event.funding_broadcasting_safe(outpoint, user_channel_id)
    assert isinstance(event, Event) and event.type == "FundingBroadcastSafe"


def test_funding_broadcasting_safe_getters():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    user_channel_id = get_random_int(8)
    event = Event.funding_broadcasting_safe(outpoint, user_channel_id)

    assert event.funding_txo == outpoint
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
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    output = TxOut(get_random_int(8), Script(get_random_bytes(50)))
    descriptor = SpendableOutputDescriptor.static_output(outpoint, output)
    event = Event.spendable_outputs([descriptor])
    assert isinstance(event, Event) and event.type == "SpendableOutputs"


def test_spendable_outputs_getters():
    outpoint = OutPoint.from_bytes(get_random_bytes(34))
    output = TxOut(get_random_int(8), Script(get_random_bytes(50)))
    descriptor = SpendableOutputDescriptor.static_output(outpoint, output)
    event = Event.spendable_outputs([descriptor])

    for local_output, binded_output in zip(event.outputs, [descriptor]):
        assert local_output.type == binded_output.type
        assert local_output.outpoint == binded_output.outpoint
        assert local_output.output == binded_output.output


# MESSAGE SEND EVENT
def test_send_accept_channel(accept_channel_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = AcceptChannel.from_bytes(accept_channel_bytes)
    event = MessageSendEvent.send_accept_channel(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendAcceptChannel"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_open_channel(open_channel_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = OpenChannel.from_bytes(open_channel_bytes)
    event = MessageSendEvent.send_open_channel(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendOpenChannel"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_funding_created(funding_created_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = FundingCreated.from_bytes(funding_created_bytes)
    event = MessageSendEvent.send_funding_created(node_id, msg)
    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_funding_signed(funding_signed_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = FundingSigned.from_bytes(funding_signed_bytes)
    event = MessageSendEvent.send_funding_signed(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendFundingSigned"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_funding_locked(funding_locked_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = FundingLocked.from_bytes(funding_locked_bytes)
    event = MessageSendEvent.send_funding_locked(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendFundingLocked"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_announcement_signatures(announcement_signatures_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = AnnouncementSignatures.from_bytes(announcement_signatures_bytes)
    event = MessageSendEvent.send_announcement_signatures(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendAnnouncementSignatures"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_update_htlcs(commitment_update_data):
    node_id = PublicKey(get_random_pk_bytes())
    updates = CommitmentUpdate(
        commitment_update_data.get("update_add_htlcs"),
        commitment_update_data.get("update_fulfill_htlcs"),
        commitment_update_data.get("update_fail_htlcs"),
        commitment_update_data.get("update_fail_malformed_htlcs"),
        commitment_update_data.get("update_fee"),
        commitment_update_data.get("commitment_signed"),
    )
    event = MessageSendEvent.update_htlcs(node_id, updates)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "UpdateHTLCs"
    assert event.node_id == node_id
    for u1, u2 in zip(event.updates.update_add_htlcs, updates.update_add_htlcs):
        assert u1.serialize() == u2.serialize()
    for u1, u2 in zip(event.updates.update_fulfill_htlcs, updates.update_fulfill_htlcs):
        assert u1.serialize() == u2.serialize()
    for u1, u2 in zip(event.updates.update_fail_htlcs, updates.update_fail_htlcs):
        assert u1.serialize() == u2.serialize()
    for u1, u2 in zip(event.updates.update_fail_malformed_htlcs, updates.update_fail_malformed_htlcs):
        assert u1.serialize() == u2.serialize()
    assert event.updates.update_fee, updates.update_fee
    assert event.updates.commitment_signed, updates.commitment_signed

    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_revoke_and_ack(revoke_and_ack_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = RevokeAndACK.from_bytes(revoke_and_ack_bytes)
    event = MessageSendEvent.send_revoke_and_ack(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendRevokeAndACK"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_closing_signed(closing_signed_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = ClosingSigned.from_bytes(closing_signed_bytes)
    event = MessageSendEvent.send_closing_signed(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendClosingSigned"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_shutdown(shutdown_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = Shutdown.from_bytes(shutdown_bytes)
    event = MessageSendEvent.send_shutdown(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendShutdown"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_send_channel_reestablish(channel_reestablish_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    msg = ChannelReestablish.from_bytes(channel_reestablish_bytes)
    event = MessageSendEvent.send_channel_reestablish(node_id, msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "SendChannelReestablish"
    assert event.node_id == node_id
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_broadcast_channel_announcement(channel_announcement_bytes, channel_update_bytes):
    msg = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    update_msg = ChannelUpdate.from_bytes(channel_update_bytes)
    event = MessageSendEvent.broadcast_channel_announcement(msg, update_msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "BroadcastChannelAnnouncement"
    assert event.msg.serialize() == msg.serialize()
    assert event.update_msg.serialize() == update_msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_broadcast_channel_update(channel_update_bytes):
    msg = ChannelUpdate.from_bytes(channel_update_bytes)
    event = MessageSendEvent.broadcast_channel_update(msg)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "BroadcastChannelUpdate"
    assert event.msg.serialize() == msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_handle_error(error_message_bytes):
    node_id = PublicKey(get_random_pk_bytes())
    error_message = ErrorMessage.from_bytes(error_message_bytes)
    action = ErrorAction.disconnect_peer(error_message)
    event = MessageSendEvent.handle_error(node_id, action)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "HandleError"
    assert event.node_id == node_id
    assert event.action.msg.serialize() == action.msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have update"):
        event.update


def test_payment_failure_network_update(channel_update_bytes):
    chan_update = ChannelUpdate.from_bytes(channel_update_bytes)
    htlc_fail_chan_update = HTLCFailChannelUpdate.channel_update_message(chan_update)
    event = MessageSendEvent.payment_failure_network_update(htlc_fail_chan_update)

    assert isinstance(event, MessageSendEvent)

    # Getters
    assert event.type == "PaymentFailureNetworkUpdate"
    assert event.update.type == htlc_fail_chan_update.type
    assert event.update.msg.serialize() == htlc_fail_chan_update.msg.serialize()

    with pytest.raises(AttributeError, match="does not have updates"):
        event.updates
    with pytest.raises(AttributeError, match="does not have update_msg"):
        event.update_msg
    with pytest.raises(AttributeError, match="does not have action"):
        event.action
