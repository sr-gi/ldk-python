from io import BytesIO
import pytest
from conftest import get_random_net_addr, get_random_bytes, get_random_pk_bytes, get_random_int

from ldk_python.primitives import PublicKey, BlockHash
from ldk_python.util.events import MessageSendEvent
from ldk_python.ln.msgs import *
from ldk_python.ln.features import InitFeatures

# INIT
@pytest.fixture
def init_bytes():
    return bytes.fromhex("00023fff0003ffffff")


def test_init_from_bytes(init_bytes):
    assert isinstance(Init.from_bytes(init_bytes), Init)


def test_init_serialize(init_bytes):
    init = Init.from_bytes(init_bytes)
    assert init.serialize() == init_bytes


# ERROR MESSAGE
@pytest.fixture
def error_message_bytes():
    return bytes.fromhex(
        "0202020202020202020202020202020202020202020202020202020202020202000e727573742d6c696768746e696e67"
    )


def test_error_message_from_bytes(error_message_bytes):
    assert isinstance(ErrorMessage.from_bytes(error_message_bytes), ErrorMessage)


def test_error_message_serialize(error_message_bytes):
    e_message = ErrorMessage.from_bytes(error_message_bytes)
    assert e_message.serialize() == error_message_bytes


def test_error_message_getter(error_message_bytes):
    e_message_io = BytesIO(error_message_bytes)
    e_message = ErrorMessage.from_bytes(error_message_bytes)

    assert e_message.channel_id == e_message_io.read(32)
    data_len = len(e_message.data)
    assert data_len == int.from_bytes(e_message_io.read(2), "big")
    assert e_message.data == e_message_io.read(data_len).decode()


# OPEN CHANNEL
@pytest.fixture
def open_channel_bytes():
    return bytes.fromhex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f02020202020202020202020202020202020202020202020202020202020202021234567890123456233403289122369832144668701144767633030896203198784335490624111800083a840000034d000c89d4c0bcc0bc031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a00"
    )


def test_open_channel_from_bytes(open_channel_bytes):
    assert isinstance(OpenChannel.from_bytes(open_channel_bytes), OpenChannel)


def test_open_channel_serialize(open_channel_bytes):
    open_channel = OpenChannel.from_bytes(open_channel_bytes)
    assert open_channel.serialize() == open_channel_bytes


def test_open_channel_getters(open_channel_bytes):
    open_channel_io = BytesIO(open_channel_bytes)
    open_channel = OpenChannel.from_bytes(open_channel_bytes)

    assert open_channel.chain_hash.serialize() == open_channel_io.read(32)
    assert open_channel.temporary_channel_id == open_channel_io.read(32)
    assert open_channel.funding_satoshis == int.from_bytes(open_channel_io.read(8), "big")
    assert open_channel.push_msat == int.from_bytes(open_channel_io.read(8), "big")
    assert open_channel.dust_limit_satoshis == int.from_bytes(open_channel_io.read(8), "big")
    assert open_channel.max_htlc_value_in_flight_msat == int.from_bytes(open_channel_io.read(8), "big")
    assert open_channel.channel_reserve_satoshis == int.from_bytes(open_channel_io.read(8), "big")
    assert open_channel.htlc_minimum_msat == int.from_bytes(open_channel_io.read(8), "big")
    assert open_channel.feerate_per_kw == int.from_bytes(open_channel_io.read(4), "big")
    assert open_channel.to_self_delay == int.from_bytes(open_channel_io.read(2), "big")
    assert open_channel.max_accepted_htlcs == int.from_bytes(open_channel_io.read(2), "big")
    assert open_channel.funding_pubkey.serialize() == open_channel_io.read(33)
    assert open_channel.revocation_basepoint.serialize() == open_channel_io.read(33)
    assert open_channel.payment_point.serialize() == open_channel_io.read(33)
    assert open_channel.delayed_payment_basepoint.serialize() == open_channel_io.read(33)
    assert open_channel.htlc_basepoint.serialize() == open_channel_io.read(33)
    assert open_channel.first_per_commitment_point.serialize() == open_channel_io.read(33)
    assert open_channel.channel_flags == int.from_bytes(open_channel_io.read(1), "big")
    assert open_channel.shutdown_scriptpubkey == None


# ACCEPT CHANNEL
@pytest.fixture
def accept_channel_bytes():
    return bytes.fromhex(
        "020202020202020202020202020202020202020202020202020202020202020212345678901234562334032891223698321446687011447600083a840000034d000c89d4c0bcc0bc031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a"
    )


def test_accept_channel_from_bytes(accept_channel_bytes):
    assert isinstance(AcceptChannel.from_bytes(accept_channel_bytes), AcceptChannel)


def test_accept_channel_serialize(accept_channel_bytes):
    accept_channel = AcceptChannel.from_bytes(accept_channel_bytes)
    assert accept_channel.serialize() == accept_channel_bytes


def test_accept_channel_getters(accept_channel_bytes):
    accept_channel_io = BytesIO(accept_channel_bytes)
    accept_channel = AcceptChannel.from_bytes(accept_channel_bytes)

    assert accept_channel.temporary_channel_id == accept_channel_io.read(32)
    assert accept_channel.dust_limit_satoshis == int.from_bytes(accept_channel_io.read(8), "big")
    assert accept_channel.max_htlc_value_in_flight_msat == int.from_bytes(accept_channel_io.read(8), "big")
    assert accept_channel.channel_reserve_satoshis == int.from_bytes(accept_channel_io.read(8), "big")
    assert accept_channel.htlc_minimum_msat == int.from_bytes(accept_channel_io.read(8), "big")
    assert accept_channel.minimum_depth == int.from_bytes(accept_channel_io.read(4), "big")
    assert accept_channel.to_self_delay == int.from_bytes(accept_channel_io.read(2), "big")
    assert accept_channel.max_accepted_htlcs == int.from_bytes(accept_channel_io.read(2), "big")
    assert accept_channel.funding_pubkey.serialize() == accept_channel_io.read(33)
    assert accept_channel.revocation_basepoint.serialize() == accept_channel_io.read(33)
    assert accept_channel.payment_point.serialize() == accept_channel_io.read(33)
    assert accept_channel.delayed_payment_basepoint.serialize() == accept_channel_io.read(33)
    assert accept_channel.htlc_basepoint.serialize() == accept_channel_io.read(33)
    assert accept_channel.first_per_commitment_point.serialize() == accept_channel_io.read(33)
    assert accept_channel.shutdown_scriptpubkey == None


# FUNDING CREATED
@pytest.fixture
def funding_created_bytes():
    return bytes.fromhex(
        "02020202020202020202020202020202020202020202020202020202020202026e96fe9f8b0ddcd729ba03cfafa5a27b050b39d354dd980814268dfa9a44d4c200ffd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a"
    )


def test_funding_created_from_bytes(funding_created_bytes):
    assert isinstance(FundingCreated.from_bytes(funding_created_bytes), FundingCreated)


def test_funding_created_serialize(funding_created_bytes):
    funding_created = FundingCreated.from_bytes(funding_created_bytes)
    assert funding_created.serialize() == funding_created_bytes


def test_funding_created_getters(funding_created_bytes):
    funding_created_io = BytesIO(funding_created_bytes)
    funding_created = FundingCreated.from_bytes(funding_created_bytes)

    assert funding_created.temporary_channel_id == funding_created_io.read(32)
    assert funding_created.funding_txid.serialize() == funding_created_io.read(32)
    assert funding_created.funding_output_index == int.from_bytes(funding_created_io.read(2), "big")
    assert funding_created.signature.serialize_compact() == funding_created_io.read(64)


# FUNDING SIGNED
@pytest.fixture
def funding_signed_bytes():
    return bytes.fromhex(
        "0202020202020202020202020202020202020202020202020202020202020202d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a"
    )


def test_funding_signed_from_bytes(funding_signed_bytes):
    assert isinstance(FundingSigned.from_bytes(funding_signed_bytes), FundingSigned)


def test_funding_created_serialize(funding_signed_bytes):
    funding_signed = FundingSigned.from_bytes(funding_signed_bytes)
    assert funding_signed.serialize() == funding_signed_bytes


def test_funding_signed_getters(funding_signed_bytes):
    funding_signed_io = BytesIO(funding_signed_bytes)
    funding_signed = FundingSigned.from_bytes(funding_signed_bytes)

    assert funding_signed.channel_id == funding_signed_io.read(32)
    assert funding_signed.signature.serialize_compact() == funding_signed_io.read(64)


# FUNDING LOCKED
@pytest.fixture
def funding_locked_bytes():
    return bytes.fromhex(
        "0202020202020202020202020202020202020202020202020202020202020202031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
    )


def test_funding_locked_from_bytes(funding_locked_bytes):
    assert isinstance(FundingLocked.from_bytes(funding_locked_bytes), FundingLocked)


def test_funding_locked_serialize(funding_locked_bytes):
    funding_locked = FundingLocked.from_bytes(funding_locked_bytes)
    assert funding_locked.serialize() == funding_locked_bytes


def test_funding_locked_getters(funding_locked_bytes):
    funding_locked_io = BytesIO(funding_locked_bytes)
    funding_locked = FundingLocked.from_bytes(funding_locked_bytes)

    assert funding_locked.channel_id == funding_locked_io.read(32)
    assert funding_locked.next_per_commitment_point.serialize() == funding_locked_io.read(33)


# SHUTDOWN
@pytest.fixture
def shutdown_bytes():
    return bytes.fromhex(
        "0202020202020202020202020202020202020202020202020202020202020202002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260"
    )


def test_shutdown_from_bytes(shutdown_bytes):
    assert isinstance(Shutdown.from_bytes(shutdown_bytes), Shutdown)


def test_shutdown_serialize(shutdown_bytes):
    shutdown = Shutdown.from_bytes(shutdown_bytes)
    assert shutdown.serialize() == shutdown_bytes


def test_shutdown_getters(shutdown_bytes):
    shutdown_io = BytesIO(shutdown_bytes)
    shutdown = Shutdown.from_bytes(shutdown_bytes)

    shutdown.channel_id == shutdown_io.read(32)
    shutdown.scriptpubkey.serialize() == shutdown_io.read(36)


# CLOSING SIGNED
@pytest.fixture
def closing_signed_bytes():
    return bytes.fromhex(
        "020202020202020202020202020202020202020202020202020202020202020200083a840000034dd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a"
    )


def test_closing_signed_from_bytes(closing_signed_bytes):
    assert isinstance(ClosingSigned.from_bytes(closing_signed_bytes), ClosingSigned)


def test_closing_signed_serialize(closing_signed_bytes):
    closing_signed = ClosingSigned.from_bytes(closing_signed_bytes)
    assert closing_signed.serialize() == closing_signed_bytes


def test_closing_signed_getters(closing_signed_bytes):
    closing_signed_io = BytesIO(closing_signed_bytes)
    closing_signed = ClosingSigned.from_bytes(closing_signed_bytes)

    assert closing_signed.channel_id == closing_signed_io.read(32)
    assert closing_signed.fee_satoshis == int.from_bytes(closing_signed_io.read(8), "big")
    assert closing_signed.signature.serialize_compact() == closing_signed_io.read(64)


# UPDATE ADD HTLC
@pytest.fixture
def update_add_htlc_bytes():
    return bytes.fromhex(
        "020202020202020202020202020202020202020202020202020202020202020200083a840000034d32144668701144760101010101010101010101010101010101010101010101010101010101010101000c89d4ff031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"
    )


def test_update_add_htlc_from_bytes(update_add_htlc_bytes):
    assert isinstance(UpdateAddHTLC.from_bytes(update_add_htlc_bytes), UpdateAddHTLC)


def test_update_add_htlc_serialize(update_add_htlc_bytes):
    update_add_htlc = UpdateAddHTLC.from_bytes(update_add_htlc_bytes)
    assert update_add_htlc.serialize() == update_add_htlc_bytes


def test_update_add_htlc_getters(update_add_htlc_bytes):
    update_add_htlc_io = BytesIO(update_add_htlc_bytes)
    update_add_htlc = UpdateAddHTLC.from_bytes(update_add_htlc_bytes)

    assert update_add_htlc.channel_id == update_add_htlc_io.read(32)
    assert update_add_htlc.htlc_id == int.from_bytes(update_add_htlc_io.read(8), "big")
    assert update_add_htlc.ammount_msat == int.from_bytes(update_add_htlc_io.read(8), "big")
    assert update_add_htlc.payment_hash.serialize() == update_add_htlc_io.read(32)
    assert update_add_htlc.cltv_expiry == int.from_bytes(update_add_htlc_io.read(4), "big")


# UPDATE FULFILL HTLC
@pytest.fixture
def update_fulfill_htlc_bytes():
    return bytes.fromhex(
        "020202020202020202020202020202020202020202020202020202020202020200083a840000034d0101010101010101010101010101010101010101010101010101010101010101"
    )


def test_update_fulfill_htlc_from_bytes(update_fulfill_htlc_bytes):
    assert isinstance(UpdateFulfillHTLC.from_bytes(update_fulfill_htlc_bytes), UpdateFulfillHTLC)


def test_update_fulfill_htlc_serialize(update_fulfill_htlc_bytes):
    update_fulfill_htlc = UpdateFulfillHTLC.from_bytes(update_fulfill_htlc_bytes)
    assert update_fulfill_htlc.serialize() == update_fulfill_htlc_bytes


def test_update_fulfill_htlc_getters(update_fulfill_htlc_bytes):
    update_fulfill_htlc_io = BytesIO(update_fulfill_htlc_bytes)
    update_fulfill_htlc = UpdateFulfillHTLC.from_bytes(update_fulfill_htlc_bytes)

    assert update_fulfill_htlc.channel_id == update_fulfill_htlc_io.read(32)
    assert update_fulfill_htlc.htlc_id == int.from_bytes(update_fulfill_htlc_io.read(8), "big")
    assert update_fulfill_htlc.payment_preimage.serialize() == update_fulfill_htlc_io.read(32)


# UPDATE FAIL HTLC
@pytest.fixture
def update_fail_htlc_bytes():
    return bytes.fromhex(
        "020202020202020202020202020202020202020202020202020202020202020200083a840000034d00200101010101010101010101010101010101010101010101010101010101010101"
    )


def test_update_fail_htlc_from_bytes(update_fail_htlc_bytes):
    assert isinstance(UpdateFailHTLC.from_bytes(update_fail_htlc_bytes), UpdateFailHTLC)


def test_update_fail_htlc_serialize(update_fail_htlc_bytes):
    update_fail_htlc = UpdateFailHTLC.from_bytes(update_fail_htlc_bytes)
    assert update_fail_htlc.serialize() == update_fail_htlc_bytes


def test_update_fail_htlc_getters(update_fail_htlc_bytes):
    update_fail_htlc_io = BytesIO(update_fail_htlc_bytes)
    update_fail_htlc = UpdateFailHTLC.from_bytes(update_fail_htlc_bytes)

    assert update_fail_htlc.channel_id == update_fail_htlc_io.read(32)
    assert update_fail_htlc.htlc_id == int.from_bytes(update_fail_htlc_io.read(8), "big")


# UPDATE FAIL MALFORMED HTLC
@pytest.fixture
def update_fail_malformed_htlc_bytes():
    return bytes.fromhex(
        "020202020202020202020202020202020202020202020202020202020202020200083a840000034d010101010101010101010101010101010101010101010101010101010101010100ff"
    )


def test_update_fail_malformed_htlc_from_bytes(update_fail_malformed_htlc_bytes):
    assert isinstance(UpdateFailMalformedHTLC.from_bytes(update_fail_malformed_htlc_bytes), UpdateFailMalformedHTLC)


def test_update_fail_malformed_htlc_serialize(update_fail_malformed_htlc_bytes):
    update_fail_malformed_htlc = UpdateFailMalformedHTLC.from_bytes(update_fail_malformed_htlc_bytes)
    assert update_fail_malformed_htlc.serialize() == update_fail_malformed_htlc_bytes


def test_update_fail_malformed_htlc_getters(update_fail_malformed_htlc_bytes):
    update_fail_malformed_htlc_io = BytesIO(update_fail_malformed_htlc_bytes)
    update_fail_malformed_htlc = UpdateFailMalformedHTLC.from_bytes(update_fail_malformed_htlc_bytes)

    assert update_fail_malformed_htlc.channel_id == update_fail_malformed_htlc_io.read(32)
    assert update_fail_malformed_htlc.htlc_id == int.from_bytes(update_fail_malformed_htlc_io.read(8), "big")
    assert update_fail_malformed_htlc.failure_code == int.from_bytes(update_fail_malformed_htlc_bytes[-2:], "big")


# COMMITMENT SIGNED
@pytest.fixture
def commitment_signed_bytes():
    return bytes.fromhex(
        "0202020202020202020202020202020202020202020202020202020202020202d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a0000"
    )


def test_commitment_signed_from_bytes(commitment_signed_bytes):
    assert isinstance(CommitmentSigned.from_bytes(commitment_signed_bytes), CommitmentSigned)


def test_commitment_signed_serialize(commitment_signed_bytes):
    commitment_signed = CommitmentSigned.from_bytes(commitment_signed_bytes)
    assert commitment_signed.serialize() == commitment_signed_bytes


def test_commitment_signed_getters(commitment_signed_bytes):
    commitment_signed_io = BytesIO(commitment_signed_bytes)
    commitment_signed = CommitmentSigned.from_bytes(commitment_signed_bytes)

    assert commitment_signed.channel_id == commitment_signed_io.read(32)
    assert commitment_signed.signature.serialize_compact() == commitment_signed_io.read(64)
    assert commitment_signed.htlc_signatures == []


# REVOKE AND ACK
@pytest.fixture
def revoke_and_ack_bytes():
    return bytes.fromhex(
        "02020202020202020202020202020202020202020202020202020202020202020101010101010101010101010101010101010101010101010101010101010101031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
    )


def test_revoke_and_ack_from_bytes(revoke_and_ack_bytes):
    assert isinstance(RevokeAndACK.from_bytes(revoke_and_ack_bytes), RevokeAndACK)


def test_revoke_and_ack_serialize(revoke_and_ack_bytes):
    revoke_and_ack = RevokeAndACK.from_bytes(revoke_and_ack_bytes)
    assert revoke_and_ack.serialize() == revoke_and_ack_bytes


def test_revoke_and_ack_getters(revoke_and_ack_bytes):
    revoke_and_ack_io = BytesIO(revoke_and_ack_bytes)
    revoke_and_ack = RevokeAndACK.from_bytes(revoke_and_ack_bytes)

    assert revoke_and_ack.channel_id == revoke_and_ack_io.read(32)
    assert revoke_and_ack.per_commitment_secret == revoke_and_ack_io.read(32)
    assert revoke_and_ack.next_per_commitment_point.serialize() == revoke_and_ack_io.read(33)


# UPDATE FEE
@pytest.fixture
def update_fee_bytes():
    return bytes.fromhex("0202020202020202020202020202020202020202020202020202020202020202013413a7")


def test_update_fee_from_bytes(update_fee_bytes):
    assert isinstance(UpdateFee.from_bytes(update_fee_bytes), UpdateFee)


def test_update_fee_serialize(update_fee_bytes):
    update_fee = UpdateFee.from_bytes(update_fee_bytes)
    assert update_fee.serialize() == update_fee_bytes


def test_update_fee_getters(update_fee_bytes):
    update_fee_io = BytesIO(update_fee_bytes)
    update_fee = UpdateFee.from_bytes(update_fee_bytes)

    assert update_fee.channel_id == update_fee_io.read(32)
    assert update_fee.feerate_per_kw == int.from_bytes(update_fee_io.read(4), "big")


# DATA LOSS PROTECT
def test_data_loss_protect():
    last_per_commitment_secret = get_random_bytes(32)
    current_per_commitment_point = PublicKey(get_random_pk_bytes())

    assert isinstance(DataLossProtect(last_per_commitment_secret, current_per_commitment_point), DataLossProtect)


def test_data_loss_protect_getters():
    last_per_commitment_secret = get_random_bytes(32)
    current_per_commitment_point = PublicKey(get_random_pk_bytes())

    data_loss_protect = DataLossProtect(last_per_commitment_secret, current_per_commitment_point)
    assert data_loss_protect.your_last_per_commitment_secret == last_per_commitment_secret
    assert data_loss_protect.my_current_per_commitment_point.serialize() == current_per_commitment_point.serialize()


# CHANNEL REESTABLISH
@pytest.fixture
def channel_reestablish_bytes():
    return bytes.fromhex(
        "0400000000000000050000000000000006000000000000000700000000000000000000000000000300000000000000040909090909090909090909090909090909090909090909090909090909090909031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
    )


def test_channel_reestablish_from_bytes(channel_reestablish_bytes):
    assert isinstance(ChannelReestablish.from_bytes(channel_reestablish_bytes), ChannelReestablish)


def test_channel_reestablish_serialize(channel_reestablish_bytes):
    channel_reestablish = ChannelReestablish.from_bytes(channel_reestablish_bytes)
    assert channel_reestablish.serialize() == channel_reestablish_bytes


def test_channel_reestablish_getters(channel_reestablish_bytes):
    channel_reestablish_io = BytesIO(channel_reestablish_bytes)
    channel_reestablish = ChannelReestablish.from_bytes(channel_reestablish_bytes)

    channel_reestablish.channel_id == channel_reestablish_io.read(32)
    channel_reestablish.next_local_commitment_number == int.from_bytes(channel_reestablish_io.read(8), "big")
    channel_reestablish.next_remote_commitment_number == int.from_bytes(channel_reestablish_io.read(8), "big")


# ANNOUNCEMENT SIGNATURES
@pytest.fixture
def announcement_signatures_bytes():
    return bytes.fromhex(
        "040000000000000005000000000000000600000000000000070000000000000000083a840000034dd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073acf9953cef4700860f5967838eba2bae89288ad188ebf8b20bf995c3ea53a26df1876d0a3a0e13172ba286a673140190c02ba9da60a2e43a745188c8a83c7f3ef"
    )


def test_announcement_signatures_from_bytes(announcement_signatures_bytes):
    assert isinstance(AnnouncementSignatures.from_bytes(announcement_signatures_bytes), AnnouncementSignatures)


def test_announcement_signatures_serialize(announcement_signatures_bytes):
    announcement_signatures = AnnouncementSignatures.from_bytes(announcement_signatures_bytes)
    assert announcement_signatures.serialize() == announcement_signatures_bytes


def test_announcement_signatures_getters(announcement_signatures_bytes):
    announcement_signatures_io = BytesIO(announcement_signatures_bytes)
    announcement_signatures = AnnouncementSignatures.from_bytes(announcement_signatures_bytes)

    assert announcement_signatures.channel_id == announcement_signatures_io.read(32)
    assert announcement_signatures.short_channel_id == int.from_bytes(announcement_signatures_io.read(8), "big")
    assert announcement_signatures.node_signature.serialize_compact() == announcement_signatures_io.read(64)
    assert announcement_signatures.bitcoin_signature.serialize_compact() == announcement_signatures_io.read(64)


# NETADDRESS
def test_netaddress_ipv4():
    ipv4, port = get_random_net_addr("ipv4")
    netaddr = NetAddress.ipv4(ipv4, port)

    assert isinstance(netaddr, NetAddress)
    assert netaddr.addr == ipv4
    assert netaddr.port == port
    assert netaddr.version == None
    assert netaddr.checksum == None


def test_netaddress_ipv4_serialize():
    ipv4, port = get_random_net_addr("ipv4")
    netaddr = NetAddress.ipv4(ipv4, port)

    port_hex = format(port, "x")
    if len(port_hex) % 2:
        port_hex = "0" + port_hex
    ser_address = b"\x01" + ipv4 + bytes.fromhex(port_hex)
    assert netaddr.serialize() == ser_address


def test_netaddress_ipv6():
    ipv6, port = get_random_net_addr("ipv6")
    netaddr = NetAddress.ipv6(ipv6, port)

    assert isinstance(netaddr, NetAddress)
    assert netaddr.addr == ipv6
    assert netaddr.port == port
    assert netaddr.version == None
    assert netaddr.checksum == None


def test_netaddress_ipv6_serialize():
    ipv6, port = get_random_net_addr("ipv6")
    netaddr = NetAddress.ipv6(ipv6, port)

    port_hex = format(port, "x")
    if len(port_hex) % 2:
        port_hex = "0" + port_hex
    ser_address = b"\x02" + ipv6 + bytes.fromhex(port_hex)
    assert netaddr.serialize() == ser_address


def test_netaddress_onionv2():
    onionv2, port = get_random_net_addr("onionv2")
    netaddr = NetAddress.onionv2(onionv2, port)

    assert isinstance(netaddr, NetAddress)
    assert netaddr.addr == onionv2
    assert netaddr.port == port
    assert netaddr.version == None
    assert netaddr.checksum == None


def test_netaddress_onionv2_serialize():
    onionv2, port = get_random_net_addr("onionv2")
    netaddr = NetAddress.onionv2(onionv2, port)

    port_hex = format(port, "x")
    if len(port_hex) % 2:
        port_hex = "0" + port_hex

    ser_address = b"\x03" + onionv2 + bytes.fromhex(port_hex)
    assert netaddr.serialize() == ser_address


def test_netaddress_onionv3():
    onionv3, port = get_random_net_addr("onionv3")
    version = 1
    checksum = get_random_int(2)
    netaddr = NetAddress.onionv3(onionv3, checksum, version, port)

    assert isinstance(netaddr, NetAddress)
    assert netaddr.addr == onionv3
    assert netaddr.checksum == checksum
    assert netaddr.version == version
    assert netaddr.port == port


def test_netaddress_onionv3_serialize():
    onionv3, port = get_random_net_addr("onionv3")
    version = 1
    checksum = get_random_int(2)
    netaddr = NetAddress.onionv3(onionv3, checksum, version, port)

    port_hex = format(port, "x")
    if len(port_hex) % 2:
        port_hex = "0" + port_hex

    ser_address = (
        b"\x04" + onionv3 + bytes.fromhex(format(checksum, "x")) + version.to_bytes(1, "big") + bytes.fromhex(port_hex)
    )

    assert netaddr.serialize() == ser_address


# UNSIGNED NODE ANNOUNCEMENT
@pytest.fixture
def unsigned_node_announcement_bytes():
    return bytes.fromhex(
        "0003029222000001f4035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c00000000000000000000000000000000000000000000000000000000000000000000000000"
    )


def test_unsigned_node_announcement_from_bytes(unsigned_node_announcement_bytes):
    assert isinstance(UnsignedNodeAnnouncement.from_bytes(unsigned_node_announcement_bytes), UnsignedNodeAnnouncement)


def test_unsigned_node_announcement_serialize(unsigned_node_announcement_bytes):
    unsigned_node_announcement = UnsignedNodeAnnouncement.from_bytes(unsigned_node_announcement_bytes)
    assert unsigned_node_announcement.serialize() == unsigned_node_announcement_bytes


def test_unsigned_node_announcement_getters(unsigned_node_announcement_bytes):
    unsigned_node_announcement_io = BytesIO(unsigned_node_announcement_bytes)
    unsigned_node_announcement = UnsignedNodeAnnouncement.from_bytes(unsigned_node_announcement_bytes)

    assert unsigned_node_announcement.features.serialize() == unsigned_node_announcement_io.read(5)
    assert unsigned_node_announcement.timestamp == int.from_bytes(unsigned_node_announcement_io.read(4), "big")
    assert unsigned_node_announcement.node_id.serialize() == unsigned_node_announcement_io.read(33)
    assert unsigned_node_announcement.rgb == unsigned_node_announcement_io.read(3)
    assert unsigned_node_announcement.alias == unsigned_node_announcement_io.read(32)

    addr_len = int.from_bytes(unsigned_node_announcement_io.read(2), "big")
    ser_addresses = b""
    for address in unsigned_node_announcement.addresses:
        ser_addresses += address.serialize()

    # addr_len inclused the excess address data, so cannot read with addr_len
    assert ser_addresses == unsigned_node_announcement_io.read(77)


# NODE ANNOUNCEMENT
@pytest.fixture
def node_announcement_bytes():
    return bytes.fromhex(
        "5e398f34f8576a841121ae5e25703be9bd757d857562465a5a86cf8ab831694346fb6c201ea4bab3fd1914719a7cf044dd0f841e28e89a0b295c024e9750b8880003029222000001f4035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c00000000000000000000000000000000000000000000000000000000000000000000000000"
    )


def test_node_announcement_from_bytes(node_announcement_bytes):
    assert isinstance(NodeAnnouncement.from_bytes(node_announcement_bytes), NodeAnnouncement)


def test_node_announcement_serialize(node_announcement_bytes):
    node_announcement = NodeAnnouncement.from_bytes(node_announcement_bytes)
    assert node_announcement.serialize() == node_announcement_bytes


def test_node_announcement_getters(node_announcement_bytes):
    node_announcement_io = BytesIO(node_announcement_bytes)
    node_announcement = NodeAnnouncement.from_bytes(node_announcement_bytes)

    assert node_announcement.signature.serialize_compact() == node_announcement_io.read(64)
    assert node_announcement.contents.serialize() == node_announcement_io.read()


# UNSIGNED CHANNEL ANNOUNCEMENT
@pytest.fixture
def unsigned_channel_announcement_bytes():
    return bytes.fromhex(
        "000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea3309000000000000000000000000035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c035c4e0dec7215e26833938730e5e505aa62504da85ba57106a46b5a2404fc9d8e02ba72a6e8ba53e8b971ad0c9823968aef4d78ce8af255ab43dff83003c902fb8d0216345bf831164a03758eaea5e8b66fee2be7710b8f190ee880249032a29ed66e"
    )


def test_unsigned_channel_announcement_from_bytes(unsigned_channel_announcement_bytes):
    assert isinstance(
        UnsignedChannelAnnouncement.from_bytes(unsigned_channel_announcement_bytes), UnsignedChannelAnnouncement
    )


def test_unsigned_channel_announcement_serialize(unsigned_channel_announcement_bytes):
    unsigned_channel_announcement = UnsignedChannelAnnouncement.from_bytes(unsigned_channel_announcement_bytes)
    assert unsigned_channel_announcement.serialize() == unsigned_channel_announcement_bytes


def test_unsigned_channel_announcement_getters(unsigned_channel_announcement_bytes):
    unsigned_channel_announcement_io = BytesIO(unsigned_channel_announcement_bytes)
    unsigned_channel_announcement = UnsignedChannelAnnouncement.from_bytes(unsigned_channel_announcement_bytes)

    assert unsigned_channel_announcement.features.serialize() == unsigned_channel_announcement_io.read(2)
    assert unsigned_channel_announcement.chain_hash.serialize() == unsigned_channel_announcement_io.read(32)
    assert unsigned_channel_announcement.short_channel_id == int.from_bytes(
        unsigned_channel_announcement_io.read(8), "big"
    )
    assert unsigned_channel_announcement.node_id_1.serialize() == unsigned_channel_announcement_io.read(33)
    assert unsigned_channel_announcement.node_id_2.serialize() == unsigned_channel_announcement_io.read(33)
    assert unsigned_channel_announcement.bitcoin_key_1.serialize() == unsigned_channel_announcement_io.read(33)
    assert unsigned_channel_announcement.bitcoin_key_2.serialize() == unsigned_channel_announcement_io.read(33)


# CHANNEL ANNOUNCEMENT
@pytest.fixture
def channel_announcement_bytes():
    return bytes.fromhex(
        "94e4f56141247d9023a0c8348cc4ca51d81759ff7dac8c9b63291ce6121293bd664d6b9cfb35da16063df08f8a3999a2f25d120f2b421b8b9afe330ceb335e52ee99a10706edf8487ac6e5f55e013a412f18948a3b0a523fbf61a9c54f70eeb87923bb1a447d91e62abca107bc653b02d91db2f23acb7579c666d8c17129df0460f4bf077bb9c211946a28c2ddd87b448f08e3c8d8f481b09f94cbc8c13cc26e3126fc33163be0dea116219f89dd97a441f29f19b1ae82f7859ab78fb7527a72f15e89e18acd40b58ec3ca4276a36e1bf4873530584304d92c505455476f709b421f91fca1db725396c8e5cd0ecba0fe6b087748b7ad4a697cdcd80428359b73000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea3309000000000000000000000000035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c035c4e0dec7215e26833938730e5e505aa62504da85ba57106a46b5a2404fc9d8e02ba72a6e8ba53e8b971ad0c9823968aef4d78ce8af255ab43dff83003c902fb8d0216345bf831164a03758eaea5e8b66fee2be7710b8f190ee880249032a29ed66e"
    )


def test_channel_announcement_from_bytes(channel_announcement_bytes):
    assert isinstance(ChannelAnnouncement.from_bytes(channel_announcement_bytes), ChannelAnnouncement)


def test_channel_announcement_serialize(channel_announcement_bytes):
    channel_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    assert channel_announcement.serialize() == channel_announcement_bytes


def test_channel_announcement_getters(channel_announcement_bytes):
    channel_announcement_io = BytesIO(channel_announcement_bytes)
    channel_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)

    assert channel_announcement.node_signature_1.serialize_compact() == channel_announcement_io.read(64)
    assert channel_announcement.node_signature_2.serialize_compact() == channel_announcement_io.read(64)
    assert channel_announcement.bitcoin_signature_1.serialize_compact() == channel_announcement_io.read(64)
    assert channel_announcement.bitcoin_signature_2.serialize_compact() == channel_announcement_io.read(64)
    assert channel_announcement.contents.serialize() == channel_announcement_io.read()


# UNSIGNED CHANNEL UPDATE
@pytest.fixture
def unsigned_channel_update_bytes():
    return bytes.fromhex(
        "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea3309000000000000000000000000000000640000009000000000000f42400000271000000014"
    )


def test_unsigned_channel_update_from_bytes(unsigned_channel_update_bytes):
    assert isinstance(UnsignedChannelUpdate.from_bytes(unsigned_channel_update_bytes), UnsignedChannelUpdate)


def test_channel_update_serialize(unsigned_channel_update_bytes):
    unsigned_channel_update = UnsignedChannelUpdate.from_bytes(unsigned_channel_update_bytes)
    assert unsigned_channel_update.serialize() == unsigned_channel_update_bytes


def test_channel_update_getters(unsigned_channel_update_bytes):
    unsigned_channel_update_io = BytesIO(unsigned_channel_update_bytes)
    unsigned_channel_update = UnsignedChannelUpdate.from_bytes(unsigned_channel_update_bytes)

    assert unsigned_channel_update.chain_hash.serialize() == unsigned_channel_update_io.read(32)
    assert unsigned_channel_update.short_channel_id == int.from_bytes(unsigned_channel_update_io.read(8), "big")
    assert unsigned_channel_update.timestamp == int.from_bytes(unsigned_channel_update_io.read(4), "big")
    # Flags is u8 but u16 needs to be read.
    assert unsigned_channel_update.flags == int.from_bytes(unsigned_channel_update_io.read(2), "big")
    assert unsigned_channel_update.cltv_expiry_delta == int.from_bytes(unsigned_channel_update_io.read(2), "big")
    assert unsigned_channel_update.htlc_minimum_msat == int.from_bytes(unsigned_channel_update_io.read(8), "big")
    assert unsigned_channel_update.htlc_maximum_msat is None
    assert unsigned_channel_update.fee_base_msat == int.from_bytes(unsigned_channel_update_io.read(4), "big")
    assert unsigned_channel_update.fee_proportional_millionths == int.from_bytes(
        unsigned_channel_update_io.read(4), "big"
    )


# CHANNEL UPDATE
@pytest.fixture
def channel_update_bytes():
    return bytes.fromhex(
        "c1523299fbb21cddabc0cdde6d4e4bd5743aed00dbe6c7cff1486542c291463a2cddaf9d7227d61273bebce396ba3567fb9e9256cd8a6bb04d46d0425fb85f2443497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea3309000000000000000000000000000000640000009000000000000f42400000271000000014"
    )


def test_channel_update_from_bytes(channel_update_bytes):
    assert isinstance(ChannelUpdate.from_bytes(channel_update_bytes), ChannelUpdate)


def test_channel_update_serialize(channel_update_bytes):
    channel_update = ChannelUpdate.from_bytes(channel_update_bytes)
    assert channel_update.serialize() == channel_update_bytes


def test_channel_update_getters(channel_update_bytes):
    channel_update_io = BytesIO(channel_update_bytes)
    channel_update = ChannelUpdate.from_bytes(channel_update_bytes)

    assert channel_update.signature.serialize_compact() == channel_update_io.read(64)
    assert channel_update.contents.serialize() == channel_update_io.read()


# ERROR ACTION
def test_error_action_disconnect_peer(error_message_bytes):
    error_message = ErrorMessage.from_bytes(error_message_bytes)
    error_action = ErrorAction.disconnect_peer(error_message)
    assert isinstance(error_action, ErrorAction)

    # Getters
    assert error_action.type == "DisconnectPeer"
    assert error_action.msg.serialize() == error_message.serialize()


def test_error_action_ignore_error():
    error_action = ErrorAction.ignore_error()
    assert isinstance(error_action, ErrorAction)

    # Getters
    assert error_action.type == "IgnoreError"
    with pytest.raises(AttributeError, match="does not have msg"):
        error_action.msg


def test_error_action_send_error_message(error_message_bytes):
    error_message = ErrorMessage.from_bytes(error_message_bytes)
    error_action = ErrorAction.send_error_message(error_message)
    assert isinstance(error_action, ErrorAction)

    # Getters
    assert error_action.type == "SendErrorMessage"
    assert error_action.msg.serialize() == error_message.serialize()


# LIGHTNING ERROR
def test_lightning_error(error_message_bytes):
    msg = "Error"
    error_action = ErrorAction.ignore_error()

    assert isinstance(LightningError(msg, error_action), LightningError)


def test_lightning_error_getters():
    msg = "Error"
    error_action = ErrorAction.ignore_error()
    lightning_error = LightningError(msg, error_action)

    assert lightning_error.err == msg
    lightning_error.action.type == error_action.type


# COMMITMENT UPDATE
@pytest.fixture
def commitment_update_data(
    update_add_htlc_bytes,
    update_fulfill_htlc_bytes,
    update_fail_htlc_bytes,
    update_fail_malformed_htlc_bytes,
    update_fee_bytes,
    commitment_signed_bytes,
):
    update_add_htlcs = [UpdateAddHTLC.from_bytes(update_add_htlc_bytes)]
    update_fulfill_htlcs = [UpdateFulfillHTLC.from_bytes(update_fulfill_htlc_bytes)]
    update_fail_htlcs = [UpdateFailHTLC.from_bytes(update_fail_htlc_bytes)]
    update_fail_malformed_htlcs = [UpdateFailMalformedHTLC.from_bytes(update_fail_malformed_htlc_bytes)]
    update_fee = UpdateFee.from_bytes(update_fee_bytes)
    commitment_signed = CommitmentSigned.from_bytes(commitment_signed_bytes)

    return {
        "update_add_htlcs": update_add_htlcs,
        "update_fulfill_htlcs": update_fulfill_htlcs,
        "update_fail_htlcs": update_fail_htlcs,
        "update_fail_malformed_htlcs": update_fail_malformed_htlcs,
        "update_fee": update_fee,
        "commitment_signed": commitment_signed,
    }


@pytest.fixture
def commitment_update(commitment_update_data):
    return CommitmentUpdate(
        commitment_update_data.get("update_add_htlcs"),
        commitment_update_data.get("update_fulfill_htlcs"),
        commitment_update_data.get("update_fail_htlcs"),
        commitment_update_data.get("update_fail_malformed_htlcs"),
        commitment_update_data.get("update_fee"),
        commitment_update_data.get("commitment_signed"),
    )


def test_commitment_update(commitment_update):
    assert isinstance(commitment_update, CommitmentUpdate)


def test_commitment_update_getters(commitment_update, commitment_update_data):
    assert (
        commitment_update.update_add_htlcs[0].serialize()
        == commitment_update_data.get("update_add_htlcs")[0].serialize()
    )
    assert (
        commitment_update.update_fulfill_htlcs[0].serialize()
        == commitment_update_data.get("update_fulfill_htlcs")[0].serialize()
    )
    assert (
        commitment_update.update_fail_htlcs[0].serialize()
        == commitment_update_data.get("update_fail_htlcs")[0].serialize()
    )
    assert (
        commitment_update.update_fail_malformed_htlcs[0].serialize()
        == commitment_update_data.get("update_fail_malformed_htlcs")[0].serialize()
    )
    assert commitment_update.update_fee.serialize() == commitment_update_data.get("update_fee").serialize()
    assert (
        commitment_update.commitment_signed.serialize() == commitment_update_data.get("commitment_signed").serialize()
    )


# HTLC FAIL CHANNEL UPDATE
def test_htlc_fail_channel_update_channel_update_message(channel_update_bytes):
    chan_update = ChannelUpdate.from_bytes(channel_update_bytes)
    htlc_fail_chan_update = HTLCFailChannelUpdate.channel_update_message(chan_update)
    assert isinstance(htlc_fail_chan_update, HTLCFailChannelUpdate)

    # Getters
    assert htlc_fail_chan_update.type == "ChannelUpdateMessage"
    assert htlc_fail_chan_update.msg.serialize() == channel_update_bytes

    with pytest.raises(AttributeError, match="does not have short_channel_id"):
        htlc_fail_chan_update.short_channel_id
    with pytest.raises(AttributeError, match="does not have is_permanent"):
        htlc_fail_chan_update.is_permanent
    with pytest.raises(AttributeError, match="does not have node_id"):
        htlc_fail_chan_update.node_id


def test_htlc_fail_channel_update_channel_closed():
    short_chan_id = get_random_int(8)
    is_permanent = True
    htlc_fail_chan_update = HTLCFailChannelUpdate.channel_closed(short_chan_id, is_permanent)
    assert isinstance(htlc_fail_chan_update, HTLCFailChannelUpdate)

    # Getters
    assert htlc_fail_chan_update.type == "ChannelClosed"
    assert htlc_fail_chan_update.short_channel_id == short_chan_id
    assert htlc_fail_chan_update.is_permanent == is_permanent

    with pytest.raises(AttributeError, match="does not have msg"):
        htlc_fail_chan_update.msg

    with pytest.raises(AttributeError, match="does not have node_id"):
        htlc_fail_chan_update.node_id


def test_htlc_fail_channel_update_node_failure():
    node_id = PublicKey(get_random_pk_bytes())
    is_permanent = False
    htlc_fail_chan_update = HTLCFailChannelUpdate.node_failure(node_id, is_permanent)
    assert isinstance(htlc_fail_chan_update, HTLCFailChannelUpdate)

    # Getters
    assert htlc_fail_chan_update.type == "NodeFailure"
    assert htlc_fail_chan_update.node_id.serialize() == node_id.serialize()
    assert htlc_fail_chan_update.is_permanent == is_permanent

    with pytest.raises(AttributeError, match="does not have msg"):
        htlc_fail_chan_update.msg

    with pytest.raises(AttributeError, match="does not have short_channel_id"):
        htlc_fail_chan_update.short_channel_id


# CHANNEL MESSAGE HANDLER
class CMH:
    def __init__(self, events=[]):
        self.events = events

    def get_and_clear_pending_msg_events(self):
        events = self.events
        self.events = []
        return events

    def handle_open_channel(self, their_node_id, their_features, msg):
        pass

    def handle_accept_channel(self, their_node_id, their_features, msg):
        pass

    def handle_funding_created(self, their_node_id, msg):
        pass

    def handle_funding_signed(self, their_node_id, msg):
        pass

    def handle_funding_locked(self, their_node_id, msg):
        pass

    def handle_shutdown(self, their_node_id, msg):
        pass

    def handle_closing_signed(self, their_node_id, msg):
        pass

    def handle_update_add_htlc(self, their_node_id, msg):
        pass

    def handle_update_fulfill_htlc(self, their_node_id, msg):
        pass

    def handle_update_fail_htlc(self, their_node_id, msg):
        pass

    def handle_update_fail_malformed_htlc(self, their_node_id, msg):
        pass

    def handle_commitment_signed(self, their_node_id, msg):
        pass

    def handle_revoke_and_ack(self, their_node_id, msg):
        pass

    def handle_update_fee(self, their_node_id, msg):
        pass

    def handle_announcement_signatures(self, their_node_id, msg):
        pass

    def peer_disconnected(self, their_node_id, no_connection_possible):
        pass

    def peer_connected(self, their_node_id, msg):
        pass

    def handle_channel_reestablish(self, their_node_id, msg):
        pass

    def handle_error(self, their_node_id, msg):
        pass


@pytest.fixture
def channel_message_handler():
    return ChannelMessageHandler(CMH())


def test_channel_manage_handler(channel_message_handler):
    assert isinstance(channel_message_handler, ChannelMessageHandler)


def test_get_and_clear_pending_msg_events(accept_channel_bytes, open_channel_bytes):
    node1_id = PublicKey(get_random_pk_bytes())
    msg1 = AcceptChannel.from_bytes(accept_channel_bytes)
    event1 = MessageSendEvent.send_accept_channel(node1_id, msg1)

    node2_id = PublicKey(get_random_pk_bytes())
    msg2 = OpenChannel.from_bytes(open_channel_bytes)
    event2 = MessageSendEvent.send_open_channel(node2_id, msg2)

    events = [event1, event2]
    cmh = CMH(events)
    channel_message_handler = ChannelMessageHandler(cmh)

    for e1, e2 in zip(channel_message_handler.get_and_clear_pending_msg_events(), events):
        assert e1.msg.serialize() == e2.msg.serialize()


def test_handle_open_channel(channel_message_handler, open_channel_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    their_features = InitFeatures.known()
    msg = OpenChannel.from_bytes(open_channel_bytes)

    channel_message_handler.handle_open_channel(their_node_id, their_features, msg)


def test_handle_accept_channel(channel_message_handler, accept_channel_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    their_features = InitFeatures.known()
    msg = AcceptChannel.from_bytes(accept_channel_bytes)

    channel_message_handler.handle_accept_channel(their_node_id, their_features, msg)


def test_handle_funding_created(channel_message_handler, funding_created_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = FundingCreated.from_bytes(funding_created_bytes)

    channel_message_handler.handle_funding_created(their_node_id, msg)


def test_handle_funding_signed(channel_message_handler, funding_signed_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = FundingSigned.from_bytes(funding_signed_bytes)

    channel_message_handler.handle_funding_signed(their_node_id, msg)


def test_handle_funding_locked(channel_message_handler, funding_locked_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = FundingLocked.from_bytes(funding_locked_bytes)

    channel_message_handler.handle_funding_locked(their_node_id, msg)


def test_handle_shutdoewn(channel_message_handler, shutdown_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = Shutdown.from_bytes(shutdown_bytes)

    channel_message_handler.handle_shutdown(their_node_id, msg)


def test_handle_closing_signed(channel_message_handler, closing_signed_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = ClosingSigned.from_bytes(closing_signed_bytes)

    channel_message_handler.handle_closing_signed(their_node_id, msg)


def test_handle_update_add_htlc(channel_message_handler, update_add_htlc_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = UpdateAddHTLC.from_bytes(update_add_htlc_bytes)

    channel_message_handler.handle_update_add_htlc(their_node_id, msg)


def test_handle_update_fulfill_htlc(channel_message_handler, update_fulfill_htlc_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = UpdateFulfillHTLC.from_bytes(update_fulfill_htlc_bytes)

    channel_message_handler.handle_update_fulfill_htlc(their_node_id, msg)


def test_handle_update_fail_htlc(channel_message_handler, update_fail_htlc_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = UpdateFailHTLC.from_bytes(update_fail_htlc_bytes)

    channel_message_handler.handle_update_fail_htlc(their_node_id, msg)


def test_handle_update_fail_malformed_htlc(channel_message_handler, update_fail_malformed_htlc_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = UpdateFailMalformedHTLC.from_bytes(update_fail_malformed_htlc_bytes)

    channel_message_handler.handle_update_fail_malformed_htlc(their_node_id, msg)


def test_handle_commitment_signed(channel_message_handler, commitment_signed_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = CommitmentSigned.from_bytes(commitment_signed_bytes)

    channel_message_handler.handle_commitment_signed(their_node_id, msg)


def test_handle_revoke_and_ack(channel_message_handler, revoke_and_ack_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = RevokeAndACK.from_bytes(revoke_and_ack_bytes)

    channel_message_handler.handle_revoke_and_ack(their_node_id, msg)


def test_handle_update_fee(channel_message_handler, update_fee_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = UpdateFee.from_bytes(update_fee_bytes)

    channel_message_handler.handle_update_fee(their_node_id, msg)


def test_handle_announcement_signatures(channel_message_handler, announcement_signatures_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = AnnouncementSignatures.from_bytes(announcement_signatures_bytes)

    channel_message_handler.handle_announcement_signatures(their_node_id, msg)


def test_peer_disconnected(channel_message_handler):
    their_node_id = PublicKey(get_random_pk_bytes())

    channel_message_handler.peer_disconnected(their_node_id, True)


def test_peer_connected(channel_message_handler, init_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = Init.from_bytes(init_bytes)

    channel_message_handler.peer_connected(their_node_id, msg)


def test_handle_channel_reestablish(channel_message_handler, channel_reestablish_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = ChannelReestablish.from_bytes(channel_reestablish_bytes)

    channel_message_handler.handle_channel_reestablish(their_node_id, msg)


def test_handle_error(channel_message_handler, error_message_bytes):
    their_node_id = PublicKey(get_random_pk_bytes())
    msg = ErrorMessage.from_bytes(error_message_bytes)

    channel_message_handler.handle_error(their_node_id, msg)


# ROUTING MESSAGE HANDLER
class RMH:
    def __init__(self, chann_update=True):
        self.chann_update = chann_update

    def handle_node_announcement(self, msg):
        return True

    def handle_channel_announcement(self, msg):
        return False

    def handle_channel_update(self, msg):
        return self.chann_update

    def handle_htlc_fail_channel_update(self, updates):
        pass

    def get_next_channel_announcements(self, starting_point, batch_amount):
        return []

    def get_next_node_announcements(self, starting_point, batch_amount):
        return []

    def should_request_full_sync(self, node_id):
        return True


@pytest.fixture
def routing_message_handler():
    return RoutingMessageHandler(RMH())


def test_channel_manage_handler(routing_message_handler):
    assert isinstance(routing_message_handler, RoutingMessageHandler)


def test_handle_node_announcement(routing_message_handler, node_announcement_bytes):
    msg = NodeAnnouncement.from_bytes(node_announcement_bytes)
    assert routing_message_handler.handle_node_announcement(msg) == True


def test_handle_channel_announcement(routing_message_handler, channel_announcement_bytes):
    msg = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    assert routing_message_handler.handle_channel_announcement(msg) == False


def test_handle_channel_update(routing_message_handler, channel_update_bytes):
    msg = ChannelUpdate.from_bytes(channel_update_bytes)
    assert routing_message_handler.handle_channel_update(msg) == True

    error_msg = "Error"
    error_action = ErrorAction.ignore_error()
    lightning_error = LightningError(error_msg, error_action)

    another_routing_message_handler = RoutingMessageHandler(RMH(lightning_error))
    result = another_routing_message_handler.handle_channel_update(msg)
    assert result.err == lightning_error.err
    assert result.action.type == lightning_error.action.type


def test_handle_htlc_fail_channel_update(routing_message_handler, channel_update_bytes):
    chan_update = ChannelUpdate.from_bytes(channel_update_bytes)
    htlc_fail_chan_update = HTLCFailChannelUpdate.channel_update_message(chan_update)

    # Check it does not fail
    assert routing_message_handler.handle_htlc_fail_channel_update(htlc_fail_chan_update) == None


def test_get_next_channel_announcements(routing_message_handler):
    starting_point = get_random_int(8)
    batch_amount = get_random_int(1)

    assert routing_message_handler.get_next_channel_announcements(starting_point, batch_amount) == []


def test_get_next_node_announcements(routing_message_handler):
    starting_point = PublicKey(get_random_pk_bytes())
    batch_amount = get_random_int(1)

    assert routing_message_handler.get_next_node_announcements(starting_point, batch_amount) == []


def test_should_request_full_sync(routing_message_handler):
    node_id = PublicKey(get_random_pk_bytes())

    assert routing_message_handler.should_request_full_sync(node_id) == True