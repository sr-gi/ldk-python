import pytest
from conftest import get_random_net_addr, get_random_bytes, get_random_pk_bytes, get_random_int

from ldk_python.primitives import PublicKey
from ldk_python.ln.msgs import *

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


# UPDATE FAIL MALFORMED HTLC
@pytest.fixture
def update_fail_maldormed_htlc_bytes():
    return bytes.fromhex(
        "020202020202020202020202020202020202020202020202020202020202020200083a840000034d010101010101010101010101010101010101010101010101010101010101010100ff"
    )


def test_update_fail_malformed_htlc_from_bytes(update_fail_maldormed_htlc_bytes):
    assert isinstance(UpdateFailMalformedHTLC.from_bytes(update_fail_maldormed_htlc_bytes), UpdateFailMalformedHTLC)


def test_update_fail_malformed_htlc_serialize(update_fail_maldormed_htlc_bytes):
    update_fail_malformed_htlc = UpdateFailMalformedHTLC.from_bytes(update_fail_maldormed_htlc_bytes)
    assert update_fail_malformed_htlc.serialize() == update_fail_maldormed_htlc_bytes


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


# UPDATE FEE
@pytest.fixture
def update_fee_bytes():
    return bytes.fromhex("0202020202020202020202020202020202020202020202020202020202020202013413a7")


def test_update_fee_from_bytes(update_fee_bytes):
    assert isinstance(UpdateFee.from_bytes(update_fee_bytes), UpdateFee)


def test_update_fee_serialize(update_fee_bytes):
    update_fee = UpdateFee.from_bytes(update_fee_bytes)
    assert update_fee.serialize() == update_fee_bytes


# DATA LOSS PROTECT
def test_data_loss_protect():
    last_per_commitment_secret = get_random_bytes(32)
    current_per_commitment_point = PublicKey(get_random_pk_bytes())

    assert isinstance(DataLossProtect(last_per_commitment_secret, current_per_commitment_point), DataLossProtect)


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

    ser_address = b"\x01" + ipv4 + bytes.fromhex(hex(port)[2:])
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

    ser_address = b"\x02" + ipv6 + bytes.fromhex(hex(port)[2:])
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

    ser_address = b"\x03" + onionv2 + bytes.fromhex(hex(port)[2:])
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

    ser_address = (
        b"\x04" + onionv3 + bytes.fromhex(hex(checksum)[2:]) + version.to_bytes(1, "big") + bytes.fromhex(hex(port)[2:])
    )

    assert netaddr.serialize() == ser_address


# NODE ANNOUNCEMENT
@pytest.fixture
def node_announcement_bytes():
    return bytes.fromhex(
        "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010003902fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0260704fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607"
    )


def test_node_announcement_from_bytes(node_announcement_bytes):
    assert isinstance(NodeAnnouncement.from_bytes(node_announcement_bytes), NodeAnnouncement)


def test_node_announcement_serialize(node_announcement_bytes):
    node_announcement = NodeAnnouncement.from_bytes(node_announcement_bytes)
    assert node_announcement.serialize() == node_announcement_bytes


# CHANNEL ANNOUNCEMENT
@pytest.fixture
def channel_announcement_bytes():
    return bytes.fromhex(
        "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d2692b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd0002ffff000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f00083a840000034d031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b"
    )


def test_channel_announcement_from_bytes(channel_announcement_bytes):
    assert isinstance(ChannelAnnouncement.from_bytes(channel_announcement_bytes), ChannelAnnouncement)


def test_channel_announcement_serialize(channel_announcement_bytes):
    channel_announcement = ChannelAnnouncement.from_bytes(channel_announcement_bytes)
    assert channel_announcement.serialize() == channel_announcement_bytes


# CHANNEL UPDATE
@pytest.fixture
def channel_update_bytes():
    return bytes.fromhex(
        "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f00083a840000034d013413a70103009000000000000f424000002710000000140000777788889999000000003b9aca00"
    )


def test_channel_update_from_bytes(channel_update_bytes):
    assert isinstance(ChannelUpdate.from_bytes(channel_update_bytes), ChannelUpdate)


def test_channel_update_serialize(channel_update_bytes):
    channel_update = ChannelUpdate.from_bytes(channel_update_bytes)
    assert channel_update.serialize() == channel_update_bytes


# ERROR ACTION
def test_error_action_disconnect_peer(error_message_bytes):
    error_message = ErrorMessage.from_bytes(error_message_bytes)
    error_action = ErrorAction.disconnect_peer(error_message)
    assert isinstance(error_action, ErrorAction)
    assert error_action.type == "DisconnectPeer"


def test_error_action_ignore_error():
    error_action = ErrorAction.ignore_error()
    assert isinstance(error_action, ErrorAction)
    assert error_action.type == "IgnoreError"


def test_error_action_send_error_message(error_message_bytes):
    error_message = ErrorMessage.from_bytes(error_message_bytes)
    error_action = ErrorAction.send_error_message(error_message)
    assert isinstance(error_action, ErrorAction)
    assert error_action.type == "SendErrorMessage"


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


# HTLC FAIL CHANNEL UPDATE
def test_htlc_fail_channel_update_channel_update_message(channel_update_bytes):
    chan_update = ChannelUpdate.from_bytes(channel_update_bytes)
    htlc_fail_chan_update = HTLCFailChannelUpdate.channel_update_message(chan_update)
    assert isinstance(htlc_fail_chan_update, HTLCFailChannelUpdate)
    assert htlc_fail_chan_update.type == "ChannelUpdateMessage"


def test_htlc_fail_channel_update_channel_closed():
    shot_chan_id = get_random_int(8)
    is_permanent = True
    htlc_fail_chan_update = HTLCFailChannelUpdate.channel_closed(shot_chan_id, is_permanent)
    assert isinstance(htlc_fail_chan_update, HTLCFailChannelUpdate)
    assert htlc_fail_chan_update.type == "ChannelClosed"


def test_htlc_fail_channel_update_node_failure():
    node_id = PublicKey(get_random_pk_bytes())
    is_permanent = False
    htlc_fail_chan_update = HTLCFailChannelUpdate.node_failure(node_id, is_permanent)
    assert isinstance(htlc_fail_chan_update, HTLCFailChannelUpdate)
    assert htlc_fail_chan_update.type == "NodeFailure"