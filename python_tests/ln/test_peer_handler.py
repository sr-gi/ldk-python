import pytest
from conftest import Empty, get_random_bytes, get_random_sk_bytes, get_random_pk_bytes

from python_tests.test_logger import Logger
from python_tests.ln.test_msgs import channel_message_handler, routing_message_handler

from ldk_python.logger import LDKLogger
from ldk_python.primitives import SecretKey, PublicKey
from ldk_python.ln.peer_handler import SocketDescriptor, PeerManager


class SockDesc:
    def hash(self):
        return self.__hash__

    def send_data(self, data, resume_read):
        # Returns int
        if resume_read:
            return 42
        else:
            return 21

    def disconnect_socket(self):
        pass


@pytest.fixture
def socket_descriptor():
    return SocketDescriptor(SockDesc())


def test_socket_descriptor(socket_descriptor):
    assert isinstance(socket_descriptor, SocketDescriptor)


def test_socket_descriptor_empty():
    with pytest.raises(TypeError, match="Not all required methods are implemented"):
        SocketDescriptor(Empty())


# FIXME: How to test that hash  actually works?
# def test_socket_descriptor_hash():
#     pass


def test_socket_descriptor_send_data(socket_descriptor):
    data = get_random_bytes(32)
    assert socket_descriptor._send_data(data, True) == 42
    assert socket_descriptor._send_data(data, False) == 21


def test_socket_descriptor_disconnect_socket(socket_descriptor):
    # Test it does not fail
    socket_descriptor._disconnect_socket()


@pytest.fixture
def peer_manager(channel_message_handler, routing_message_handler):
    our_node_secret = SecretKey(get_random_sk_bytes())
    ephemeral_random_data = get_random_bytes(32)
    logger = LDKLogger(Logger())

    return PeerManager(channel_message_handler, routing_message_handler, our_node_secret, ephemeral_random_data, logger)


def test_peer_manager(peer_manager):
    assert isinstance(peer_manager, PeerManager)


def test_peer_manager_get_peer_node_ids(peer_manager):
    assert peer_manager.get_peer_node_ids() == []


def test_peer_manager_new_outbound_connection(peer_manager, socket_descriptor):
    their_node_id = PublicKey(get_random_pk_bytes())

    r = peer_manager.new_outbound_connection(their_node_id, socket_descriptor)
    assert isinstance(r, bytes) and len(r) == 50


def test_peer_manager_new_inbound_connection(peer_manager, socket_descriptor):
    # Test it does not fail
    peer_manager.new_inbound_connection(socket_descriptor)


def test_write_buffer_space_avail(peer_manager, socket_descriptor):
    with pytest.raises(BaseException, match="is not already known"):
        peer_manager.write_buffer_space_avail(socket_descriptor)


def test_read_event(peer_manager, socket_descriptor):
    data = get_random_bytes(64)
    with pytest.raises(BaseException, match="is not already known"):
        peer_manager.read_event(socket_descriptor, data)


def test_process_events(peer_manager):
    # Test it does not fail
    peer_manager.process_events()


def test_socket_disconnected(peer_manager):
    # Test it does not fail
    peer_manager.socket_disconnected


def test_timer_tick_occured(peer_manager):
    # Test it does not fail
    peer_manager.timer_tick_occured()
