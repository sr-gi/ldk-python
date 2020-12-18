from io import BytesIO
import pytest
from conftest import (
    get_random_bytes,
    get_random_sk_bytes,
    get_random_pk_bytes,
    generate_random_keypair,
    get_random_der_signature,
    get_random_compact_signature,
)

from ldk_python.primitives import *


# SECRET KEY TESTS


def test_secret_key_init():
    assert isinstance(SecretKey(get_random_sk_bytes()), SecretKey)


def test_secret_key_init_wrong_range():
    with pytest.raises(ValueError, match="malformed or out-of-range"):
        SecretKey(bytes(32))


def test_secret_key_serialize():
    sk_bytes = get_random_sk_bytes()
    assert SecretKey(sk_bytes).serialize() == sk_bytes


def test_secret_key_sign():
    message = "test message"
    sk = SecretKey(get_random_sk_bytes())
    sig = sk.sign(message)
    assert isinstance(sig, Signature)


def test_secret_key_str():
    sk_bytes = get_random_sk_bytes()
    assert str(SecretKey(sk_bytes)) == sk_bytes.hex()


# PUBLIC KEY TESTS


def test_public_key_init():
    assert isinstance(PublicKey(get_random_pk_bytes()), PublicKey)
    assert isinstance(PublicKey(get_random_pk_bytes(compressed=False)), PublicKey)


def test_public_key_wrong_data():
    with pytest.raises(ValueError, match="malformed public key"):
        PublicKey(bytes(33))

    with pytest.raises(ValueError, match="malformed public key"):
        PublicKey(bytes(65))


def test_public_key_from_sk():
    sk = SecretKey(get_random_sk_bytes())
    assert isinstance(PublicKey.from_secret_key(sk), PublicKey)


def test_public_key_verify():
    message = "test message"
    sk, pk = generate_random_keypair()

    sig = sk.sign(message)
    assert pk.verify(message, sig)


def test_public_key_serialize():
    pk_bytes = get_random_pk_bytes()
    assert (PublicKey(pk_bytes).serialize()) == pk_bytes

    pk_bytes = get_random_pk_bytes(compressed=False)
    assert (PublicKey(pk_bytes).serialize(compressed=False)) == pk_bytes


def test_public_key_str():
    pk_bytes = get_random_pk_bytes()
    assert (str(PublicKey(pk_bytes))) == pk_bytes.hex()


# SIGNATURE TESTS


def test_signature_init():
    assert isinstance(Signature(get_random_der_signature()), Signature)


def test_signature_wrong_data():
    with pytest.raises(ValueError, match="malformed signature"):
        Signature(bytes(71))


def test_signature_from_compact():
    assert isinstance(Signature.from_compact(get_random_compact_signature()), Signature)


def test_signature_from_compact_wrong_data():
    with pytest.raises(ValueError, match="malformed signature"):
        Signature.from_compact(bytes(63))


def test_signature_serialize_der():
    der_sig = get_random_der_signature()
    assert Signature(der_sig).serialize_der() == der_sig


def test_signature_serialize_compact():
    compact_sig = get_random_compact_signature()
    assert Signature.from_compact(compact_sig).serialize_compact() == compact_sig


def test_signature_str():
    der_sig = get_random_der_signature()
    assert (str(Signature(der_sig))) == der_sig.hex()


# BLOCK HEADER TESTS


class BH:
    def __init__(self, raw_header):
        buffered_header = BytesIO(raw_header)
        self.version = int.from_bytes(buffered_header.read(4), "little")
        self.prev_blockhash = buffered_header.read(32).hex()
        self.merkle_root = buffered_header.read(32)[::-1].hex()
        self.time = int.from_bytes(buffered_header.read(4), "little")
        self.bits = int.from_bytes(buffered_header.read(4), "little")
        self.nonce = int.from_bytes(buffered_header.read(4), "little")
        self.serialised = raw_header


@pytest.fixture
def genesis_raw_block_header():
    return bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
    )


@pytest.fixture
def ldk_block_header(genesis_raw_block_header):
    return BlockHeader(genesis_raw_block_header)


@pytest.fixture
def local_block_header(genesis_raw_block_header):
    return BH(genesis_raw_block_header)


def test_block_header_init(ldk_block_header):
    assert isinstance(ldk_block_header, BlockHeader)


def test_block_header_wrong_data_length():
    with pytest.raises(ValueError, match="Data must be 80-byte long"):
        BlockHeader(bytes(79))


def test_block_getters(local_block_header, ldk_block_header):
    assert local_block_header.version == ldk_block_header.version
    assert local_block_header.prev_blockhash == ldk_block_header.prev_blockhash
    assert local_block_header.merkle_root == ldk_block_header.merkle_root
    assert local_block_header.time == ldk_block_header.time
    assert local_block_header.bits == ldk_block_header.bits
    assert local_block_header.nonce == ldk_block_header.nonce


def test_block_serialize(genesis_raw_block_header, local_block_header, ldk_block_header):
    assert local_block_header.serialised == ldk_block_header.serialize() == genesis_raw_block_header


def test_block_str(genesis_raw_block_header, ldk_block_header):
    assert str(ldk_block_header) == genesis_raw_block_header.hex()


# SCRIPT TESTS


def test_script_init():
    assert isinstance(Script(get_random_bytes(40)), Script)


def test_script_serialize():
    s_length = b"\x28"
    s_data = get_random_bytes(40)
    assert Script(s_data).serialize() == s_length + s_data


def test_script_str():
    s_length = "32"
    s_data = get_random_bytes(50)

    assert str(Script(s_data)) == s_length + s_data.hex()


# OUTPOINT TESTS


def test_outpoint_init():
    assert isinstance(OutPoint(TxId(get_random_bytes(32)), 0), OutPoint)


def test_outpoint_from_bytes():
    assert isinstance(OutPoint.from_bytes(get_random_bytes(36)), OutPoint)


def test_outpoint_from_bytes_wrong_size():
    with pytest.raises(ValueError, match="Outpoint data must be 36-bytes long"):
        OutPoint.from_bytes(get_random_bytes(35))

    with pytest.raises(ValueError, match="Outpoint data must be 36-bytes long"):
        OutPoint.from_bytes(get_random_bytes(37))


def test_outpoint_getters():
    txid = get_random_bytes(32)
    index = 42

    outpoint = OutPoint(TxId(txid), index)
    assert outpoint.txid == txid
    assert outpoint.index == index


def test_outpoint_serialize():
    # The last 4 bits of the index are zeroes for LN (indexes are bound to 2-bytes)
    outpoint = get_random_bytes(36)
    assert OutPoint.from_bytes(outpoint).serialize() == outpoint[:34] + b"\x00\x00"


def test_outpoint_str():
    outpoint = get_random_bytes(36)
    assert str(OutPoint.from_bytes(outpoint)) == outpoint.hex()[:68] + "0000"
