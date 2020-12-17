import pytest
from conftest import (
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
