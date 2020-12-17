import random
import pytest
import coincurve as cc

from ldk_python.primitives import SecretKey, PublicKey


@pytest.fixture(scope="session", autouse=True)
def prng_seed():
    random.seed(0)


class Empty:
    pass


def get_random_bytes(nbytes):
    return random.getrandbits(8 * nbytes).to_bytes(nbytes, "big")


def get_random_sk_bytes():
    x = get_random_bytes(32)
    while int.from_bytes(x, "big") == 0:
        x = get_random_bytes(32)

    return x


def get_random_pk_bytes(compressed=True):
    return cc.PrivateKey(get_random_sk_bytes()).public_key.format(compressed)


def generate_random_keypair():
    sk = SecretKey(get_random_sk_bytes())
    return sk, PublicKey.from_secret_key(sk)


def get_random_der_signature():
    sk = cc.PrivateKey(get_random_sk_bytes())
    message = get_random_bytes(32)
    return sk.sign(message)


def get_random_compact_signature():
    sk = cc.PrivateKey(get_random_sk_bytes())
    message = get_random_bytes(32)

    # The recoverable signature is a compact signature with trailing recovery
    # byte. The trailing byte is removed since it is not expected by the constructor
    return sk.sign_recoverable(message)[:-1]
