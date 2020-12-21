import random
import pytest
import coincurve as cc

from ldk_python.primitives import SecretKey, PublicKey


@pytest.fixture(scope="session", autouse=True)
def prng_seed():
    random.seed(0)


@pytest.fixture()
def tx():
    return bytes.fromhex(
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    )


@pytest.fixture()
def txin():
    # txin *WITHOUT* witness, given it is not (de)serialzed with the rest of the data by rust-bitcoin
    return bytes.fromhex("9d4abd3f68803972ebb0b2d85882c950e38b835f2416e34e9fcaa2c104ead20c0100000000ffffffff")


@pytest.fixture()
def txout():
    return bytes.fromhex("6c7808000000000017a914a3df719fd30ef904ba8860ce5c8ef79cf9e4c5c687")


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
