import pytest
from conftest import get_random_pk_bytes, get_random_sk_bytes, get_random_bytes

from ldk_python.primitives import PublicKey, SecretKey, Transaction
from ldk_python.ln.channelmanager import PaymentHash
from ldk_python.ln.chan_utils import (
    ChannelPublicKeys,
    TxCreationKeys,
    HTLCOutputInCommitment,
    HolderCommitmentTransaction,
)


def test_channel_public_keys():
    chan_pks = ChannelPublicKeys(
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
    )

    assert isinstance(chan_pks, ChannelPublicKeys)


def test_test_channel_public_keys_getters():
    funding_pk = PublicKey(get_random_pk_bytes())
    revocation_basepoint = PublicKey(get_random_pk_bytes())
    payment_point = PublicKey(get_random_pk_bytes())
    delayed_payment_basepoint = PublicKey(get_random_pk_bytes())
    htlc_basepoint = PublicKey(get_random_pk_bytes())

    chan_pks = ChannelPublicKeys(
        funding_pk, revocation_basepoint, payment_point, delayed_payment_basepoint, htlc_basepoint
    )

    assert chan_pks.funding_pubkey.serialize() == funding_pk.serialize()
    assert chan_pks.revocation_basepoint.serialize() == revocation_basepoint.serialize()
    assert chan_pks.payment_point.serialize() == payment_point.serialize()
    assert chan_pks.delayed_payment_basepoint.serialize() == delayed_payment_basepoint.serialize()
    assert chan_pks.htlc_basepoint.serialize() == htlc_basepoint.serialize()


def test_tx_creation_keys():
    tx_creation_keys = TxCreationKeys(
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
    )
    assert isinstance(tx_creation_keys, TxCreationKeys)


def test_tx_creation_keys_getters():
    per_commitment_point = PublicKey(get_random_pk_bytes())
    revocation_key = PublicKey(get_random_pk_bytes())
    broadcaster_htlc_key = PublicKey(get_random_pk_bytes())
    countersignatory_htlc_key = PublicKey(get_random_pk_bytes())
    broadcaster_delayed_payment_key = PublicKey(get_random_pk_bytes())

    tx_creation_keys = TxCreationKeys(
        per_commitment_point,
        revocation_key,
        broadcaster_htlc_key,
        countersignatory_htlc_key,
        broadcaster_delayed_payment_key,
    )

    assert tx_creation_keys.per_commitment_point.serialize() == per_commitment_point.serialize()
    assert tx_creation_keys.revocation_key.serialize() == revocation_key.serialize()
    assert tx_creation_keys.broadcaster_htlc_key.serialize() == broadcaster_htlc_key.serialize()
    assert tx_creation_keys.countersignatory_htlc_key.serialize() == countersignatory_htlc_key.serialize()
    assert tx_creation_keys.broadcaster_delayed_payment_key.serialize() == broadcaster_delayed_payment_key.serialize()


def test_htlc_output_in_commitment():
    amount_msat = 500000
    cltv_expiry = 30
    payment_hash = PaymentHash(get_random_bytes(32))

    htlc_out_1 = HTLCOutputInCommitment(True, amount_msat, cltv_expiry, payment_hash, 0)
    htlc_out_2 = HTLCOutputInCommitment(False, amount_msat, cltv_expiry, payment_hash, None)

    assert isinstance(htlc_out_1, HTLCOutputInCommitment)
    assert isinstance(htlc_out_2, HTLCOutputInCommitment)


def test_htlc_output_in_commitment_getters():
    offered = True
    amount_msat = 500000
    cltv_expiry = 30
    payment_hash = PaymentHash(get_random_bytes(32))
    tx_out_index = None

    htlc_out = HTLCOutputInCommitment(offered, amount_msat, cltv_expiry, payment_hash, tx_out_index)

    assert htlc_out.offered == offered
    assert htlc_out.amount_msat == amount_msat
    assert htlc_out.cltv_expiry == cltv_expiry
    assert htlc_out.payment_hash.serialize() == payment_hash.serialize()
    assert htlc_out.transaction_output_index == tx_out_index


@pytest.fixture()
def holder_commitment_tx_data(tx):
    counterparty_sk = SecretKey(get_random_sk_bytes())

    counterparty_pk = PublicKey.from_secret_key(counterparty_sk)
    counterparty_sig = counterparty_sk.sign(tx.hex())
    holder_pk = PublicKey(get_random_pk_bytes())
    keys = TxCreationKeys(
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
        PublicKey(get_random_pk_bytes()),
    )
    feerate_kw = 1000

    # HTLC DATA
    offered = True
    amount_msat = 500000
    cltv_expiry = 30
    payment_hash = PaymentHash(get_random_bytes(32))
    tx_out_index = None

    htlc_out = HTLCOutputInCommitment(offered, amount_msat, cltv_expiry, payment_hash, tx_out_index)
    htlc_data = [(htlc_out, None)]

    return Transaction.from_bytes(tx), counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data


def test_holder_commitment_tx(holder_commitment_tx_data):
    tx, counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data = holder_commitment_tx_data

    holder_commitment_tx = HolderCommitmentTransaction(
        tx, counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data
    )

    assert isinstance(holder_commitment_tx, HolderCommitmentTransaction)


def test_holder_commitment_tx_getters(holder_commitment_tx_data):
    tx, counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data = holder_commitment_tx_data

    holder_commitment_tx = HolderCommitmentTransaction(
        tx, counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data
    )

    assert tx.serialize() == holder_commitment_tx.unsigned_tx.serialize()
    assert counterparty_sig.serialize_der() == holder_commitment_tx.counterparty_sig.serialize_der()
    assert feerate_kw == holder_commitment_tx.feerate_per_kw
    for local_data, remote_data in zip(htlc_data, holder_commitment_tx.per_htlc):
        local_htlc_data = local_data[0]
        local_sig = local_data[1]
        remote_htlc_data = remote_data[0]
        remote_sig = remote_data[1]

        assert local_htlc_data.offered == remote_htlc_data.offered
        assert local_htlc_data.amount_msat == remote_htlc_data.amount_msat
        assert local_htlc_data.cltv_expiry == remote_htlc_data.cltv_expiry
        assert local_htlc_data.payment_hash.serialize() == remote_htlc_data.payment_hash.serialize()
        assert local_htlc_data.transaction_output_index == remote_htlc_data.transaction_output_index
        assert local_sig == remote_sig