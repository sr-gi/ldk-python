from ldk_python.chain.channelmonitor import *
from ldk_python.ln.channelmanager import PaymentHash
from ldk_python.chain.keysinterface import InMemoryChannelKeys
from ldk_python.primitives import SecretKey, PublicKey, Transaction, Script, OutPoint, TxId
from ldk_python.ln.chan_utils import TxCreationKeys, HTLCOutputInCommitment, HolderCommitmentTransaction

from conftest import get_random_bytes, get_random_sk_bytes, get_random_pk_bytes, get_random_int

# HOLDER COMMITMENT TX
#####################
tx = bytes.fromhex(
    "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
)
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

holder_commitment_tx = HolderCommitmentTransaction(
    Transaction.from_bytes(tx), counterparty_sig, holder_pk, counterparty_pk, keys, feerate_kw, htlc_data
)
################

# IN MEM CHAN KEYS
#################
sk = SecretKey(get_random_sk_bytes())
commitment_seed = get_random_sk_bytes()
channel_value_satoshis = pow(2, 64) - 1
key_derivation_params = (0, 1)

in_mem_chan_keys = InMemoryChannelKeys(
    sk, sk, sk, sk, sk, commitment_seed, channel_value_satoshis, key_derivation_params
)
###########

shutdown_pk = PublicKey(get_random_pk_bytes())
on_counterparty_tx_csv = 20
destination_script = Script(get_random_bytes((40)))
counterparty_htlc_base_key = PublicKey(get_random_pk_bytes())
counterparty_delayed_payment_base_key = PublicKey(get_random_pk_bytes())
on_holder_tx_csv = 30
funding_redeemscript = Script(get_random_bytes(40))
channel_value_satoshis = 42
commitment_transaction_number_obscure_factor = 10

# outpoint_index = get_random_bytes(4)
# txid = get_random_bytes(32)
# funding_info = (OutPoint.from_bytes(txid + outpoint_index), Script(get_random_bytes(50)))
# print(f"OutPoint: {txid[::-1].hex()}:{int.from_bytes(outpoint_index, 'little')}")
# print(f"OutPoint (u16): {txid[::-1].hex()}:{int.from_bytes(outpoint_index[:2], 'little')}")
outpoint_index = get_random_int(2)
txid = get_random_bytes(32)
funding_info = (OutPoint(TxId(txid), outpoint_index), Script(get_random_bytes(50)))
print(f"OutPoint: {txid.hex()}:{outpoint_index}")

# CREATE MONITOR

channel_monitor = InMemoryKeysChannelMonitor(
    in_mem_chan_keys,
    shutdown_pk,
    on_counterparty_tx_csv,
    destination_script,
    funding_info,
    counterparty_htlc_base_key,
    counterparty_delayed_payment_base_key,
    on_holder_tx_csv,
    funding_redeemscript,
    channel_value_satoshis,
    commitment_transaction_number_obscure_factor,
    holder_commitment_tx,
)


# GET OUTPUTS
channel_monitor.get_dummy_funding_txo()
channel_monitor.get_funding_txo()
