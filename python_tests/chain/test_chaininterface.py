import pytest
from conftest import Empty

from ldk_python.chain.chaininterface import FeeEstimator, BroadcasterInterface
from ldk_python.primitives import Transaction

targets = {"BACKGROUND": 1, "NORMAL": 10, "HIGHPRIORITY": 50}
tx_hex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"


class FeeEst():
    def get_est_sat_per_1000_weight(self, confirmation_target):
        # Normalize input
        confirmation_target = confirmation_target.upper()

        if confirmation_target not in targets:
            raise ValueError(f"confirmation target must be in {list(targets.keys())}. {confirmation_target} received")

        return targets.get(confirmation_target)


class WrongFeeEst():
    def get_est_sat_per_1000_weight(self, confirmation_target):
        """
        This method tests the binding against a None return, which is valid since PyAny::call_method returns PyAny,
        which on casting (extract) returns an Option<T>.
        """
        return None

class Broadcaster():
    def __init__(self):
        self.broadcast_txs = []

    def broadcast_transaction(self, tx):
        print(f"tx sent {str(tx)[:16]}...{str(tx)[-16:]}")
        self.broadcast_txs.append(str(tx))

def test_wrong_fee_estimator():
    with pytest.raises(TypeError, match="Not all required methods are implemented"):
        FeeEstimator(Empty())

def test_get_est_sat_per_1000_weight():
    estimator = FeeEstimator(FeeEst())

    for k, v in targets.items():
        assert estimator.get_est_sat_per_1000_weight(k) == v
        assert estimator.get_est_sat_per_1000_weight(k.lower()) == v

def test_get_est_sat_per_1000_weight_wrong_key():
    estimator = FeeEstimator(FeeEst())

    with pytest.raises(ValueError, match="confirmation target must be in"):
        assert estimator.get_est_sat_per_1000_weight("random_key")

def test_get_est_sat_per_1000_weight_invalid_estimator():
    with pytest.raises(TypeError, match="Expected a return of type"):
        wrong_estimator = FeeEstimator(WrongFeeEst())
        assert wrong_estimator.get_est_sat_per_1000_weight("random_key")

def test_wrong_broadcaster():
    with pytest.raises(TypeError, match="Not all required methods are implemented"):
        BroadcasterInterface(Empty())

def test_broadcast_transaction():
    b = Broadcaster()
    bi = BroadcasterInterface(b)
    tx = Transaction(bytes.fromhex(tx_hex))
    bi.broadcast_transaction(tx)
    assert str(tx) in b.broadcast_txs

def test_broadcast_transaction_wrong_tx():
    b = Broadcaster()
    bi = BroadcasterInterface(b)
    with pytest.raises(TypeError, match="Can't convert"):
        bi.broadcast_transaction(bytes(170))

