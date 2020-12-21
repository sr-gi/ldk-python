import pytest
from conftest import Empty

from ldk_python.chain.chaininterface import FeeEstimator, BroadcasterInterface
from ldk_python.primitives import Transaction

targets = {"BACKGROUND": 1, "NORMAL": 10, "HIGHPRIORITY": 50}


class FeeEst:
    def get_est_sat_per_1000_weight(self, confirmation_target):
        # Normalize input
        confirmation_target = confirmation_target.upper()

        if confirmation_target not in targets:
            raise ValueError(f"confirmation target must be in {list(targets.keys())}. {confirmation_target} received")

        return targets.get(confirmation_target)


class WrongFeeEst:
    def get_est_sat_per_1000_weight(self, confirmation_target):
        """
        This method tests the binding against a None return, which is valid since PyAny::call_method returns PyAny,
        which on casting (extract) returns an Option<T>.
        """
        return None


class Broadcaster:
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


def test_broadcast_transaction(tx):
    b = Broadcaster()
    bi = BroadcasterInterface(b)
    t = Transaction.from_bytes(tx)
    bi.broadcast_transaction(t)
    assert str(t) in b.broadcast_txs


def test_broadcast_transaction_wrong_tx():
    b = Broadcaster()
    bi = BroadcasterInterface(b)
    with pytest.raises(TypeError, match="Can't convert"):
        bi.broadcast_transaction(bytes(170))
