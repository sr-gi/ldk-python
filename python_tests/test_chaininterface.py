import pytest

from ldk_python.chaininterface import FeeEstimator

targets = {"BACKGROUND": 1, "NORMAL": 10, "HIGHPRIORITY": 50}


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


def test_get_est_sat_per_1000_weight():
    estimator = FeeEstimator(FeeEst())

    for k, v in targets.items():
        assert estimator.get_est_sat_per_1000_weight(k) == v
        assert estimator.get_est_sat_per_1000_weight(k.lower()) == v

def test_get_est_sat_per_1000_weight_wrong_key():
    estimator = FeeEstimator(FeeEst())

    with pytest.raises(ValueError, match="confirmation target must be in"):
        assert estimator.get_est_sat_per_1000_weight("random_key")

def test_get_est_sat_per_1000_weight_invalid_extimator():
    with pytest.raises(TypeError, match="Expected a return of type"):
        wrong_estimator = FeeEstimator(WrongFeeEst())
        assert wrong_estimator.get_est_sat_per_1000_weight("random_key")
