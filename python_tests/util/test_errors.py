from ldk_python.util.errors import *

# Test that all exceptions can be created and that the inheritance works as expected
def test_expectioms():
    api_error = APIError()
    api_misuse_error = APIMisuseError()
    fee_rate_too_high = FeeRateTooHigh()
    chan_unavailable = ChannelUnavailable()
    monitor_update_failed = MonitorUpdateFailed()

    assert isinstance(api_error, APIError)
    assert isinstance(api_misuse_error, APIMisuseError) and isinstance(api_misuse_error, APIError)
    assert isinstance(fee_rate_too_high, FeeRateTooHigh) and isinstance(api_misuse_error, APIError)
    assert isinstance(chan_unavailable, ChannelUnavailable) and isinstance(api_misuse_error, APIError)
    assert isinstance(monitor_update_failed, MonitorUpdateFailed) and isinstance(api_misuse_error, APIError)
