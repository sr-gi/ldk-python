import pytest
from conftest import Empty

from ldk_python.logger import LDKLogger


class Logger:
    def log(self, message, level):
        print(f"[{level}]: {message}")

    def info(self, message):
        self.log(message, "INFO")

    def warn(self, message):
        self.log(message, "WARN")

    def error(self, message):
        self.log(message, "ERROR")

    def debug(self, message):
        self.log(message, "DEBUG")


inner_logger = Logger()
ldk_logger = LDKLogger(inner_logger)


def test_wrong_logger():
    with pytest.raises(TypeError, match="Not all required methods are implemented"):
        LDKLogger(Empty())


def test_logger_log(capfd):
    inner_logger.log("This is a custom log", "CUSTOM_LEVEL")
    inner_out, _ = capfd.readouterr()

    ldk_logger.log("This is a custom log", "CUSTOM_LEVEL")
    ldk_out, _ = capfd.readouterr()

    assert inner_out == ldk_out


def test_logger_info(capfd):
    message = "This is an info message"
    inner_logger.info(message)
    inner_out, _ = capfd.readouterr()

    ldk_logger.info(message)
    ldk_out, _ = capfd.readouterr()

    assert inner_out == ldk_out


def test_logger_warn(capfd):
    message = "This is a warning"
    inner_logger.warn(message)
    inner_out, _ = capfd.readouterr()

    ldk_logger.warn(message)
    ldk_out, _ = capfd.readouterr()

    assert inner_out == ldk_out


def test_logger_error(capfd):
    message = "This is an error"
    inner_logger.error(message)
    inner_out, _ = capfd.readouterr()

    ldk_logger.error(message)
    ldk_out, _ = capfd.readouterr()

    assert inner_out == ldk_out


def test_logger_debug(capfd):
    message = "This is a debug message"
    inner_logger.debug(message)
    inner_out, _ = capfd.readouterr()

    ldk_logger.debug(message)
    ldk_out, _ = capfd.readouterr()

    assert inner_out == ldk_out
