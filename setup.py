from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="ldk-python",
    version="1.0",
    rust_extensions=[RustExtension("ldk_python.ldk_python", binding=Binding.PyO3)],
    packages=["ldk_python"],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)