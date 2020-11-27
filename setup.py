from setuptools import setup
from setuptools_rust import Binding, RustExtension

package_name = "ldk_python"
extension_names = ["primitives", "logger", "chaininterface", "keysmanager"]
extensions = [RustExtension(f"{package_name}.{e_name}", binding=Binding.PyO3) for e_name in extension_names]

setup(
    name="ldk-python",
    version="1.0",
    rust_extensions=extensions,
    packages=["ldk_python"],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)