import os
from setuptools import setup
from setuptools_rust import Binding, RustExtension


module_names = []
for folder, subfolders, files in os.walk("src"):
    if folder == "src":
        modules = [f"{f_name[:-3]}" for f_name in files if f_name.endswith(".rs") and f_name != "lib.rs"]
    else:
        # There's, at most, a single level of nestig in modules
        _, folder = folder.split("/")
        modules = [f"{folder}.{f_name[:-3]}" for f_name in files if f_name.endswith(".rs") and f_name != "mod.rs"]

    module_names.extend(modules)

package_name = "ldk_python"
packages = [f"{package_name}.{m_name}" for m_name in module_names]

setup(
    name="ldk-python",
    version="1.0",
    rust_extensions=[
        RustExtension("ldk_python.ldk_python", binding=Binding.PyO3, args=["--target=x86_64-apple-darwin"])
    ],
    packages=packages,
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)