from setuptools import setup

setup(
    name="fnfqueue",
    version="0.9",
    setup_requires=["cffi>=1.0.0"],
    packages=["fnfqueue"],
    cffi_modules=["build_fnfqueue.py:ffibuilder"],
    install_requires=["cffi>=1.0.0"],
    author="Gernot Vormayr",
    author_email="gvormayr@gmail.com",
    description="Fast python library encapsulating the nfqueue netlink interface.",
    license="LGPL"
)
