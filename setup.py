from setuptools import setup

setup(
    name="nfqueue",
    version="0.9",
    setup_requires=["cffi>=1.0.0"],
    packages=["nfqueue"],
    cffi_modules=["build_nfqueue.py:ffibuilder"],
    install_requires=["cffi>=1.0.0"],
    author="Gernot Vormayr",
    author_email="gvormayr@gmail.com",
    description="Python library encapsulating the nfqueue netlink interface.",
    license="LGPL"
)
