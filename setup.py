from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(
    name="fnfqueue",
    version="1.1.1",
    setup_requires=["cffi>=1.0.0"],
    packages=["fnfqueue"],
    cffi_modules=["build_fnfqueue.py:ffibuilder"],
    install_requires=["cffi>=1.0.0"],
    author="Gernot Vormayr",
    author_email="gvormayr@gmail.com",
    description="Fast python library encapsulating the nfqueue netlink interface.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/notti/fnfqueue',
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",

        "Environment :: Other Environment",

        "Intended Audience :: Developers",
        "Intended Audience :: Telecommunications Industry",
        "Intended Audience :: Information Technology",

        "License :: OSI Approved :: MIT License",

        "Operating System :: POSIX :: Linux",

        "Programming Language :: C",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: PyPy",

        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Operating System Kernels :: Linux"

    ],
    keywords='nfqueue netfilter netlink iptables firewall mangle',
)
