from setuptools import setup, find_packages
import os
import re

NAME = "sharem"
VERSION = "0.1.02"
REQUIREMENTS = [
    #"ssdeep>=3.4",
    "capstone",
    "Cython==0.29.27",
    "colorama>=0.4.4",
    "pycos>=4.12.1",
    "dispy==4.15.0",
    "numpy>=1.19.5",
    "future",
    "netifaces>=0.11.0",
    "pefile",
    "psutil>=5.8.0",
    "pypiwin32>=223 ; platform_system=='Windows'",
    "toml>=0.9.6",
    "unicorn>=1.0.2",
    "textwrap3>=0.9.2",
    "urllib3"

]

setup(
    name=NAME,
    author='SHAREM',
    description='Shellcode Analaysis Framework - Emualtor, Disassembler, and More',
    version=VERSION,
    long_description="Words",
    url='https://github.com/',
    include_package_data=True,
    packages=find_packages(),
    install_requires=REQUIREMENTS,
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=3.6',
)

