import setuptools

setuptools.setup(
    name='SHAREM',
    author='SHAREM',
    description='Shellcode Analaysis Framework - Emualtor, Disassembler, and More',
    version=0.01,
    long_description="Words",
    url='https://github.com/',
    include_package_data=True,
    install_requires=[
        "capstone",
        "colorama>=0.4.4",
        "pycos>=4.12.1",
        "dispy==4.15.0",
        "numpy==1.19.5",
        "future",
        "netifaces>=0.11.0",
        "pefile",
        "psutil>=5.8.0",
        "pypiwin32",
        "toml>=0.9.6",
        "unicorn>=1.0.2",

    ],
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=3.6',
)

