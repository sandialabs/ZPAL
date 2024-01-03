"""setup.py file."""
from setuptools import setup, find_packages

with open("README.md", "r") as f:
    readme = f.read()


__author__ = "Simon Reeser <streese@sandia.gov>"

requires = [
    'requests>=2.27.1',
    'setuptools>=39.2.0'

]
setup(
    name="zpal",
    version="1.0.0",
    packages=find_packages(where='src'),
    package_dir={"":"src"},
        test_suite="test_base",
    author="Sarah Ashley, Roscoe Hill, Francis Oroyan, Simon Reeser",
    author_email="snashle@sandia.gov, roshill@sandia.gov, fdoroyan@sandia.gov, streese@sandia.gov",
    description="ZPE API Abstraction Layer",
    license="Apache 2.0",
    long_description=readme,
    long_description_content_type="text/markdown",
    classifiers=[
        "Topic :: Utilities",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    url="https://github.com/snl",
    include_package_data=True,
    install_requires=requires,
    python_requires='>=3.6',
)
