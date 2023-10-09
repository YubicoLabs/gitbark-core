#!/usr/bin/env python


"""
Setup script for `bark_core`
"""


from setuptools import setup, find_packages

setup(
    name="bark-core",
    version="0.0.1",
    packages=find_packages(),
    install_requires=['pgpy>=0.6.0', 'paramiko>=3.3.0.0', 'pygit2>=1.12.12'],
)
