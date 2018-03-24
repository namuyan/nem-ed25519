#!/user/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


try:
    with open('README.md') as f:
        readme = f.read()
except IOError:
    readme = ''


def _requires_from_file(filename):
    return open(filename).read().splitlines()

setup(
    name="nem_ed25519",
    version='0.0.6',
    url='https://github.com/namuyan/nem-ed25519',
    author='namuyan',
    description='Encryption modules applied to NEM.',
    long_description=readme,
    packages=find_packages(),
    license="MIT Licence",
    install_requires=['pycryptodomex', 'pysha3'],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: MIT License',
    ],
)
