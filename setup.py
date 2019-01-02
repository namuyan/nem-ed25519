#!/user/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


try:
    with open('README.md', encoding='utf8') as f:
        readme = f.read()
except IOError:
    readme = ''


install_requires = [
    'pycryptodomex',
    'git+https://github.com/jameshilliard/pysha3@pypy3',
    'gmpy_cffi'
]

# for pypy3
# git+https://github.com/jameshilliard/pysha3@pypy3
# gmpy_cffi


setup(
    name="nem_ed25519",
    version='0.0.11',
    url='https://github.com/namuyan/nem-ed25519',
    author='namuyan',
    description='Encryption modules applied to NEM.',
    long_description=readme,
    packages=find_packages(),
    license="MIT Licence",
    install_requires=install_requires,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: MIT License',
    ],
)
