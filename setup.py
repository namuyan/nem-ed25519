#!/user/env python3
# -*- coding: utf-8 -*-

from distutils.core import setup
from setuptools import find_packages
from distutils.extension import Extension
from Cython.Distutils import build_ext

try:
    with open('README.md') as f:
        readme = f.read()
except IOError:
    readme = ''


def _requires_from_file(filename):
    return open(filename).read().splitlines()


ext_modules = [Extension(
    name="nem_ed25519.outer", sources=["nem_ed25519/outer.pyx"])]


setup(
    name="nem_ed25519",
    version='0.0.9',
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
    cmdclass={'build_ext': build_ext},
    ext_modules=ext_modules
)
