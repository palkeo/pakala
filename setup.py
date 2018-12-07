# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pakala',
    version='1.0.3',

    description='An EVM symbolic execution tool and vulnerability scanner',

    long_description=long_description,
    long_description_content_type='text/markdown',

    url='https://github.com/palkeo/pakala',

    author='palkeo',

    author_email='ethereum@palkeo.com',

    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',

        'Programming Language :: Python :: 3',
    ],

    keywords='ethereum evm symbolic execution vulnerability scanner',

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    install_requires=['ethereum', 'claripy', 'web3'],

    extras_require={
        'test': ['mock'],
    },
)
