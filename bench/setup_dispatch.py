#!/usr/bin/env python3
"""Standalone builder for the libpcap dispatch ceiling extension.

Build in place from the packets checkout root with:

    python3 bench/setup_dispatch.py build_ext --inplace

This produces ``bench/pcap_dispatch_bench*.so`` next to the source, which
``compare_libs.py --libs libpcap`` imports (it runs with ``bench`` on the
import path). It is intentionally separate from the package ``setup.py`` so
building the benchmark ceiling never rebuilds or disturbs the installed
``packets`` package.
"""
from __future__ import print_function
import os

from setuptools import setup, Extension
from Cython.Build import cythonize

HERE = os.path.dirname(os.path.abspath(__file__))

extensions = [
    Extension(
        'pcap_dispatch_bench',
        [os.path.join('bench', 'pcap_dispatch_bench.pyx')],
        libraries=['pcap'],
    ),
]

setup(
    name='pcap_dispatch_bench',
    # Map the (root) package to bench/ so ``build_ext --inplace`` drops the
    # built .so into bench/ next to the .pyx, where compare_libs.py finds it,
    # even though the build is launched from the checkout root.
    package_dir={'': 'bench'},
    ext_modules=cythonize(extensions, language_level=3),
)
