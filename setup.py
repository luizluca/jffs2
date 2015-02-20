#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

import jffs2

setup(
    name="jffs2",
    version=jffs2.__version__,
    packages=['jffs2'],
    classifiers=[
        "Environment :: Console",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Topic :: System :: Filesystems",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4"
    ],
    scripts=[
        'jffs2extract'
    ],
    author="Antti Häyrynen",
    author_email="hayrynen@codenomicon.com",
    long_description=open('README').read(),
)
