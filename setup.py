# coding: utf-8
from distutils.core import setup

from setuptools import find_packages

with open("REQUIREMENTS") as f:
    requirements = [i.strip() for i in f.readlines()]


def read(fname):
    try:
        with open(fname, 'r') as f:
            return f.read()

    except IOError:
        return ''


setup(
    name='kcare-nexpose',
    license='Apache License v2.0',
    version='1.0',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    install_requires=requirements,
    long_description=read('README'),
    url='',
    author='CloudLinux',
    author_email='ntelepenin@cloudlinux.com',
    description='The script marks vulnerabilities detected by Nexpose, but patched by KernelCare as exceptions'
)
