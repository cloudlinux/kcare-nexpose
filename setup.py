# coding: utf-8
from distutils.core import setup

INSTALL_REQUIRES = [
    'fusepy',
    'celery',
    'sqlalchemy',
    'psycopg2',
    'bottle',
    'pyyaml',
    'boto3']

setup(
    name='kcare-nexpose',
    version='',
    packages=[''],
    package_dir={'': 'src'},
    url='',
    license='',
    author='CloudLinux',
    author_email='ntelepenin@cloudlinux.com',
    description='This can mark related vulnerabilities as exceptions in Nexpose from Kernelcare'
)
