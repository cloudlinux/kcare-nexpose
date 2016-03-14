from distutils.core import setup

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
    version='1.0.0',
    packages=['kcare_nexpose'],
    package_dir={'': 'src'},
    long_description=read('README.md'),
    url='https://github.com/cloudlinux/kcare-nexpose',
    author='CloudLinux',
    author_email='ntelepenin@cloudlinux.com',
    description='The script marks vulnerabilities detected by Nexpose, '
                'but patched by KernelCare as exceptions',
    data_files=[
        ('local/etc', ['src/configs/kcare-nexpose.yml.template']),
        ('local/bin', ['src/scripts/kcare-nexpose']),
    ],
    install_requires=requirements,
    include_package_data=True,
    entry_points={
        'console_scripts':
            ['kcare-nexpose = kcare_nexpose.main:main']
    },
    classifiers=[
        "Programming Language :: Python",
    ]
)
