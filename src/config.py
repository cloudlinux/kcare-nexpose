import logging

import yaml

__author__ = 'Nikolay Telepenin'
__copyright__ = "Cloud Linux Zug GmbH 2016, KernelCare Project"
__credits__ = 'Nikolay Telepenin'
__license__ = 'Apache License v2.0'
__maintainer__ = 'Nikolay Telepenin'
__email__ = 'ntelepenin@kernelcare.com'
__status__ = 'beta'
__version__ = '1.0'

with open('config.yml') as yaml_config:
    config = yaml.load(yaml_config)

logging.basicConfig(
    format=u'%(levelname)-8s [%(asctime)s] %(message)s',
    level=logging.INFO,
    filename=u'working.log')

logging.getLogger().addHandler(logging.StreamHandler())

logging.getLogger("requests").setLevel(logging.WARNING)
