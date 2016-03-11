import logging

import yaml

with open('config.yml') as yaml_config:
    config = yaml.load(yaml_config)

logging.basicConfig(
    format=u'%(levelname)-8s [%(asctime)s] %(message)s',
    level=logging.INFO,
    filename=u'working.log')


logging.getLogger().addHandler(logging.StreamHandler())

logging.getLogger("requests").setLevel(logging.WARNING)
