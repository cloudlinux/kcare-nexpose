"""
Classes and functions for working with Kernelcare patch server.
"""
import json
import logging
import re

import urllib2
import urlparse

__author__ = 'Nikolay Telepenin'
__copyright__ = "Cloud Linux Zug GmbH 2016, KernelCare Project"
__credits__ = 'Nikolay Telepenin'
__license__ = 'Apache License v2.0'
__maintainer__ = 'Nikolay Telepenin'
__email__ = 'ntelepenin@kernelcare.com'
__status__ = 'beta'
__version__ = '1.0.2'

pattern = re.compile(r'(CVE-\d{4}-\d{4})', re.MULTILINE)

logger = logging.getLogger(__name__)


class PatchServer(object):
    def __init__(self, server, keys, **kwargs):
        self.server = server
        self.keys = keys
        self.patches_info = kwargs.get('patches-info', self.server)

        self._cve_cache = {}

    def get_kernel_cve(self, kernel_id, level):
        """
        Get CVE info from kernel id and level from patch server

        :param kernel_id: Kernel identifier in patch server
        :param level: Kernel level patch in patch server
        :return: set of CVE
        """

        req = urllib2.Request(
            url='{0}/{1}/{2}/kpatch.info'.format(
                self.patches_info, kernel_id, level
            )
        )
        response = urllib2.urlopen(req)
        text = response.read()
        return set(re.findall(pattern, text))

    def get_instances(self):
        """
        Get all devices from Kernelcare patch server
        :return: list of tuple (ip, kernel_id, level)
        """
        result = []
        for key in self.keys:
            req = urllib2.Request(
                urlparse.urljoin(
                    '{0}/{1}'.format(self.server, key),
                    key
                )
            )

            response = urllib2.urlopen(req)
            response_data = response.read()
            if not response_data:
                logger.info('Not found instances from "{0}" key'.format(
                    key
                ))
            else:
                data = json.loads(response_data)['data']

                logger.info('Found {0} instances from "{1}" key'.format(
                    len(data), key
                ))
                result.extend(data)

        return result

    def get_cve_info(self):
        """
        Return instances with their CVE info
        1. Get all registered instances from Kernelcare patch server
        2. For each instances try to look up cve info

        :return: dict {ip: set of CVE}
        """
        instances = self.get_instances()
        kc_info = {}
        cve_cache = {}
        for ip, kernel_id, level in instances:

            if level and int(level) > 0:
                patch_id = kernel_id, level
                if cve_cache.get(patch_id):
                    cve_info = cve_cache[patch_id]
                    logger.info(
                        'Found {0} cve for ip "{1}" from local cache'.format(
                            len(cve_info), ip
                        ))
                else:

                    cve_info = self.get_kernel_cve(kernel_id, level)
                    cve_cache[patch_id] = cve_info
                    logger.info(
                        'Found {0} cve for ip "{1}" from '
                        'patch server "{2}"'.format(
                            len(cve_info), ip, self.patches_info))

                kc_info[ip] = cve_info

        return kc_info
