"""
Classes and functions for working with Kernelcare ePortal.
"""
import logging
import re

import urllib2

__author__ = 'Nikolay Telepenin'
__copyright__ = "Cloud Linux Zug GmbH 2016, KernelCare Project"
__credits__ = 'Nikolay Telepenin'
__license__ = 'Apache License v2.0'
__maintainer__ = 'Nikolay Telepenin'
__email__ = 'ntelepenin@kernelcare.com'
__status__ = 'beta'
__version__ = '1.0.0'

pattern = re.compile(r'(CVE-\d{4}-\d{4})', re.MULTILINE)

logger = logging.getLogger(__name__)


class KernelCarePortal(object):
    def __init__(self, host, port, keys):
        self.host = host
        self.port = port
        self.keys = keys

        self._cve_cache = {}

    def get_kernel_cve(self, kernel_id, level):
        """
        Get CVE info from kernel id and level from Kernelcare ePortal

        :param kernel_id: Kernel identifier in ePortal
        :param level: Kernel level patch in ePortal
        :return: set of CVE
        """

        req = urllib2.Request(
            url='http://{0}:{1}/{2}/{3}/kpatch.info'.format(
                self.host, self.port, kernel_id, level
            )
        )
        response = urllib2.urlopen(req)
        text = response.read()
        return set(re.findall(pattern, text))

    def get_instances(self):
        """
        Get all devices in Kernelcare ePortal
        :return: list of tuple (ip, kernel_id, level)
        """
        result = set()
        for key in self.keys:
            req = urllib2.Request(
                url='http://{0}:{1}/admin/api/kcare/patchset/{2}'.format(
                    self.host, self.port, key
                )
            )

            response = urllib2.urlopen(req)
            result_by_key = set()
            for line in response.readlines():
                ip, kernel_id, level = line.strip().split(',')
                result_by_key.add((ip, kernel_id, level))

            logger.info('Found {0} instances from "{1}" key'.format(
                len(result_by_key), key
            ))
            result.update(result_by_key)

        return result

    def get_cve_info(self):
        """
        Return instances with their CVE info
        1. Get all registerd instances in the Kernelcare ePortal
        2. For each instances try to look up cve info

        :return: dict {ip: set of CVE}
        """
        instances = self.get_instances()
        kc_info = {}
        cve_cache = {}
        for ip, kernel_id, level in instances:

            if int(level) > 0:
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
                        'Kernelcare ePortal'.format(len(cve_info), ip))

                kc_info[ip] = cve_info

        return kc_info
