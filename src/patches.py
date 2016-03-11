import logging
import re
import urllib2

pattern = re.compile(r'(CVE-\d{4}-\d{4})', re.MULTILINE)

logger = logging.getLogger(__name__)


class KernelCarePortal(object):
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key

        self._cve_cache = {}

    def get_kernel_cve(self, kernel_id, level):
        patch_hash = '%s,%s' % (kernel_id, level)
        cve_from_cache = self._cve_cache.get(patch_hash)
        if cve_from_cache:
            cves = cve_from_cache

        else:
            req = urllib2.Request(
                url='http://{0}:{1}/{2}/{3}/kpatch.info'.format(
                    self.host, self.port, kernel_id, level
                )
            )
            response = urllib2.urlopen(req)
            text = response.read()
            cves = set(re.findall(pattern, text))
            self._cve_cache[patch_hash] = cves

        return cves

    def get_instances(self):
        req = urllib2.Request(
            url='http://{0}:{1}/admin/api/kcare/patchset/{2}'.format(
                self.host, self.port, self.key
            )
        )

        response = urllib2.urlopen(req)
        result = [line.strip().split(',') for line in response.readlines()]
        # logging.debug("Servers: {}".format(result))
        return result
