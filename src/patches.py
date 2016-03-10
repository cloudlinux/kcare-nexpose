import re
import urllib2

pattern = re.compile(r'(CVE-\d{4}-\d{4})', re.MULTILINE)


class KernelCarePortal(object):
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key

    def get_kernel_cve(self, kernel_id, level):
        req = urllib2.Request(
            url='http://{}:{}/{}/{}/kpatch.info'.format(
                self.host, self.port, kernel_id, level
            )
        )
        response = urllib2.urlopen(req)
        text = response.read()
        cves = set(re.findall(pattern, text))
        # logging.debug("CVES: {}".format(cves))
        return cves

    def get_instances(self):
        req = urllib2.Request(
            url='http://{}:{}/admin/api/kcare/patchset/{}'.format(
                self.host, self.port, self.key
            )
        )

        response = urllib2.urlopen(req)
        result = [line.strip().split(',') for line in response.readlines()]
        # logging.debug("Servers: {}".format(result))
        return result
