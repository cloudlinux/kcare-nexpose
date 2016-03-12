"""
Functions for parsing reports and comparing CVE info in reports and in Kernelcare

What type of reports is implemented:
- ns-xml

Full list of types:
- csv
- db
- html
- ns-xml
- pdf
- qualys-xml
- raw-xml
- raw-xml-v2
- rtf
- scap-xml
- text
"""

__author__ = 'Nikolay Telepenin'
__copyright__ = "Cloud Linux Zug GmbH 2016, KernelCare Project"
__credits__ = 'Nikolay Telepenin'
__license__ = 'Apache License v2.0'
__maintainer__ = 'Nikolay Telepenin'
__email__ = 'ntelepenin@kernelcare.com'
__status__ = 'beta'
__version__ = '1.0'


def ns_xml(root, kc_info):
    """
    Parsing NS-XML report and comparing CVE info in the Kernelcare

    :param root: root XML element in the report
    :param kc_info: dict - key is device-id, value is set of CVE
    :return: Iterator tuple (vulnerability-id, device-id, ip address)
    """
    devices = root.find('devices')
    for device in devices:
        device_id = device.get('id')
        ip = device.get('address')
        if ip in kc_info.keys():
            vulns = device.find('vulnerabilities')
            for vuln in vulns:

                # for support python 2.6
                # it can't find with 'id[@type="cve"]' and havn't iterfind
                cve_set = set(item.text
                              for item in vuln.findall('id')
                              if item.get('type') == 'cve')

                if cve_set and kc_info[ip] >= cve_set:
                    yield vuln.get('id'), device_id, ip
