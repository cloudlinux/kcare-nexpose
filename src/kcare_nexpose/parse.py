"""
Functions for parsing reports and comparing CVE info in reports and in the
patch server (for example KernelCare eportal or offical Kernelcare patch
server)

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
__version__ = '1.0.3'


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
                              if str(item.get('type')).lower() == 'cve')

                if cve_set and kc_info[ip] >= cve_set:
                    yield vuln.get('id'), device_id, ip

def raw_xml_v2(root, kc_info):
    """
    Parsin RAW XML v2  report and comparing CVE info in the KernelCare

    :param root: root XML element in the report
    :param kc_info: dict - key is device-id, value is set of CVE
    :return: Iterator tuple (vulnerability-id, device-id, hostname
    """

    # Init vulnerability definitions
    vulns = {}
    vulnNodes = root.findall('./VulnerabilityDefinitions/vulnerability')
    for v in vulnNodes:
        id = v.get('id')
        cve = v.find("references/reference/[@source='CVE']")
        if cve is not None:
            vulns[id]=cve.text


    nodes = root.findall('./nodes/node')
    for node in nodes:
        # get node IP, device_id & names. we want ot use names in the future
        ip=node.get('address')
        device_id=node.get('device-id')
        names=[]
        namesNode = node.findall('./names/name')
        for name in namesNode:
            names.append(name.text)
        names.append(ip)

        if ip in kc_info.keys():

            testsNode = node.findall('./tests/test')
            for test in testsNode:
                id = test.get('id')
                if id in vulns:
                    cve = vulns[id]
                    if kc_info['USE_HOSTNAME']:
                        for name in names:
                            if cve in kc_info[name]:
                                yield id, device_id, name
                                break
                    else:
                        if cve is not None:
                            vulns[id] = cve.text

