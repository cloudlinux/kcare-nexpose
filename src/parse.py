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
                cve_set = set()
                for item in vuln.findall('id'):
                    if item.get('type') == 'cve':
                        cve_set.add(item.text)

                if cve_set and kc_info[ip] >= cve_set:
                    yield vuln.get('id'), device_id, ip
