def ns_xml(root, kc_info):
    devices = root.find('devices')
    for device in devices:
        device_id = device.get('id')
        ip = device.get('address')
        if ip in kc_info.keys():
            vulns = device.find('vulnerabilities')
            for vuln in vulns:
                cve_set = set(cve.text for cve in vuln.findall('id[@type="cve"]'))
                if cve_set and kc_info[ip] >= cve_set:
                    yield vuln.get('id'), device_id, ip
