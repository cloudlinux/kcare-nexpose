import logging

import config
import nexpose
from parse import ns_xml
from patches import KernelCarePortal

SUPPORTED_FORMATS = {
    'ns-xml': ns_xml
}
GENERATED = 'Generated'

logger = logging.getLogger(__name__)


def main(name):
    eportal = KernelCarePortal(**config.config['kernelcare-eportal'])
    instances = eportal.get_instances()

    with nexpose.NexposeClient(**config.config['nexpose']) as client:

        # find report by name
        reports = client.report_listing()
        logger.info('Get report listing')

        for report in reports:
            if report.get('name') == name:
                if report.get('status') != GENERATED:
                    raise Exception('Report "{}" is not generated'.format(name))
                break
        else:
            raise Exception('Report "{}" not found'.format(name))

        report_uri = report.get('report-URI')

        # check supported formats
        report_config = client.report_config(report.get('cfg-id'))
        logger.info('Get report config: {}'.format(report.get('cfg-id')))

        report_format = report_config.get('format')
        if report_format not in SUPPORTED_FORMATS.keys():
            raise Exception('Report format "{}" unsupported. Supported formats: "{}"'.format(
                report_format, SUPPORTED_FORMATS.keys()
            ))

        # get KC info about patched CVE
        kc_info = {}
        for ip, kernel_id, level in instances:
            if int(level) > 0:
                cve_info = eportal.get_kernel_cve(kernel_id, level)
                logger.info('Found {} cve for ip "{}" from Kernelcare'.format(
                    len(cve_info), ip
                ))
                kc_info[ip] = cve_info

        if not kc_info:
            raise Exception('Empty information about kernelcare CVE')

        # get report & find related CVE
        root = client.get_report(report_uri)
        logger.info('Get report from uri - "{}"'.format(report_uri))
        vulnerabilities = SUPPORTED_FORMATS[report_format](root, kc_info)

        is_approve = config.config['nexpose']['is_approve']
        for vuln_id, device_id, ip in vulnerabilities:
            exception_id = client.create_exception_for_device(vuln_id, device_id)
            logger.info('Mark vulnerability "{}" for ip "{}" as exception'.format(
                vuln_id, ip
            ))

            if is_approve:
                client.approve_exception(exception_id)
                logger.info('Approve exception "{}" for ip "{}"'.format(
                    vuln_id, ip
                ))

        if is_approve:
            logger.info('Don\'t forget regenerate "{}" report'.format(name))


if __name__ == '__main__':
    main(config.config['nexpose']['report-name'])
