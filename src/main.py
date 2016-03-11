import logging
import sys

import config
from nexpose_client import ReportSummaryStatus, NexposeClient
from parse import ns_xml
from patches import KernelCarePortal

__author__ = 'Nikolay Telepenin'
__copyright__ = "Cloud Linux Zug GmbH 2016, KernelCare Project"
__credits__ = 'Nikolay Telepenin'
__license__ = 'Apache License v2.0'
__maintainer__ = 'Nikolay Telepenin'
__email__ = 'ntelepenin@kernelcare.com'
__status__ = 'beta'
__version__ = '1.0'

SUPPORTED_FORMATS = {
    'ns-xml': ns_xml
}

logger = logging.getLogger(__name__)


def main(report_name):
    eportal = KernelCarePortal(**config.config['kernelcare-eportal'])
    instances = eportal.get_instances()

    with NexposeClient(**config.config['nexpose']) as client:

        # find report by name
        reports = client.report_listing()
        logger.info('Get report listing')

        for report in reports:
            if report.get('name') == report_name:
                if report.get('status') != ReportSummaryStatus.GENERATED:
                    logger.error('Report "{0}" is not generated'.format(report_name))
                    sys.exit(1)
                break
        else:
            logger.error('Report "{0}" not found'.format(report_name))
            sys.exit(1)

        report_uri = report.get('report-URI')

        # check supported formats
        report_config = client.report_config(report.get('cfg-id'))
        logger.info('Get report config: {0}'.format(report.get('cfg-id')))

        report_format = report_config.get('format')
        if report_format not in SUPPORTED_FORMATS.keys():
            logger.error('Report format "{0}" unsupported. Supported formats: "{1}"'.format(
                report_format, SUPPORTED_FORMATS.keys()
            ))
            sys.exit(1)

        # get KC info about patched CVE
        kc_info = {}
        for ip, kernel_id, level in instances:

            if int(level) > 0:
                cve_info = eportal.get_kernel_cve(kernel_id, level)
                logger.info('Found {0} cve for ip "{1}" from Kernelcare'.format(
                    len(cve_info), ip
                ))

                kc_info[ip] = cve_info

        if not kc_info:
            logger.error('Empty information about kernelcare CVE')
            sys.exit(1)

        # get report & find related CVE
        root = client.get_report(report_uri)
        logger.info('Get report from uri - "{0}"'.format(report_uri))
        vulnerabilities = SUPPORTED_FORMATS[report_format](root, kc_info)

        is_approve = config.config['nexpose']['is_approve']
        for vuln_id, device_id, ip in vulnerabilities:
            exception_id = client.create_exception_for_device(vuln_id, device_id)
            logger.info('Mark vulnerability "{0}" for ip "{1}" as exception'.format(
                vuln_id, ip
            ))

            if is_approve:
                client.approve_exception(exception_id)
                logger.info('Approve exception "{0}" for ip "{1}"'.format(
                    vuln_id, ip
                ))

        if is_approve:
            logger.info('Don\'t forget regenerate "{0}" report'.format(report_name))


if __name__ == '__main__':
    main(config.config['nexpose']['report-name'])
