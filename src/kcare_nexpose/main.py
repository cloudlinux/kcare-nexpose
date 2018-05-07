"""
Entry point into script.

Take a look help for usage:
`python main.py -h`
"""

import logging
import optparse
import os
import sys

import yaml

from nexpose_client import (
    ReportSummaryStatus,
    NexposeClient,
    ExceptionReason,
    ExceptionScope)
from parse import ns_xml, raw_xml_v2
from patches import PatchServer

__author__ = 'Nikolay Telepenin'
__copyright__ = "Cloud Linux Zug GmbH 2018, KernelCare Project"
__credits__ = 'Nikolay Telepenin'
__license__ = 'Apache License v2.0'
__maintainer__ = 'Igor Seletskiy'
__email__ = 'iseletsk@kernelcare.com'
__status__ = 'production'
__version__ = '1.2.3'

SUPPORTED_FORMATS = {
    'ns-xml': ns_xml,
    'raw-xml-v2': raw_xml_v2
}

# This is used as a comment to submit exception
# We also use it later on to remove exceptions
EXCEPTION_COMMENT = "Added by kcare-nexpose"

logging.basicConfig(
    format=u'%(levelname)-8s [%(asctime)s] %(message)s',
    level=logging.INFO,
    filename=u'working.log')

logging.getLogger().addHandler(logging.StreamHandler())

logger = logging.getLogger(__name__)


def get_generated_report(client, report):
    """
    Try to get generated report. If current report has status is GENERATED -
    return it, else try to find report in history with status GENERATED

    :param client: nexpose client
    :param report: last report
    :return: if found - report with status GENERATED else raise LookupError
    """
    if report.get('status') != ReportSummaryStatus.GENERATED:
        for report in client.report_history(report.get('cfg-id')):
            if report.get('status') == ReportSummaryStatus.GENERATED:
                break
        else:
            raise LookupError(
                'Generated report for name "{0}" not found'.format(
                    report.get('name')
                ))

    return report


def filter_exceptions(exceptions):
    """
    Filter out exceptions that were not added by kcare-nexpose

    :param exceptions: list of exceptions
    :return: list of exception-ids that were added by kcare-nexpose
    """
    result = []
    for el in exceptions.findall('./VulnerabilityException'):
        try:
            comment = el.find('./submitter-comment').text
            status = el.get('status')
            if comment == EXCEPTION_COMMENT and status != 'Deleted':
                result.append(el.get('exception-id'))
        except AttributeError:
            pass
    return result


def delete_old_exceptions(client):
    """
    Delete OLD vulnerability exceptions

    :param client: initialized nexpose client
    :return: None
    """
    # find exceptions
    exceptions = client.exceptions_listing()
    exception_ids = filter_exceptions(exceptions)
    for eid in exception_ids:
        logger.info("Removing exception ({0}) ".format(eid))
        client.exception_delete(eid)
    logger.info("Removed Old Exceptions")


def process(config):
    """
    Processing data from Nexpose and patch server

    :param config: config yml-file
    :return:
    """
    report_name = config['nexpose']['report-name']

    # get KC info about patched CVE
    patch_server = PatchServer(**config['patch-server'])
    kc_info = patch_server.get_cve_info()
    if not kc_info:
        logger.error('Empty information about kernelcare CVE')
        sys.exit(1)

    with NexposeClient(**config['nexpose']) as client:

        # find report by name
        reports = client.report_listing()
        logger.info('Get report listing')

        for report in reports:
            if report.get('name') == report_name:
                break
        else:
            logger.error('Report "{0}" not found'.format(report_name))
            sys.exit(1)

        # try to get generated report
        try:
            current_report = get_generated_report(client, report)
        except LookupError:
            logger.error('Report "{0}" is not generated'.format(report_name))
            sys.exit(1)

        report_uri = current_report.get('report-URI')

        # get report config
        report_config = client.report_config(current_report.get('cfg-id'))
        if report_config is None:
            logger.info('Unable to retrieve report config '
                        '"{0}" with id "{1}"'.format
                        (current_report.get('name'),
                         current_report.get('cfg-id')))
        logger.info('Get report config by name "{0}" with id "{1}"'.format(
            current_report.get('name'), current_report.get('cfg-id')
        ))

        # check supported formats
        if report_config is None:
            try:
                report_format = config['nexpose']['format']
            except Exception:
                report_format = 'raw-xml-v2'
        else:
            report_format = report_config.get('format')
        if report_format not in SUPPORTED_FORMATS.keys():
            logger.error(
                'Report format "{0}" unsupported. '
                'Supported formats: "{1}"'.format(
                    report_format,
                    SUPPORTED_FORMATS.keys()
                ))
            sys.exit(1)

        # get report & find related CVE
        root = client.get_report(report_uri)
        logger.info('Get report from uri - "{0}"'.format(report_uri))
        vulnerabilities = SUPPORTED_FORMATS[report_format](root, kc_info)

        # Remove old vulnerabilities?
        if config['nexpose']['delete_old']:
            delete_old_exceptions(client)

        # Add vuln to exception list
        is_approve = config['nexpose']['is_approve']
        for vuln_id, device_id, ip in vulnerabilities:
            try:
                exception_id = client.create_exception_for_device(
                    vuln_id=vuln_id,
                    device_id=device_id,
                    reason=ExceptionReason.COMPENSATING_CONTROL,
                    scope=ExceptionScope.ALL_INSTANCES_ON_SPECIFIC_ASSET,
                    comment=EXCEPTION_COMMENT
                )
                logger.info(
                    'Mark vulnerability "{0}" for "{1}" as exception'.format(
                        vuln_id, ip
                    ))

                if is_approve:
                    # Approve exception
                    client.approve_exception(exception_id,
                                             comment="Approved by kcare-nexpose")
                    logger.info('Approve exception "{0}" for "{1}"'.format(
                        vuln_id, ip
                    ))
            except Exception as e:
                if "An exception for all instances of " in e.message:
                    logger.info("Exception already exists")
                else:
                    raise e

        if is_approve:
            logger.info('Don\'t forget regenerate "{0}" report'.format(
                report_name))


def main():
    parser = optparse.OptionParser(
        description='The script marks vulnerabilities detected by Nexpose, '
                    'but patched by KernelCare as exceptions.',
        usage="%prog", version="1.0.3")
    parser.add_option(
        '-c',
        '--config',
        dest='config',
        help='Configuration file',
        default='')

    option, args = parser.parse_args()

    if not option.config:
        logger.error('Config file should be using'.format(
            option.config
        ))
        sys.exit(1)
    if not os.path.isfile(option.config):
        logger.error('Config file not found in "{0}"'.format(
            option.config
        ))
        sys.exit(1)

    with open(option.config, 'r') as yaml_config:
        config = yaml.load(yaml_config)

    process(config)


if __name__ == '__main__':
    main()
