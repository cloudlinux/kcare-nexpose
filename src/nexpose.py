import logging
import random
from abc import ABCMeta

import requests
from lxml import etree as ET
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

VERSION_1_1 = '1.1'
VERSION_1_2 = '1.2'


class ExceptionReason(object):
    FALSE_POSITIVE = 'False Positive'
    COMPENSATING_CONTROL = 'Compensating Control'
    ACCEPTABLE_USE = 'Acceptable Use'
    ACCEPTABLE_RISK = 'Acceptable Risk'
    OTHER = 'Other'


class ExceptionScope(object):
    ALL_INSTANCES = 'All Instances'
    ALL_INSTANCES_ON_SPECIFIC_ASSET = 'All Instances on a Specific Asset'
    SPECIFIC_INSTANCE_OF_SPECIFIC_ASSET = 'Specific Instance of Specific Asset'


class VulnerabilityDetailInstance(object):
    def __init__(self, elem):
        self.elem = elem

    @property
    def description(self):
        elem = self.elem.find('.//description')
        return elem.text

    @property
    def references(self):
        elem = self.elem.find('.//references')
        result = {}
        for child in elem:
            result.setdefault(child.attrib['source'], []).append(child.text)
        return result


class Request(object):
    def __init__(self, serveraddr, port):
        self.serveraddr = serveraddr
        self.port = port

    def send(self, data, protocol):
        response = self._make_request(protocol, data)
        return ET.XML(response.content)

    def _make_request(self, protocol, data):
        return requests.post(
            url='https://%(serveraddr)s:%(port)s/api/%(protocol)s/xml' % {
                'serveraddr': self.serveraddr,
                'port': self.port,
                'protocol': protocol
            },
            data=data,
            headers={
                'Content-Type': 'text/xml',
                'Accept': '*/*',
                'Cache-Control': 'no-cache'
            },
            verify=False
        )


class Element(object):
    __metaclass__ = ABCMeta

    request_tag = response_tag = None

    def __init__(self):
        self.attr_dict = {}

    def __str__(self):
        return ET.tostring(
            ET.Element(self.request_tag, self.attr_dict)
        )


class SessionElement(Element):
    __metaclass__ = ABCMeta


class LoginElement(Element):
    request_tag = 'LoginRequest'
    response_tag = 'LoginResponse'

    def __init__(self, login, password):
        super(LoginElement, self).__init__()
        self.attr_dict = {
            'user-id': login,
            'password': unicode(password)
        }


class LogoutElement(SessionElement):
    request_tag = 'LogoutRequest'
    response_tag = 'LogoutResponse'


class ReportListingElement(SessionElement):
    request_tag = 'ReportListingRequest'
    response_tag = 'ReportListingResponse'


class ReportConfigElement(SessionElement):
    request_tag = 'ReportConfigRequest'
    response_tag = 'ReportConfigResponse'

    def __init__(self, config_id):
        super(ReportConfigElement, self).__init__()
        self.attr_dict = {
            'reportcfg-id': config_id
        }


class ReportTemplateListingElement(SessionElement):
    request_tag = 'ReportTemplateListingRequest'
    response_tag = 'ReportTemplateListingResponse'


class VulnerabilityListingElement(SessionElement):
    request_tag = 'VulnerabilityListingRequest'
    response_tag = 'VulnerabilityListingResponse'


class VulnerabilityDetailsElement(SessionElement):
    request_tag = 'VulnerabilityDetailsRequest'
    response_tag = 'VulnerabilityDetailsResponse'

    def __init__(self, vuln_id):
        super(VulnerabilityDetailsElement, self).__init__()
        self.attr_dict = {
            'vuln-id': vuln_id
        }


class VulnerabilityExceptionCreateElement(SessionElement):
    request_tag = 'VulnerabilityExceptionCreateRequest'
    response_tag = 'VulnerabilityExceptionCreateResponse'

    def __init__(self, vuln_id, reason, scope, device_id=None):
        super(VulnerabilityExceptionCreateElement, self).__init__()
        self.attr_dict = {
            'vuln-id': vuln_id,
            'reason': reason,
            'scope': scope,
            'device-id': device_id
        }


class VulnerabilityExceptionApproveElement(SessionElement):
    request_tag = 'VulnerabilityExceptionApproveRequest'
    response_tag = 'VulnerabilityExceptionApproveResponse'

    def __init__(self, exception_id):
        super(VulnerabilityExceptionApproveElement, self).__init__()
        self.attr_dict = {
            'exception-id': exception_id
        }


class NexposeClient(object):
    def __init__(self, host, port, username, password, *args, **kwargs):
        self.request = Request(host, port)
        self.host = host
        self.port = port
        self.username = username
        self.password = password

        self.session_id = None

    def login(self):
        response = self.send(
            LoginElement(self.username, self.password)
        )
        logger.info('Login with "{}"'.format(self.username))
        self.session_id = response.attrib['session-id']

    def logout(self):
        self.send(LogoutElement())
        logger.info('Logout "{}"'.format(self.username))

    def send(self, elem, protocol=VERSION_1_2):
        sync_id = str(random.randint(1, 1000))
        if isinstance(elem, SessionElement):
            elem.attr_dict['session-id'] = self.session_id
            elem.attr_dict['sync-id'] = sync_id

        response = self.request.send(str(elem), protocol)
        if response.tag != elem.response_tag:
            raise Exception("Wrong API answer:\n{}".format(
                ET.tostring(response)))

        if protocol == VERSION_1_2 and isinstance(elem, SessionElement) and response.attrib['sync-id'] != sync_id:
            raise Exception('Different sync-id from request "{}" and response "{}"'.format(
                sync_id, response.attrib['sync-id']
            ))

        return response

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def vulnerability_listing(self):

        elem = VulnerabilityListingElement()
        response = self.send(elem)
        return response

    def vulnerability_details(self, vuln_id):
        elem = VulnerabilityDetailsElement(vuln_id)
        response = self.send(elem)
        return VulnerabilityDetailInstance(response)

    def report_listing(self):
        elem = ReportListingElement()
        response = self.send(elem, VERSION_1_1)
        return response

    def report_config(self, config_id):
        elem = ReportConfigElement(config_id)
        response = self.send(elem, VERSION_1_1)
        return response.find('ReportConfig')

    def report_template_listing(self):
        elem = ReportTemplateListingElement()
        response = self.send(elem, VERSION_1_1)
        return response

    def get_report(self, uri):
        url = 'https://{}:{}/{}'.format(
            self.host, self.port, uri
        )
        response = requests.get(url, verify=False, cookies={
            'nexposeCCSessionID': self.session_id
        })
        return ET.XML(response.content)

    def create_exception_for_device(self, vuln_id, device_id):
        elem = VulnerabilityExceptionCreateElement(
            vuln_id=vuln_id,
            reason=ExceptionReason.COMPENSATING_CONTROL,
            scope=ExceptionScope.ALL_INSTANCES_ON_SPECIFIC_ASSET,
            device_id=device_id)
        response = self.send(elem)
        return response.get('exception-id')

    def approve_exception(self, exception_id):
        elem = VulnerabilityExceptionApproveElement(exception_id)
        response = self.send(elem)
        return response
