%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print (get_python_lib())")}

Name:		kcare-nexpose
Version:	1.2.2
Release:	1%{?dist}
Summary:	The script marks vulnerabilities detected by Nexpose, but patched by KernelCare as exceptions

Group:		Applications/System
License:	Apache License v2.0
URL:		http://www.kernelcare.com
Source0:	%{name}-%{version}.tar.gz

BuildArch:   noarch

BuildRequires:	python-setuptools python-requests PyYAML
Requires:	python-requests PyYAML

%description
The script marks vulnerabilities detected by Nexpose, but patched by KernelCare as exceptions

%prep
%setup -q %{name}-%{version}

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
%{__python} setup.py install -O1 --skip-build --root %{buildroot}

%files
%doc README.md REQUIREMENTS LICENSE
/usr/local/etc/kcare-nexpose.yml.template
/usr/bin/kcare-nexpose
%{python_sitelib}/kcare_nexpose-*.egg-info
%dir %{python_sitelib}/kcare_nexpose
%{python_sitelib}/kcare_nexpose/__init__.py*
%{python_sitelib}/kcare_nexpose/main.py*
%{python_sitelib}/kcare_nexpose/nexpose_client.py*
%{python_sitelib}/kcare_nexpose/parse.py*
%{python_sitelib}/kcare_nexpose/patches.py*

%changelog
* Fri May 4 2018 Igor Seletskiy <iseletsk@kernelcare.com> - 1.2.2-1
- Backward compatibility for SSL Handing for python 2.6
- Fix for error on custom exceptions

* Tue May 1 2018 Igor Seletskiy <iseletsk@kernelcare.com> - 1.2.0-1
- Added ability to delete old exceptions by specifying delete_old in yaml config file
- Improved SSL handing for python 2.7 and higher

* Fri Mar 30 2018 Igor Seletskiy <iseletsk@kernelcare.com> - 1.1.4-1
- if we cannot get report_format from report_config, get it from script config
- or default to raw-xml-v2
- add support for parsing new format/longer CVE numbers

* Wed Mar 28 2018 Igor Seletskiy <iseletsk@kernelcare.com> - 1.1.2-1
- fixed raw_xml_v2 parser

* Mon Mar 26 2018 Igor Seletskiy <iseletsk@kernelcare.com> - 1.1.1-1
- raw_xml_v2 report format uses names when avaialble

* Sun Mar 25 2018 Igor Seletskiy <iseletsk@kernelcare.com> - 1.1.0-1
- Added support for raw_xml_v2 report format
- Weakened SSL checks
- Fixed ns-xml format when CVE is in upper case

* Sun Jun 28 2016 Nikolay Telepenin <ntelepenin@cloudlinux com> - 1.0.3-1
- Added ckeck for kernel_id from Kernelcare ePortal

* Thu Apr 21 2016 Nikolay Telepenin <ntelepenin@cloudlinux com> - 1.0.2-1
- Support original server https://cln.cloudlinux.com for getting licenses and patches

* Fri Mar 25 2016 Nikolay Telepenin <ntelepenin@cloudlinux com> - 1.0.1-1
- Remove requests from requirements

* Fri Mar 11 2016 Nikolay Telepenin <ntelepenin@cloudlinux com> - 1.0.0-1
- initial build for Cloud Linux
