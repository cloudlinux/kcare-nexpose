%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print (get_python_lib())")}

Name:		kcare-nexpose
Version:	1.0.0
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
* Fri Mar 11 2016 Nikolay Telepenin <ntelepenin@cloudlinux com> - 1.0.0-1
- initial build for Cloud Linux

* Fri Mar 25 2016 Nikolay Telepenin <ntelepenin@cloudlinux com> - 1.0.1-1
- Remove requests from requirements
