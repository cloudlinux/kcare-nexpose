%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print (get_python_lib())")}

Name:		kcare-nexpose
Version:	1.0.0
Release:	1%{?dist}
Summary:	The script marks vulnerabilities detected by Nexpose, but patched by KernelCare as exceptions.

Group:		Applications/System
License:	Apache License v2.0
URL:		http://www.kernelcare.com
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	python-requests PyYAML
Requires:	python-requests PyYAML

%description
The script marks vulnerabilities detected by Nexpose, but patched by KernelCare as exceptions.

%prep
%setup -q %{name}-%{version}

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
%{__python} setup.py install -O1 --skip-build --root %{buildroot}

%files
%doc README.md REQUIREMENTS LICENSE
%{python_sitelib}/config.py*
%{python_sitelib}/config.yml.template
%{python_sitelib}/kcare_nexpose-*.egg-info
%{python_sitelib}/main.py*
%{python_sitelib}/nexpose_client.py*
%{python_sitelib}/parse.py*
%{python_sitelib}/patches.py*

%changelog
* Fri Mar 11 2016 Nikolay Telepenin <ntelepenin@cloudlinux com> - 1.0.0-1
- initial build for Cloud Linux