# Kcare-nexpose
The script marks vulnerabilities detected by Nexpose, but patched by KernelCare as exceptions.

## Table of Contents
* [Installation](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#installation)
    * [From YUM repo](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#from-yum-repository)
    * [From github](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#from-github)
* [How it works](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#how-it-works)
* [How to launch](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#how-to-launch)
* [Supported type's reports](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#supported-types-reports)
* [YAML config file description](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#yaml-config-file-description)

## Installation

### From yum repository

To install kcare-nexpose, start with the minimal image of EL6:
```sh
$ cat > /etc/yum.repos.d/kcare-eportal.repo <<EOL
[kcare-eportal]
name=kcare-eportal
baseurl=http://repo.eportal.kernelcare.com/x86_64/
gpgkey=http://repo.cloudlinux.com/kernelcare-debian/6/conf/kcaredsa_pub.gpg
enabled=1
gpgcheck=1
EOL
```

Install kcare-nexpose:
```sh
$ yum install kcare-nexpose
```

### From github

```sh
$ git clone https://github.com/cloudlinux/kcare-nexpose.git
$ cd kcare-nexpose/
$ python setup.py install
$ pip install -r REQUIREMENTS
```

## How it works
The script finds related CVE from patch server (for example Kernelcare ePortal or
original patch server https://cln.cloudlinux.com/api/kcare) and report in the Nexpose.
If all CVE is patched for one vulnerability in Kernelcare script adds this vulnerability as 
 exception in Nexpose. The script also can approve this exception in the Nexpose 
(approve by default, if you wan't approve please set to false `is_approve` in the config).
 
The first you should generate report in Nexpose ([see supported type below](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#supported-types-reports)) and to specify it
in the config file.
Also you need to specify other parameters ([see below](https://github.com/cloudlinux/kcare-nexpose/blob/master/README.md#yaml-config-file-description)):
```sh
$ cp /usr/local/etc/kcare-nexpose.yml.template /usr/local/etc/kcare-nexpose.yml
$ vim /usr/local/etc/kcare-nexpose.yml
```

**Important!**
IP addressed in the Nexpose and int the patch server should be the **same**. 
If you use Nexpose and KC ePortal on different instances you should to check Nexpose and 
KC ePortal not using *localhost (127.0.0.1)*.
Otherwise kcare-nexpose can mark vulnerability wrong: 
it's just analyze ip addresses from Nexpose and KC ePortal.

If you want to use kcare-nexpose **with** servers behind [NAT](https://en.wikipedia.org/wiki/Network_address_translation) 
make sure you use XML Export 2.0 (raw-xml-v2) format, and *patchset.json?key=* as
server source.


## How to launch

```sh
$ kcare-nexpose -c /usr/local/etc/kcare-nexpose.yml
```

## Supported type's reports

 - ns-xml  Nexpose<sup>tm</sup> Simple XML Export
 - raw-xml-v2 XML Export 2.0 (recommended)
 
## YAML config file description

```yaml
# Nexpose section
nexpose:

  # Host to connect with Nexpose Security Console
  host: 178.204.226.194

  # Port to connect with Nexpose Security Console
  port: 3780

  # Username to auth with Nexpose Security Console
  username: user

  # Password to auth with Nexpose Security Console
  password: hup^r37kZc72MjY}=ox?WTQ

  # Report name which will be analyze for look up related CVE with kernelcare ePortal
  report-name: kc-report

  # If needed to approve exception. If it false - only finds and adds vulnerability in the exception list
  is_approve: true
  
  # Report type (XML Export 2.0 recommended).
  format: raw-xml-v2

# Patch server section
patch-server:

  # URL to connect with Kernelcare ePortal
  # For kernelcare ePortal use "http://<kernel-care-eportal-domain-name-or-ip>/admin/api/kcare/patchset/"
  # For original server use "https://cln.cloudlinux.com/api/kcare/patchset/"
  # To use hostnames instead of IPs (requires raw-xml-v2): 
  # https://cln.cloudlinux.com/api/kcare/patchset.json?key=
   server: https://cln.cloudlinux.com/api/kcare/patchset.json?key=

  # Server for patch sets
  # For patch sets from server Kernelcare ePortal use domain name
  # (or ip addresses)
  # patches-info: http://<kernel-care-eportal-domain-name-or-ip>

  # For patch sets from original server
  patches-info: http://patches.kernelcare.com/

  # List of keys
  keys:
    - 0G0996952sTtCU4z
    - hx5LO1n49zY5jp6B

```
