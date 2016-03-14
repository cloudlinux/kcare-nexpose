# Kcare-nexpose
The script marks vulnerabilities detected by Nexpose, but patched by KernelCare as exceptions.

### Installation

```sh
$ python setup.py install
$ pip install -r REQUIREMENTS
```

### How it works
The script finds related CVE in Kernelcare ePortal and report in the Nexpose.
If all CVE is patched for one vulnerability in Kernelcare script adds this vulnerability as 
 exception in Nexpose. The script also can approve this exception in the Nexpose 
(approve by default, if you wan't approve please set to false `is_approve` in the config).
 
The first you should generate report in Nexpose (see supported type below) and to specify it
in the config file.
Also you need to specify other parameters:
```sh
$ cp /usr/local/etc/kcare-nexpose.yml.template /usr/local/etc/kcare-nexpose.yml
$ vim /usr/local/etc/kcare-nexpose.yml
```


### How to launch

```sh
$ kcare-nexpose -c /usr/local/etc/kcare-nexpose.yml
```

### Supported type's reports

 - ns-xml