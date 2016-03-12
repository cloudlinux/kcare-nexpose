# Kcare-nexpose
The script marks vulnerabilities detected by Nexpose, but patched by KernelCare as exceptions.

### Installation

```sh
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
$ cp src/config.yaml.template src/config.yaml
$ vim src/config.yaml
```


### How to launch

```sh
$ cd src
$ python main.py
```

### Supported type's reports

 - ns-xml