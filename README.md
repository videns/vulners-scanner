# vulners-scanner
# Description
PoC of a host-based vulnerability scanner, which uses vulners.com API. Detects operating system, collects installed packages and checks vulnerabilities in it.
# Supported OS
Currently support collecting packages for these operating systems:
* Debian-based (debian, kali, ubuntu)
* Rhel-based (redhat, centos, fedora)

# Docker support
Experimental support of detecting vulnerabilities in running docker containters


# How to use
* Lazy scanner
The simplest script to show vulners API capabilities. Just run script and it will return all found vulnerabilities:
```
#python2.6 lazyScanner.py
OS Name - debian, OS Version - 8
Total provided packages: 315
{
    "data": {
        "vulnerabilities": [
            "DSA-3644",
            "DSA-3626"
        ],
        "packages": {            
            "openssh-client 1:6.7p1-5+deb8u2 amd64": {
                "DSA-3626": [
                    {
                        "bulletinVersion": "1:6.7p1-5+deb8u3",
                        "providedVersion": "1:6.7p1-5+deb8u2",
                        "bulletinPackage": "openssh-client_1:6.7p1-5+deb8u3_all.deb",
                        "result": true,
                        "operator": "lt",
                        "OSVersion": "8",
                        "providedPackage": "openssh-client 1:6.7p1-5+deb8u2 amd64"
                    }
                ]
            }
            "fontconfig-config 2.11.0-6.3 all": {
                "DSA-3644": [
                    {
                        "bulletinVersion": "2.11.0-6.3+deb8u1",
                        "providedVersion": "2.11.0-6.3",
                        "bulletinPackage": "fontconfig-config_2.11.0-6.3+deb8u1_all.deb",
                        "result": true,
                        "operator": "lt",
                        "OSVersion": "8",
                        "providedPackage": "fontconfig-config 2.11.0-6.3 all"
                    }
                ]
            },
            "libfontconfig1 2.11.0-6.3 amd64": {
                "DSA-3644": [
                    {
                        "bulletinVersion": "2.11.0-6.3+deb8u1",
                        "providedVersion": "2.11.0-6.3",
                        "bulletinPackage": "libfontconfig1_2.11.0-6.3+deb8u1_all.deb",
                        "result": true,
                        "operator": "lt",
                        "OSVersion": "8",
                        "providedPackage": "libfontconfig1 2.11.0-6.3 amd64"
                    }
                ]
            }
        }
    },
    "result": "OK"
}
Vulnerabilities:
DSA-3644
DSA-3626
```


