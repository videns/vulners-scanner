# Ansible playbook for vulners.com audit

This is the sample ansible playbook to check for vulnerabilities in your packages via new vulners.com audit API.

Populate hosts file with your hosts (currently checked on Debian 8, Ubuntu 14.04 and Cento 6.8).

Edit `- hosts: centos` part of vulners-check.yml to match your hosts and groups.
If you need to debug playbook, uncomment `strategy: debug` part.

Run with:

```
ansible-playbook vulners-check.yml
```

Sample output (fresh CentOS install):

```
...
...
...
                    "ntpdate-4.2.6p5-10.el6.centos.x86_64": {
                        "CESA-2016:1141": [
                            {
                                "OSVersion": "6",
                                "bulletinPackage": "ntpdate-4.2.6p5-10.el6.centos.1.x86_64",
                                "bulletinVersion": "4.2.6p5-10.el6.centos.1",
                                "operator": "lt",
                                "providedPackage": "ntpdate-4.2.6p5-10.el6.centos.x86_64",
                                "providedVersion": "0:4.2.6p5-10.el6.centos",
                                "result": true
                            }
                        ]
                    },
                    "openssl-1.0.1e-48.el6.x86_64": {
                        "CESA-2016:0996": [
                            {
                                "OSVersion": "6",
                                "bulletinPackage": "openssl-1.0.1e-48.el6_8.1.x86_64",
                                "bulletinVersion": "1.0.1e-48.el6_8.1",
                                "operator": "lt",
                                "providedPackage": "openssl-1.0.1e-48.el6.x86_64",
                                "providedVersion": "0:1.0.1e-48.el6",
                                "result": true
                            }
                        ]
                    }
                },
                "vulnerabilities": [
                    "CESA-2016:1292",
                    "CESA-2016:0996",
                    "CESA-2016:1141",
                    "CESA-2016:1547",
                    "CESA-2013:0620",
                    "CESA-2016:1406"
                ]
            },
            "result": "OK"
        }
    }
}
```
