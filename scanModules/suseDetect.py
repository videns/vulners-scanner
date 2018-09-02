# -*- coding: utf-8 -*-
__author__ = 'holmboe'
import re

from scanModules.linuxDetect import linuxDetect


class rpmBasedDetect(linuxDetect):
    def __init__(self,sshPrefix):
        self.supportedFamilies = ('redhat', 'centos', 'oraclelinux', 'suse', 'fedora')
        super(rpmBasedDetect, self).__init__(sshPrefix)

    def osDetect(self):
        osDetection = super(rpmBasedDetect, self).osDetect()
        if osDetection:
            (osVersion, osFamily, osDetectionWeight) = osDetection

            if osFamily in self.supportedFamilies:
                osDetectionWeight = 60
                return (osVersion, osFamily, osDetectionWeight)

        version = self.sshCommand("cat /etc/SuSE-release").splitlines()[0]
        if version:
            osVersion = re.search("\w{4}\s+(\d+)",version).group(1)
            osFamily = "sles"
            osDetectionWeight = 70
            return (osVersion, osFamily, osDetectionWeight)

    def getPkg(self):
        pkgList = self.sshCommand("rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | grep -v '^kernel-'")
        uname = self.sshCommand("uname -r").rstrip("-default")
        pkgList += self.sshCommand("rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | grep '^kernel.*" + uname + "'")
        return pkgList.splitlines()

