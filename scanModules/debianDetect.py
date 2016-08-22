# -*- coding: utf-8 -*-
__author__ = 'videns'
import re

from scanModules.linuxDetect import linuxDetect


class debBasedDetect(linuxDetect):
    def __init__(self,sshPrefix):
        self.supportedFamilies = ('debian','ubuntu', 'kali')
        super(debBasedDetect, self).__init__(sshPrefix)

    def osDetect(self):
        osDetection = super(debBasedDetect, self).osDetect()
        if osDetection:
            (osVersion, osFamily, osDetectionWeight) = osDetection

            if osFamily in self.supportedFamilies:
                osDetectionWeight = 60
                return (osVersion, osFamily, osDetectionWeight)

        version = self.sshCommand("cat /etc/debian_version")
        if version and re.search("(\d+)\.",version):
            osVersion = re.search("(\d+)\.",version).group(1)
            osFamily = "debian"
            osDetectionWeight = 60
            return (osVersion, osFamily, osDetectionWeight)

        version = self.sshCommand("cat /etc/lsb-release")
        if version:
            mID = re.search("^DISTRIB_ID=\"?(.*?)\"?",version,re.MULTILINE)
            mVer = re.search("^DISTRIB_RELEASE=\"?(.*?)\"?", version, re.MULTILINE)
            if mID and mVer:
                osFamily = mID.group(1).lower()
                osVersion = mVer.group(1).lower()
                osDetectionWeight = 60
                return (osVersion, osFamily, osDetectionWeight)



    def getPkg(self):
        pkgList = self.sshCommand("dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'")
        return pkgList.splitlines()


