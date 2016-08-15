# -*- coding: utf-8 -*-
__author__ = 'videns'
from linuxDetect import linuxDetect
import re

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
        if version:
            osVersion = re.search("(\d+)\.",version).group(1)
            osFamily = "debian"
            osDetectionWeight = 60
            return (osVersion, osFamily, osDetectionWeight)


    def getPkg(self):
        pkgList = self.sshCommand("dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'")
        return pkgList.splitlines()


