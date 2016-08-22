# -*- coding: utf-8 -*-
__author__ = 'videns'
import re

from scanModules.osDetect import ScannerInterface


class linuxDetect(ScannerInterface):
    def osDetect(self):
        version = self.sshCommand("cat /etc/os-release")
        if version:
            osFamily = re.search("^ID=\"?(.*)\"?",version,re.MULTILINE).group(1).lower()
            osVersion = re.search("^VERSION_ID=\"?([0-9\.]+)\"?",version,re.MULTILINE).group(1).lower()
            osVersion = osVersion.split(".")[0]
            osDetectionWeight = 50
            return (osVersion, osFamily, osDetectionWeight)

