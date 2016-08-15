# -*- coding: utf-8 -*-
__author__ = 'videns'
from osDetect import ScannerInterface
import re

class linuxDetect(ScannerInterface):
    def osDetect(self):
        version = self.sshCommand("cat /etc/os-release")
        if version:
            osFamily = re.search("^ID=\"?(.*?)\"?",version,re.MULTILINE).group(1)
            osVersion = re.search("^VERSION_ID=\"?(.*?)\"?",version,re.MULTILINE).group(1)
            osDetectionWeight = 50
            return (osVersion, osFamily, osDetectionWeight)

