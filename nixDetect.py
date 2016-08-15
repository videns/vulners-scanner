# -*- coding: utf-8 -*-
__author__ = 'videns'
from osDetect import ScannerInterface
import re

class nixDetect(ScannerInterface):
    def osDetect(self):
        osFamily = self.sshCommand("uname -s")
        osVersion = self.sshCommand("uname -r")
        if osFamily and osVersion:
            osDetectionWeight = 10
            return (osVersion, osFamily, osDetectionWeight)

