# -*- coding: utf-8 -*-
__author__ = 'videns'
import inspect
import pkgutil
import json
import os
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

import osDetect

VULNERS_LINKS = {'pkgChecker':'https://vulners.com/api/v3/audit/audit/',
                 'bulletin':'https://vulners.com/api/v3/search/id/?id=%s'}


class scannerEngine():
    def __init__(self):
        self.osInstanceClasses = self.getInstanceClasses()

    def getInstanceClasses(self):
        self.detectors = None
        members = set()
        for modPath, modName, isPkg in pkgutil.iter_modules([os.path.realpath(os.path.dirname(__file__))]):
            #find all classed inherited from scanner.osDetect.ScannerInterface in all files
            members = members.union(inspect.getmembers(__import__(modName),
                                         lambda member:inspect.isclass(member)
                                                       and issubclass(member,osDetect.ScannerInterface)
                                                       and member.__module__ == modName
                                                       and member != osDetect.ScannerInterface))
        return members

    def getInstance(self,sshPrefix):
        inited = [instance[1](sshPrefix) for instance in self.osInstanceClasses]
        osInstance = max(inited, key=lambda x:x.osDetectionWeight)
        if osInstance.osDetectionWeight:
            return osInstance

    def auditSystem(self, sshPrefix, systemInfo=None):
        instance = self.getInstance(sshPrefix)
        installedPackages = instance.getPkg()
        print("="*20)
        if systemInfo:
            print("Host info - %s" % systemInfo)
        print("OS Name - %s, OS Version - %s" % (instance.osFamily, instance.osVersion))
        print("Total provided packages: %s" % len(installedPackages))
        if not installedPackages:
            return instance
        # Get vulnerability information
        payload = {'os':instance.osFamily,
                   'version':instance.osVersion,
                   'package':installedPackages}
        req = urllib2.Request(VULNERS_LINKS.get('pkgChecker'))
        req.add_header('Content-Type', 'application/json')
        response = urllib2.urlopen(req, json.dumps(payload).encode('utf-8'))
        responseData = response.read()
        if isinstance(responseData, bytes):
            responseData = responseData.decode('utf8')
        responseData = json.loads(responseData)
        resultCode = responseData.get("result")
        if resultCode == "OK":
            print(json.dumps(responseData, indent=4))
            print("Vulnerabilities:\n%s" % "\n".join(responseData.get('data').get('vulnerabilities')))
        else:
            print("Error - %s" % responseData.get('data').get('error'))
        return instance

    def scan(self, checkDocker = False):
        #scan host machine
        hostInstance = self.auditSystem(sshPrefix=None,systemInfo="Host machine")
        #scan dockers
        if checkDocker:
            containers = hostInstance.sshCommand("docker ps")
            if containers:
                containers = containers.splitlines()[1:]
                dockers = [(line.split()[0], line.split()[1]) for line in containers]
                for (dockerID, dockerImage) in dockers:
                    sshPrefix = "docker exec %s" % dockerID
                    self.auditSystem(sshPrefix, "docker container \"%s\"" % dockerImage)
                pass


if __name__ == "__main__":
    scannerInstance = scannerEngine()
    scannerInstance.scan(checkDocker=True)
