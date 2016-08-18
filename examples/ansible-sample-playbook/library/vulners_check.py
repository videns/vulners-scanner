#!/usr/bin/python
__author__ = 'lctrcl'
# original API code by @videns
# https://github.com/videns/vulners-scanner/blob/master/linuxScanner.py
from ansible.module_utils.basic import *
import json
import ast
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

VULNERS_LINKS = {'pkgChecker':'https://vulners.com/api/v3/audit/audit/',
                 'bulletin':'https://vulners.com/api/v3/search/id/?id=%s'}

def vulnersCheck(os_distrib, os_version, os_packages):

    os_packages_list = ast.literal_eval(os_packages)
    payload = {'os':os_distrib,
               'version':os_version,
               'package':os_packages_list}

    headers = {
    'Content-Type': 'application/json'
    }
    httpPayload = json.dumps(payload).encode('utf-8')
    req = urllib2.Request(VULNERS_LINKS.get('pkgChecker'), headers=headers, data=httpPayload)
    response = urllib2.urlopen(req)

    responseData = response.read()
    if isinstance(responseData, bytes):
        responseData = responseData.decode('utf8')
    responseData = json.loads(responseData)

    status = 'ok'
    msg = responseData
    return status, msg
def main():

    fields = {
        "os_distrib": {"required": True, "type": "str"},
        "os_version": {"required": True, "type": "str"},
        "os_packages": {"required": True},
    }

    module = AnsibleModule(argument_spec=fields)
    os_distrib = module.params['os_distrib']
    os_version = module.params['os_version']
    os_packages = module.params['os_packages']
    status, msg = vulnersCheck(os_distrib, os_version, os_packages)
    module.exit_json(msg=msg)

if __name__ == '__main__':
    main()
