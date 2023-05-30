import os
import logging
import json
import pprint
import requests

from oauth2_client.credentials_manager import CredentialManager, ServiceInformation, OAuthError
from oauth2_client.http_server import read_request_parameters, _ReuseAddressTcpServer

_logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG,
                    format='%(levelname)5s - %(name)s -  %(message)s')

scopes = ['connectors.self:write-resource', 'connectors.self:read-resource']
client_id = "1234"
client_secret = "1234"

service_information = ServiceInformation('https://api.vanta.com/oauth/authorize',
                                         'https://api.vanta.com/oauth/token',
                                         client_id,
                                         client_secret,
                                          scopes)
manager = CredentialManager(service_information)
redirect_uri = 'http://localhost:8080/oauth/code'

# Builds the authorization url and starts the local server according to the redirect_uri parameter
url = manager.init_authorize_code_process(redirect_uri, 'state_test')
_logger.info('Open this url in your browser\n%s', url)

code = manager.wait_and_terminate_authorize_code_process()
# From this point the http server is opened on 8080 port and wait to receive a single GET request
# All you need to do is open the url and the process will go on
# (as long you put the host part of your redirect uri in your host file)
# when the server gets the request with the code (or error) in its query parameters
_logger.debug('Code got = %s', code)
manager.init_with_authorize_code(redirect_uri, code)
_logger.debug('Access got = %s', manager._access_token)
# Here access and refresh token may be used with self.refresh_token

url = "https://api.vanta.com/v1/resources/static_analysis_code_vulnerability_connectors/sync_all"

os.environ["CODE_DIR"] = os.getcwd()
os.system("docker run -e CODE_DIR -e LIC -e SNYK_TOKEN -v ${PWD}:${PWD}  -ti  scanmycode/scanmycode3-ce:worker-cli /bin/sh -c 'cd $CODE_DIR && git config --global --add safe.directory $CODE_DIR &&  checkmate init'")
os.system("docker run -e CODE_DIR -e LIC -e SNYK_TOKEN -v ${PWD}:${PWD}  -ti  scanmycode/scanmycode3-ce:worker-cli /bin/sh -c 'cd $CODE_DIR && git config --global --add safe.directory $CODE_DIR && checkmate git init'")
os.system("docker run -e CODE_DIR -e LIC -e SNYK_TOKEN -v ${PWD}:${PWD}  -ti  scanmycode/scanmycode3-ce:worker-cli /bin/sh -c 'cd $CODE_DIR && git config --global --add safe.directory $CODE_DIR && checkmate git analyze --branch `git rev-parse --abbrev-ref HEAD`'")
os.system("docker run -e CODE_DIR -e LIC -e SNYK_TOKEN -v ${PWD}:${PWD}  -ti  scanmycode/scanmycode3-ce:worker-cli /bin/sh -c 'cd $CODE_DIR && git config --global --add safe.directory $CODE_DIR && checkmate issues html'")


f = open("report.json")
report = json.load(f)

payload = {}
payload["resources"] = []
vuln = {}
vuln1 = {}
occur = []
for item in report:
  vuln["displayName"] = item["description"]
  vuln["uniqueId"] = item["hash"]
  vuln["externalUrl"] = "none"
  vuln["severity"] = 10
  vuln["confidence"] = 10
  vuln["vulnerableComponentUniqueId"] = item["hash"]
  vuln["description"] = item["description"]
  vuln["remediationInstructions"] = "Please resolve according to the descritpion"
  
  vuln1["path"] = item["file"]
  vuln1["beginLine"] = item["line"]
  vuln1["endLine"] = item["line"]
  vuln1["beginColumn"] = 0
  vuln1["endColumn"] = 0
  vuln["occurences"] = vuln1
  payload["resources"].append(vuln)
  payload["sourceId"] = "1234"
  payload["resourceId"] = "1234"
  vuln = {}


headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": manager._access_token
}

response = requests.put(url, json=payload, headers=headers)

print(response.text)


