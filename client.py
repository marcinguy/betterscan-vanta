import os
import logging
import json
import pprint
import requests
from collections import defaultdict
from oauth2_client.credentials_manager import CredentialManager, ServiceInformation, OAuthError
from oauth2_client.http_server import read_request_parameters, _ReuseAddressTcpServer

_logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG,
                    format='%(levelname)5s - %(name)s -  %(message)s')

scopes = ['connectors.self:write-resource', 'connectors.self:read-resource']
client_id = "vci_"
client_secret = "vcs_"
source_id = "acct1234"


tokens = {}
try:
    f = open("tokens.json", "r")
    tokens = json.load(f)
    f.close()
except:
  tokens["access_token"] = ""
  tokens["refresh_token"] = ""





if not tokens["access_token"]:
  print("here")
  service_information = ServiceInformation('https://app.vanta.com/oauth/authorize',
                                         'http://api.vanta.com/oauth/token',
                                         client_id,
                                         client_secret,
                                         scopes)
  manager = CredentialManager(service_information)
  redirect_uri = 'http://localhost:8080/oauth/code'

  # Builds the authorization url and starts the local server according to the redirect_uri parameter
  url = manager.init_authorize_code_process(redirect_uri, 'state_test')
  url = url + "&source_id="+source_id
  _logger.info('Open this url in your browser\n%s', url)

  code = manager.wait_and_terminate_authorize_code_process()
  # From this point the http server is opened on 8080 port and wait to receive a single GET request
  # All you need to do is open the url and the process will go on
  # (as long you put the host part of your redirect uri in your host file)
  # when the server gets the request with the code (or error) in its query parameters
  _logger.debug('Code got = %s', code)
  # manager.init_with_authorize_code(redirect_uri, code+"&source_id=app1234")
  # pprint.pprint(manager)

  payload = {'client_id': client_id,
           'client_secret': client_secret,
           'code': code,
           'source_id': source_id,
           'redirect_uri': redirect_uri,
           'grant_type': "authorization_code"
           }

  x = requests.post("http://api.vanta.com/oauth/token", json=payload)

  response = json.loads(x.text)
  access_token = response['access_token']
  refresh_token = response['refresh_token']

  tokens["access_token"] = access_token
  tokens["refresh_token"] = refresh_token
  pprint.pprint(tokens)

  f = open("tokens.json","w")
  f.write(json.dumps(tokens))
  f.close()

url = "https://api.vanta.com/v1/resources/static_analysis_code_vulnerability_connectors/sync_all"

os.environ["CODE_DIR"] = os.getcwd()
os.system("docker run -e CODE_DIR -e LIC -e SNYK_TOKEN -v ${PWD}:${PWD}  -ti  scanmycode/scanmycode3-ce:worker-cli /bin/sh -c 'cd $CODE_DIR && git config --global --add safe.directory $CODE_DIR &&  checkmate init'")
os.system("docker run -e CODE_DIR -e LIC -e SNYK_TOKEN -v ${PWD}:${PWD}  -ti  scanmycode/scanmycode3-ce:worker-cli /bin/sh -c 'cd $CODE_DIR && git config --global --add safe.directory $CODE_DIR && checkmate git init'")
os.system("docker run -e CODE_DIR -e LIC -e SNYK_TOKEN -v ${PWD}:${PWD}  -ti  scanmycode/scanmycode3-ce:worker-cli /bin/sh -c 'cd $CODE_DIR && git config --global --add safe.directory $CODE_DIR && checkmate git analyze --branch `git rev-parse --abbrev-ref HEAD`'")
os.system("docker run -e CODE_DIR -e LIC -e SNYK_TOKEN -v ${PWD}:${PWD}  -ti  scanmycode/scanmycode3-ce:worker-cli /bin/sh -c 'cd $CODE_DIR && git config --global --add safe.directory $CODE_DIR && checkmate issues html'")

f = open("report.json","r")
report = json.load(f)
f.close()

payload = {}
payload["resources"] = []
vuln = {}
vuln["occurrences"] = []

vuln1 = {}
vulns = []

i = 0
for item in report:
    vuln["displayName"] = item["description"]
    vuln["uniqueId"] = item["hash"]
    vuln["externalUrl"] = "none"
    vuln["severity"] = 10
    vuln["confidence"] = 10
    vuln["isResolvable"] = True
    vuln["vulnerableComponentUniqueId"] = item["hash"]
    vuln["description"] = item["description"]
    vuln["remediationInstructions"] = "Please resolve according to the description"

    vuln1["path"] = item["file"]
    vuln1["beginLine"] = int(item["line"])
    vuln1["endLine"] = int(item["line"])
    vuln1["beginColumn"] = int(0)
    vuln1["endColumn"] = int(0)
    vulns.append(vuln1)
    vuln["occurrences"] = vulns
    payload["resources"].append(vuln)
    payload["sourceId"] = source_id
    payload["resourceId"] = "6482f64c865e267eff077874"
    vuln = {}
    vuln1 = {}
    vulns = []
    i = i+1

headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+tokens["access_token"]
}
print(headers)
print(json.dumps(payload))
response = requests.put(url, json=json.dumps(payload), headers=headers)
print(response.text)

if response.status_code == 401:

    f = open("tokens.json", "r")
    tokens = json.load(f)
    f.close()
    payload = {'client_id': client_id,
           'client_secret': client_secret,
           'refresh_token': tokens["refresh_token"],
           'grant_type': "refresh_token"
    }

    x = requests.post("http://api.vanta.com/oauth/token", json=payload)
    tokens_response = json.loads(x.text)

    f = open("tokens.json","w")
    f.write(json.dumps(tokens_response))
    f.close()

    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+tokens_response["access_token"]
    }
    
    
    response = requests.put(url, json=json.dumps(payload), headers=headers)
    print(response.text)
