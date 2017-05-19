# -*- coding: utf-8 -*-
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



import requests
import sys
import time



from  UtilsLibFuzzing_v1 import Utils
from requests.exceptions import ConnectionError
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
      "orgName": "xxxxxx",
      "orgUnit": "Eng",
      "address": {
        "addressLine1": "4201 norwalk dr1",
        "addressLine2": "",
        "addressLine3": "",
        "phoneNumber": "",
        "city": "san jose",
        "state": "$california$",
        "country": "us",
        "zip": "95129"}

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
api_url_enroll = 'https://xxxxxxxxxxxxxxxxx.net/ssl/v1/enroll'
#mal_file = ["alert}>'><script>alert(<fin2000>)</script>"]
mal_file = 'test.txt'

########################################################################
time_i = str(time.ctime()).replace(' ', '-').replace(':', '-')
enroll_fail_file = 'Enroll_Fail_' + time_i + '.txt'
enroll_pass_file = enroll_fail_file.replace('Fail', 'Pass')
network_issues_file = enroll_fail_file.replace('Fail', 'network_issues')

open(enroll_fail_file, 'w').close()  # create the files if does not exist
open(enroll_pass_file, 'w').close()  # create teh file if does not exist
open(network_issues_file, 'w').close()

########################################################################
loop = asyncio.get_event_loop()
set_all_requests = set()


def post_request(url, postdata):
    try:
        print(json.dumps(postdata, ensure_ascii=False), time.ctime())
        resp = requests.post(api_url_enroll,
                             json=postdata,
                             verify=False)

    except ConnectionError:
        print('-' * 20)
        print('----Connection Issues---')
        print('-' * 20)
    return resp

def process_resp(resp):
        if resp.status_code in [200, 201]:
            outputfile = enroll_pass_file
        else:
            outputfile = enroll_fail_file
            print(resp.status_code)
            u.write_details_to_file_ee(outputfile,
                                           resp.request.body,
                                           'POST response : Here is output::'+ resp.text,
                                           'Status Code::' + str(resp.status_code),
                                           '=END=' * 5)


async def execute_async(no_of_parallel_req=1):
    with concurrent.futures.ThreadPoolExecutor(max_workers=no_of_parallel_req) as executor:
        for postdata, val, key in u.postdata_generator_with_insecure_values_ee(a, mal_file):

            set_all_requests.add(loop.run_in_executor(executor, post_request, api_url_enroll, postdata))
    
        for future in set_all_requests:
            resp = await future
            process_resp(resp)



loop.run_until_complete(execute_async(no_of_parallel_req=4))
