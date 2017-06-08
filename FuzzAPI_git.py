# -*- coding: utf-8 -*-
'''
Set Up:
    ::python 3(preferred) flavor of  (miniconda) installed
Usage:
    ::mal_file -> a file name containing malicious strings: 'xss.txt'
                  OR
               -> a list of values haing malicious strings : ["alert}>'><script>alert(<fin2000>)</script>", "<script>alert(<fin2000>)</script>", ...]
               Each malicious string is set for all the keys in the json structure and posted

Dependency: UtilsLibFuzzing.py in the same directory as that of script
'''
import concurrent.futures as cf
import json
import logging
import requests
import time
from UtilsLibFuzzing import Utils
from requests.exceptions import ConnectionError
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
logging.basicConfig(filename='log.txt', filemode='w+', level=logging.INFO)
#######################################################################

def post_request(url, postdata):
    try:
        print(time.ctime())
        with requests.session() as s:
            resp = s.post(url=api_url_enroll,
                          json=postdata,
                          verify=False)
        return resp

    except ConnectionError:
        print('-' * 20)
        print('----Connection Issues---')
        print('-' * 20)
        return None


def process_resp(resp):
    if resp is not None:
        req = json.dumps(json.loads(resp.request.body), ensure_ascii=False)
        code = resp.status_code

        if resp.status_code in [200, 201]:
            result = 'PASS'
        else:
            result = 'FAIL'
            print(resp.status_code)
    else:
        result, resp, code, req = 'UNKNOWN', 'NA', 'NA', 'NA'
    logging.info(time.ctime())
    logging.info('result:{result}-resp:{resp}-request:{req}-status:{code}'.format(result=result,
                                                                                  resp=resp,
                                                                                  req=req,
                                                                                  code=code))


def execute_async(no_of_parallel_req, 
                  target_url,
                  mal_source,
                  orig_json):
    set_all_requests = set()
    with cf.ThreadPoolExecutor(max_workers=no_of_parallel_req) as executor:
        for postdata, val, key in u.postdata_generator_with_insecure_values_ee(orig_json, mal_source):
            set_all_requests.add(executor.submit(post_request,  #: function that makes the request
                                                 target_url,    #: End point url
                                                 postdata))     #: post data with malicious data

        for future in set_all_requests:
            resp = future.result()
            process_resp(resp)

api_url_enroll = 'https://xxxx.net/ssl/v1/enroll'
mal_file = 'test.txt'

execute_async(no_of_parallel_req=10, 
              target_url=api_url_enroll, 
              mal_source=mal_file,
              orig_json=a)



