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
from UtilsLibFuzzing import Utils, detection, logParsing

from requests.exceptions import ConnectionError
requests.packages.urllib3.disable_warnings()  # supress https warnings
######################################################################
######################################################################
u = Utils()  # create instance
dt = detection() # create instance
lg = logParsing()
master_log_file = 'log.txt'
logging.basicConfig(filename=master_log_file, filemode='w+', level=logging.INFO)
#######################################################################

def post_request(url, postdata):
    '''this method is passed into the async function
    e.g.
    executor.submit(post_request,  #: function that makes the request
                                                 target_url,    #: End point url ( arguments to teh function) post_request
                                                 postdata)) #: postdata ( argument to the function post_request
    if the arguments of this function changes that need to reflected. 
    '''
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
    print(resp)
    result = ''
    if resp:
        try:
            req = json.dumps(json.loads(resp.request.body), ensure_ascii=False)
        except:
            req = resp.request.body

        code = resp.status_code
        log_prefix = dt.detect_in_response(resp, http_status_codes=[200, 201], result_prefix='PASS')
        
    else:
        result, resp, code, req = 'UNKNOWN', 'NA', 'NA', 'NA'
        log_prefix = 'network_issue-UNKNOWN'

    logging.info(time.ctime())

    logging.info('{l}-result:-resp:{resp}-request body:{req}-status:{code}'.format(#result=result,
                                                                              resp=resp,
                                                                              req=req,
                                                                              code=code,
                                                                              l=log_prefix))


def execute_async(no_of_parallel_req, 
                  target_url,
                  mal_source,
                  orig_json):
    '''this can fire multiple simultaneous requests using async '''
    set_all_requests = set()
    with cf.ThreadPoolExecutor(max_workers=no_of_parallel_req) as executor:
        for postdata, val, key in u.postdata_generator_with_insecure_values_ee(orig_json, mal_source):
            set_all_requests.add(executor.submit(post_request,  #: function that makes the request
                                                 target_url,    #: End point url
                                                 postdata))     #: post data with malicious data

        for future in set_all_requests:
            resp = future.result()
            process_resp(resp)



def process_log(log_file):
    lg.parse(log_file)
    logging.info('log parsing finished')
    logging.disable = True

## execution starts here ############

if __name__ == '__main__':
    print('hi')
    a = {1:'hi'}
    api_url_enroll = 'https://digiXXX.com'
    mal_file = 'all-attacks-unix.txt'

    execute_async(no_of_parallel_req=6, 
                target_url=api_url_enroll, 
                mal_source=mal_file,
                orig_json=a)
    process_log(master_log_file)
    print('bye')


