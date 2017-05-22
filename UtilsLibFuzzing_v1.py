"""
Set up: Works with python 2 or python 3 version  miniconda(out of box)
Usage: take an input dictionary/json ( all valid inputs)
      return an dictionary/json ( with one value replaced by string
      from the xss/sql string file)
      Works for commercial/EE apis
Note: 'yield' is heavily used, helps to separate test data creation logic from use


__maintainer__: debadityamohankudo+github at gmail dot com
"""
import pickle
import os
import time
import copy
import codecs
import json
import hashlib

class Utils(object):
    """docstring for Utils"""

    def __init__(self):
        pass






    """
    def postdata_generator_with_insecure_values(self, filename, input_dict, specific_params=None):
        parameters_list = specific_params  if specific_params is not None else input_dict.keys()
        for parameter in parameters_list:
            print('-' * 60)
            print('parameter targeted : {param}'.format(param=parameter))
            
            print('-' * 60)
            for value in generate_insecure_strings(filename):
                    print('-' * 20)
                    print('value is:{v}'.format(v=value))
                    
                    print('-' * 20)
                    output_dict = input_dict.copy()
                    output_dict[parameter] = value
                    yield output_dict"""


    def generate_insecure_strings(self, mal_data):
        # yield is for lazy binding -> iterator pattern
        # http://stackoverflow.com/questions/2223882/whats-different-between-utf-8-and-utf-8-without-bom
        # encoding used to remove BOM char in mal input issue
        if isinstance(mal_data, str):
            if os.path.isfile(mal_data):
                for line in codecs.open(mal_data, 'r').readlines():
                    data = line.rstrip('\n').rstrip('\r')
                    if data != '':
                        #print(data) # dotn delete this works
                        yield data
        else:
            for data in mal_data:
                    yield data





    def write_details_to_file_ee(self, filename, *args):
        for arg in args:
            with open(filename, 'a') as f:
                if isinstance(arg, (list, dict)):
                    json.dump(arg, f, ensure_ascii=False)
                else:
                    f.write(str(arg))



    def parse_json_get_items(self, a_object,
                             str_malicious=None,
                             key=None,  
                             get_item=True,
                             set_item=False):
        ''' this function does two operations
        1. When get_item is true -> gets all key value pairs in self.list_k,
        2. When set_item is true -> sets the value for one key to malicious
        3. When there are duplicate keys like zip, try giving unique values
        4. What is the use of key parameter: key is to be supplied from the temp list_k
        '''

        if not hasattr(self, 'done_set_item'): # dont delete this: used while reading json
            self.done_set_item = False 
        if not hasattr(self, 'list_k'):
                        self.list_k = []  # stores all key-val pairs - one time execution

        if not self.done_set_item:  # if set quit the function
            if isinstance(a_object, list):
                for item in a_object:
                    if isinstance(item, (list, dict)): # can list appear in list?
                        self.parse_json_get_items(a_object=item, 
                                                  str_malicious=str_malicious, 
                                                  key=key,
                                                  get_item=get_item, 
                                                  set_item=set_item)
                    else:
                        self.parse_json_get_items(a_object=(item, a_object),
                                                  str_malicious=str_malicious,
                                                  key=key,
                                                  get_item=get_item,
                                                  set_item=set_item)


            elif isinstance(a_object, dict):
                for item in a_object:
                    if isinstance(a_object[item], (dict, list)):
                        self.parse_json_get_items(a_object=a_object[item], 
                                                  str_malicious=str_malicious,
                                                  key=key, 
                                                  get_item=get_item, 
                                                  set_item=set_item)
                    else:
                        self.parse_json_get_items(a_object=(item, a_object),
                                                  str_malicious=str_malicious,
                                                  key=key, 
                                                  get_item=get_item,
                                                  set_item=set_item)

            elif isinstance(a_object, tuple): # each tuple is key, value, parent dict

                if True:
                    hashobj = hashlib.md5()
                    hashobj.update(json.dumps(a_object).encode('utf-8'))                    
                    hashobj.update(str(a_object[0]).encode('utf-8'))
                    hash_key1 = hashobj.hexdigest()

                if get_item is True:
                    if hash_key1 not in self.list_k:
                        self.list_k.append(hash_key1)

                elif set_item is True:
                    if key == hash_key1 and isinstance(a_object[1], dict):
                        a_object[1][a_object[0]] = str_malicious
                        self.done_set_item = True

                    if key == hash_key1 and isinstance(a_object[1], list):
                        a_object[1][a_object[1].index(a_object[0])] = str_malicious
                        self.done_set_item = True
                else:
                    pass


    def parse_json_set_items(self, a_object,
                             str_malicious=None,
                             key=None,
                             get_item=False,
                             set_item=True):
        self.parse_json_get_items(a_object=a_object,
                             str_malicious=str_malicious,
                             key=key,
                             get_item=False,
                             set_item=True)


    def generate_testdata_with_malicious_str_ee(self, a_json_list, str_malicious):
        self.parse_json_get_items(a_json_list) # fills the self.list_k with unique hash values
        for key in self.list_k:
            self.done_set_item = False # reset the value
            input_json = copy.deepcopy(a_json_list) #http://stackoverflow.com/questions/184643/what-is-the-best-way-to-copy-a-list
            self.parse_json_set_items(input_json, str_malicious, key, get_item=False, set_item=True)
            yield input_json, key

    def postdata_generator_with_insecure_values_ee(self, a_json_list, mal_data):
        for value in self.generate_insecure_strings(mal_data):
            for td, key in self.generate_testdata_with_malicious_str_ee(a_json_list, value):
                yield td, value, key

    def postdata_generator_with_insecure_values_get_req_ee(self, api_url_get, mal_data, target_param):
        for value in self.generate_insecure_strings(mal_data):
            if target_param != []:
                for param in target_param:
                    yield value, api_url_get.replace(param, value)


if __name__ == '__main__':
    ######################################################################
    a = [{
      "partnerOrderId": ["xxxxxx", 1, False],
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
    mal_source = ['abcccccccccccc']
    for postdata, val, key in u.postdata_generator_with_insecure_values_ee(a, mal_source):
        print(postdata)
