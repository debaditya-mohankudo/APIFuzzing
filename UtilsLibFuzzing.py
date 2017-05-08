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

class Utils(object):
    """docstring for Utils"""

    def __init__(self):
        pass

    def postdata_generator_with_insecure_values(self, filename, input_dict, specific_params=None):
        parameters_list = specific_params  if specific_params is not None else input_dict.keys()
        for parameter in parameters_list:
            for value in generate_insecure_strings(filename):
                    output_dict = input_dict.copy()
                    output_dict[parameter] = value
                    yield output_dict

    def generate_insecure_strings(self, mal_data):
        # yield is for lazy binding -> iterator pattern
        # http://stackoverflow.com/questions/2223882/whats-different-between-utf-8-and-utf-8-without-bom
        # encoding used to remove BOM char in mal input issue
        if isinstance(mal_data, str):
            if os.path.isfile(mal_data):
                for line in codecs.open(mal_data, 'r', encoding="utf-8-sig").readlines():
                    data = line.rstrip('\n').rstrip('\r')
                    if data != '':
                        yield data
        else:
            for data in mal_data:
                    yield data

    def write_details_to_file(self, postdata, resp, filename):
        to_write = ''
        to_write += '\n' + repr(postdata) + '\n' + '-' * 40 + '\n'
        to_write += '"' + resp + '"'
        with open(filename, 'a') as f:
            f.write(str(to_write))

    def write_details_to_file_ee(self, filename, *args):
        for arg in args:
            to_write = ''
            to_write += '\n' + repr(arg) + '\n' + '-' * 40 + '\n'
            with open(filename, 'a') as f:
                f.write(str(to_write))

    def _serialize_data(self, data_object, pickle_file):
        with open(pickle_file, 'wb') as f:  # hard coded pickle name??
            pickle.dump(data_object, f)

    def _deserialize_data(self, pickle_file):
        with open(pickle_file, 'rb') as f:
            return pickle.load(f)

    def replace_this_value(self, value):
        if str(value).startswith('$') and str(value).endswith('$'):
            return True
        return False

    def get_original_value(self, value):
        temp = value.replace('$', '')
        try:
            if int(temp):
                return int(temp)
        except:
            pass
        if temp == 'False':
            return False
        if temp == 'True':
            return True
        return temp

    def __parse_json_and_set_value(self,
                                   a_object=None,
                                   str_malicious=None):
        '''
        this will parse the json and replace the value surrounded by
        $value$
        '''
        if isinstance(a_object, list):
            for item in a_object:
                if isinstance(item, (list, dict)):
                    self.__parse_json_and_set_value(a_object=item,
                                                  str_malicious=str_malicious)
                elif self.replace_this_value(item):
                    if self.set_value is True:
                        if item in self.temp_holder_targets and item not in self.temp_targets_hit:
                            a_object[a_object.index(item)] = str_malicious
                            self.temp_targets_hit.append(item)
                            break
                        else:
                            a_object[a_object.index(item)] = self.get_original_value(item)

                            #: else it ll replace all target
                    else:
                        #: just scan the json structure
                        self.temp_holder_targets.append(item)

        elif isinstance(a_object, dict):
            #: #print(a_object, 'dict')
            for key, value in a_object.items():
                #: #print(key, 'key')
                if isinstance(a_object[key], (dict,list)):
                    self.__parse_json_and_set_value(a_object=a_object[key],
                                                    str_malicious=str_malicious)
                elif self.replace_this_value(a_object[key]):
                    temp = a_object[key] + key
                    if self.set_value is True:
                        if temp in self.temp_holder_targets and temp not in self.temp_targets_hit:
                            a_object[key] = str_malicious
                            self.temp_targets_hit.append(temp)
                            break
                        else:
                            a_object[key] = self.get_original_value(a_object[key])
                    else:
                        self.temp_holder_targets.append(temp)
                        #: just scan the json structure

    def parse_json_and_set_value(self,
                                 a_object=None,
                                 str_malicious=None):
        a_object_copy = copy.deepcopy(a_object)
        self.temp_holder_targets = []
        self.temp_targets_hit = []
        self.set_value = False
        #: scan the json to find all target values
        self.__parse_json_and_set_value(a_object=a_object_copy)
        #: set the values
        self.set_value = True
        for item in self.temp_holder_targets:
            self.__parse_json_and_set_value(a_object=a_object_copy,
                                            str_malicious=str_malicious)            
            yield a_object_copy
            a_object_copy = copy.deepcopy(a_object)

    def generator_with_insecure_values_POST_req(self,
                                                a_json,
                                                mal_data):
        for value in self.generate_insecure_strings(mal_data=mal_data):  
            for mal_json in self.parse_json_and_set_value(a_object=a_json,
                                                          str_malicious=value):
               yield mal_json

    def generator_with_insecure_values_GET_req_ee(self, 
                                                  api_url_get, 
                                                  mal_data, 
                                                  target_param):
        for value in self.generate_insecure_strings(mal_data):
            if target_param != []:
                for param in target_param:
                    yield value, api_url_get.replace(param, value)

if __name__ == '__main__':
    u = Utils()
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
        "city": "$san jose$",
        "state": "california",
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
    for p in u.generator_with_insecure_values_POST_req(a, ['maldataxx']):
        print(p)

