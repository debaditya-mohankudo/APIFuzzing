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

class Utils(object):
    """docstring for Utils"""

    def __init__(self):
        pass







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
                    yield output_dict


    def generate_insecure_strings(self, mal_data):
        # yield is for lazy binding -> iterator pattern
        # http://stackoverflow.com/questions/2223882/whats-different-between-utf-8-and-utf-8-without-bom
        # encoding used to remove BOM char in mal input issue
        if isinstance(mal_data, str):
            if os.path.isfile(mal_data):
                for line in codecs.open(mal_data, 'r').readlines():
                    data = line.rstrip('\n').rstrip('\r')
                    if data != '':
                        print(data) # dotn delete this works
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
        '''

        if not hasattr(self, 'done_set_item'):
            self.done_set_item = False  # flag if the malicious value is set- one time creation
        if not hasattr(self, 'list_k'):
                        self.list_k = []  # stores all key-val pairs - one time execution

        if not self.done_set_item:  # if set quit the function
            if isinstance(a_object, list):
                for item in a_object:
                    if isinstance(item, (list, dict)): # can list appear in list?
                        self.parse_json_get_items(item, str_malicious, key,
                                                  get_item, set_item)

            elif isinstance(a_object, dict):
                for item in a_object:
                    if isinstance(a_object[item], (dict, list)):
                        self.parse_json_get_items(a_object[item], str_malicious,
                                                  key, get_item, set_item)
                    else:
                        self.parse_json_get_items((item, a_object[item], a_object),
                                                  str_malicious,
                                                  key, get_item,
                                                  set_item)

            elif isinstance(a_object, tuple): # each item in  a dict is a tuple
                key1 = str(a_object[0]) + '-' + str(a_object[1])
                if get_item is True:
                    if key1 not in self.list_k:
                        self.list_k.append(key1)

                elif set_item is True and not self.done_set_item:
                    if key == key1:
                        a_object[2][a_object[0]] = str_malicious
                        self.done_set_item = True


        self.done_set_item = False # reset the value after recursion is complete

    def parse_json_set_items(self, a_object,
                             str_malicious=None,
                             key=None,
                             get_item=False,
                             set_item=True):
        self.parse_json_get_items(a_object,
                             str_malicious,
                             key,
                             get_item=False,
                             set_item=True)


    def generate_testdata_with_malicious_str_ee(self, a_json_list, str_malicious):
        self.parse_json_get_items(a_json_list) # fills the self.list_k
        for key in self.list_k:
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
