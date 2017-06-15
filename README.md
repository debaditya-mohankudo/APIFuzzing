# APIFuzzing
Fuzz API data ( json input supported)

Dependencies:
Python 3.5 or above; 

requests library; if not installed ( pip install requests)



UtilsLibFuzzing:

This traverses across all the keys in the json and replaces each with data from fuzzdb in each iteration and 
only one key-value pair is targeted in each iteration


How to execute:
Step 1 : Set up FuzzAPI_git.py with valid inputs

Step 2 : Set up the authentication ( if to be passed in headers) inside -> def post_request(url, postdata):
(The current example does not require any authentication)

Step 3 : Set up detection logic here :

 dt.detect_in_response(resp, http_status_codes=[200, 201], result_prefix='PASS')
 
 if all the conditions match it logs as a PASS entry: there are only two valid values for result_prefix: 'PASS' and 'FAIL'
 
Step 3: Execute FuzzAPI_git.py

