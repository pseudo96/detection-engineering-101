import requests
import os
import tomllib

'''
Traverse through the detections folder which contains rules in the TOML format, convert them into JSON and then push them into Elastic using the Detections API.
'''

# LOAD API KEY
api_key = os.environ['ELASTIC_KEY']
#print(api_key)


# Set up the http request
url = "https://ef86e3656d584e6ba3edcac1db20db09.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"
headers = {
    'Content-Type': 'application/json',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

# How do we generate the data variable? We have TOML, but the API only takes JSON.

data = ""

# Navigate through the custom_alerts directory and look for TOML files, and then parse them using tomlllib.load() and then perform the validation for the respective rule type.
for root,dir,files in os.walk("detections/"):
    for file in files:
        data = "{\n"
        if file.endswith(".toml"):
            full_path = os.path.join(root,file) # Create full path of the toml document since file will only carry the individual file name and not the full path.
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml) # Dictionary object returned by tomllib.load()
                # Different rules (based on type) can make use of certain fields unique to that rule type, which makes those fields mandatory for that rule type.
                # We check the alert.rule.type attribute from the result obtained above and create the required_fields list accordingly.
                # From here we can add the other required fields as necessary
                if alert['rule']['type'] == 'query': # Query based alert
                    required_fields = ['author','description','name','query','risk_score','severity','type','query','threat','rule_id'] 
                elif alert['rule']['type'] == 'eql': # Event Correlation Alert
                    required_fields = ['author','description','name','risk_score','severity','type','query','language','threat','rule_id']  
                elif alert['rule']['type'] == 'threshold': # Threshold based Alert
                    required_fields = ['author','description','name','risk_score','severity','type','query','threshold','threat','rule_id']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break
                # Perform string manipulations on fields based on the field type (int, str, list, dict) like:
                # 1. converting single to double-quotes, 
                # 2. escaping backslashes properly, 
                # 3. replacing multi-line strings as single-line ones 
                # 4. add commas and a new line wherever
                for field in alert['rule']:
                    if field in required_fields:
                        if type(alert['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                        elif type(alert['rule'][field]) == str:
                            if field == 'description':
                                data += "  " + "\"" + field + "\": " + "\"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"").replace("\\","\\\\") + "\"," + "\n"
                            elif field == 'query':
                                data += "  " + "\"" + field + "\": " + "\"" + str(alert['rule'][field]).replace("\\","\\\\").replace("\"","\\\"").replace("\n"," ") + "\"," + "\n"
                            else:    
                                data += "  " + "\"" + field + "\": " + "\"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"") + "\"," + "\n"
                        elif type(alert['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + ",\n"
                        elif type(alert['rule'][field]) == dict:
                           data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("\'","\"") + ",\n"
            data += "  \"enabled\": true\n}"
        #print(data)
        elastic_data = requests.post(url,headers=headers,data=data).json()
        print(elastic_data)
        
