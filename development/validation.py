import tomllib
import sys
import os

'''
What does this program do?
The program begins by traversing the detections/ directory and finds .toml files. 
It then sets the list of madatory fields required in the toml section based on the alert type (here only query, event correlation (eql) and threshold types are considered).
If the fields from the required_fields list are not present in the toml file, they get added to a separate list and then a missing field message is printed on screen. 
'''



# Navigate through the custom_alerts directory and look for TOML files, and then parse them using tomlllib.load() and then perform the validation for the respective rule type.
for root,dir,files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root,file) # Create full path of the toml document since file will only carry the individual file name and not the full path.
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                
                present_fields = [] # List of fields present in the toml file currently
                missing_fields = [] # List of fields from required fields that are missing in the toml file

                # Different types of rule can make use of certain fields unique to that rule type, which makes those fields mandatory for that rule type.
                # We check the alert.rule.type attribute from the result obtained above and create the required_fields list accordingly.
                if alert['rule']['type'] == 'query': # Query based alert
                    required_fields = ['description','name','query','risk_score','severity','type','query','rule_id'] 
                elif alert['rule']['type'] == 'eql': # Event Correlation Alert
                    required_fields = ['description','name','risk_score','severity','type','query','language','rule_id']  
                elif alert['rule']['type'] == 'threshold': # Threshold based Alert
                    required_fields = ['description','name','risk_score','severity','type','query','threshold','rule_id']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break  


                # Traverse through the toml file and carve out the fields in it.
                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                # Traverse through the present_fields list, compare it to required_fields and add the fields missing from required_fields to missing_fields
                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)


                if missing_fields:
                    print("The following fields are not present in " + file + ": " + str(missing_fields))
                else:
                    print("Validation passed for: " + file)