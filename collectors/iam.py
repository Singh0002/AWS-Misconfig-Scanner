import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Initialize the AWS STS (Security Token Service) client
iam = boto3.client('iam')

# Function to retrieve all user names from iam service
def collector_userName():
    print("\n--- Getting all User Names ---")
    try:
        
        response = iam.list_users()
        users = response.get('Users', [])
        
        user_list = []
        for user in users:
            user_names = user['UserName']
            user_list.append({"User": user_names})
            
            

    
        return user_list
    
    except ClientError as e:
        print(f"AWS API Error: {e.response['Error']['Message']}")
        return []
    except NoCredentialsError:
        print("Error: No AWS credentials configured.")
        return []




# Checks mfa status through inputting all usernames collected from collector_userName function           
def check_mfa(username):
    issues = []
    
    #Call list_mfa_devices for given parameter username
    #Get MFADevices list to check if mfa is activated
    #Return true if activated else return false
    
    try:    
            
        response = iam.list_mfa_devices(UserName = username)
        mfa_devices = response.get("MFADevices",[])
    
        if mfa_devices:            
            return True
        else:
            return False 
                
    except ClientError as e:
        print(f"An error occurred: {{e.response['Error']['Message']}}")
        return []         




# Checks password policies such as length of password so far
def check_password_policies(username):
    
    # Retrieve PasswordPolicy dictionary
    # From dictionary get minimum password length list
    # Print username and its password length
    try:
                
        response = iam.get_account_password_policy()
        passwordPolicy = response.get("PasswordPolicy",{})
        
        Min_Pass = passwordPolicy.get("MinimumPasswordLength",[])
        print(f"The password length for {username} is {Min_Pass}")
        
        
    except ClientError as e:
        print(f"An error occurred: {{e.response['Error']['Message']}}")
        return [] 





# Checks user policies for any wildcards in the account
def check_statement_wildcards(username): 
    
    
    try:    
        
        # Retrieve PolicyNames list from each account
        response = iam.list_user_policies(UserName = username)
        in_policies = response.get("PolicyNames",[])
        
        #If there are no policies print no policies exist
        if not in_policies:
            print(in_policies, "no Policies", username)
            
        
        # For loop to go through policy in policynames list 
        # Retrieve PolicyDocument dictionary from each username with given username and policy name
        for policy_name in in_policies:
            Policy_Doc = iam.get_user_policy(UserName = username, PolicyName = policy_name)
            Policy_Doc2 = Policy_Doc.get("PolicyDocument",{})
            
            
            # Retrieve statement list from policy document dictionary
            # If the list contains something make it insto a list
            statements = Policy_Doc2.get("Statement",[])
            if isinstance(statements, dict):
                statements = [statements]
            
            # Call check_user_wildcards methods to go through each statement    
            for s in statements:   
                if (check_user_wildcards(s)):
                    print("User  has wildcards in: ", s,username)

            
            
    except ClientError as e:
        print(f"An error occurred: {{e.response['Error']['Message']}}")
        return []      




# Function to go through each statement in the Policy Document checks for * in resource/action list from dictionary statement
def check_user_wildcards(statement):
    
    if (statement.get("Effect",[]) != "Allow"):
        return False
            
    # Retrive lists action and resource from Statement dictionary
    action = statement.get("Action",[])
    resource = statement.get("Resource",[])
    
    # If action and resource contain something make it into a list
    if isinstance(action,str):
        action = [action]
    if isinstance(resource,str):        
        resource = [resource]
    
    # Return true if '*' wildcard is found in action or resource     
    wildcard_action_found = '*'  in action
    wildcard_resource_found = '*' in resource
    
    
    return wildcard_action_found or wildcard_resource_found


# Ignore        
if __name__ == "__main__":
    result = collector_userName()
    print(result)
    for user in result:
        user_names1 = user["User"]
        print("Input account:", user_names1)
        has_mfa = check_mfa(user_names1)
    
        if has_mfa:
            print(f"User: {user_names1} -> MFA is enabled")
        else:
            print(f"User: {user_names1} -> No MFA is enabled")