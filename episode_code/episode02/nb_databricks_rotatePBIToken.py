# Databricks notebook source
# MAGIC %md
# MAGIC ####Set manual variables and import modules

# COMMAND ----------

# Import necessary modules
import requests
import json

# Databricks Variables - Do not include trailing slash!
workspaceUrl = ""

# Key Vault Variables
keyVaultName = ""
kv_secret_name_oauthSecret = ""
kv_secret_name_clientId = ""
kv_secret_name_tenantId = ""
kv_secret_name_secretValue = ""

# Power BI Variables
workspace_id = ''
dataset_id = ''

# COMMAND ----------

# MAGIC %md
# MAGIC ####Retrieve variables from Environment Variables and Key Vault
# MAGIC
# MAGIC Databricks Assistant Prompt: ```create a variable named spn_oauth_secret that uses dbutils to retreive the secret named afer the dbxOAuthSecretName variable in the scope named after the keyVaultName variable```
# MAGIC

# COMMAND ----------

spn_oauth_secret = dbutils.secrets.get(scope=keyVaultName, key=kv_secret_name_oauthSecret)
spn_clientid = dbutils.secrets.get(scope=keyVaultName, key=kv_secret_name_clientId)
spn_client_secret = dbutils.secrets.get(scope=keyVaultName, key=kv_secret_name_secretValue)
tenant_id = dbutils.secrets.get(scope=keyVaultName, key=kv_secret_name_tenantId)

# COMMAND ----------

# MAGIC %md
# MAGIC ####Retreive short-lived OAuth M2M token from workspace-level REST APIs
# MAGIC Databricks Assistant Prompt:```Use the request library and the oidc/v1/token endpoint to get a ouath m2m token```

# COMMAND ----------

# Define the endpoint URL
endpoint_url = f"{workspaceUrl}/oidc/v1/token"

# Define the grant type and scope
grant_type = "client_credentials"
scope = "all-apis"

# Define the headers and payload for the request
m2m_headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}
m2m_payload = {
    "grant_type": grant_type,
    "client_id": spn_clientid,
    "client_secret": spn_oauth_secret,
    "scope": scope
}

# Send the POST request to the endpoint
m2m_response = requests.post(endpoint_url, headers=m2m_headers, data=m2m_payload)

# Check if the request was successful
if m2m_response.status_code == 200:
    # Extract the access token from the response
    m2m_access_token = m2m_response.json()["access_token"]
    print("OAuth M2M token created")
else:
    print("Failed to get OAuth M2M token:", m2m_response.text)


# COMMAND ----------

# MAGIC %md
# MAGIC ####Generate a Databricks Personal Access Token representing the Service Principal
# MAGIC Databricks Assistant Prompt: ```generate a databricks personal access token by calling the token rest api using the already created m2m_access_token variable```

# COMMAND ----------

# Define the Databricks API endpoint
endpoint_url = f"{workspaceUrl}/api/2.0/token/create"

# Define the headers and payload for the request
pat_headers = {
    "Authorization": f"Bearer {m2m_access_token}",
    "Content-Type": "application/json"
}
pat_payload = {
    "lifetime_seconds": 3600,  # Set the desired token lifetime in seconds
    "comment": "Personal Access Token"  # Optional comment for the token
}

# Send the POST request to the endpoint
pat_response = requests.post(endpoint_url, headers=pat_headers, json=pat_payload)

# Check if the request was successful
if pat_response.status_code == 200:
    # Extract the personal access token from the response
    personal_access_token = pat_response.json()["token_value"]
    print("Databricks Personal Access Token created")
else:
    print("Failed to generate Databricks Personal Access Token:", pat_response.text)

# COMMAND ----------

# MAGIC %md
# MAGIC ####Retreive a token representing the Service Principal that will be used to authenticate to Power BI APIs
# MAGIC Databricks Assistant Prompt: ```get a power bi access token via rest api```

# COMMAND ----------


scope = "https://analysis.windows.net/powerbi/api/.default"

# Azure AD OAuth2 token endpoint
token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

# Prepare the request payload
pbitoken_payload = {
    "grant_type": "client_credentials",
    "client_id": spn_clientid,
    "client_secret": spn_client_secret,
    "scope": scope
}

# Send the POST request
pbitoken_response = requests.post(token_url.format(tenant_id=tenant_id), data=pbitoken_payload)

# Extract the access token from the response
if pbitoken_response.status_code == 200:
    pbi_access_token = pbitoken_response.json().get("access_token")
    print("Obtained access token")
else:
    print("Failed to obtain access token:", pbitoken_response.text)


# COMMAND ----------

# MAGIC %md
# MAGIC ####Take over Power BI Semantic Model using the Service Principal
# MAGIC This is required to change the credentials of the Semantic Model
# MAGIC
# MAGIC Databricks Assistant Prompt: ```create an api request to take over a power bi dataset```

# COMMAND ----------

# Set the request headers including the content type and authorization token
pbi_headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + pbi_access_token
}

# Send a POST request to take over a Power BI dataset within a specific workspace
takeover_response = requests.post(f"https://api.powerbi.com/v1.0/myorg/groups/{workspace_id}/datasets/{dataset_id}/Default.TakeOver", headers=pbi_headers)

# Check if the dataset takeover was successful
if takeover_response.status_code == 200:
    print("Dataset takeover successful")
else:
    # If the takeover was not successful, print the error message
    print("Failed to take over dataset:", takeover_response.text)

# COMMAND ----------

# MAGIC %md 
# MAGIC ####Get the details of the Semantic Model
# MAGIC Prompt used in Databricks Assistant: ```create an api request to get a dataset from power bi and collect the gatewayId and datasourceId into variables```

# COMMAND ----------

# Send a GET request to retrieve data source details for a specific dataset in a Power BI workspace
dsdetails_response = requests.get(f"https://api.powerbi.com/v1.0/myorg/groups/{workspace_id}/datasets/{dataset_id}/datasources", headers=pbi_headers)

# Check if the request was successful
if dsdetails_response.status_code == 200:
    # Parse the JSON response to extract data source and gateway IDs
    data_sources = dsdetails_response.json()
    datasource_id = data_sources["value"][0]["datasourceId"]
    gateway_id = data_sources["value"][0]["gatewayId"]
    # Print a message indicating which data source and gateway are being updated
    print(f"Updating Data Source {datasource_id} on Gateway {gateway_id}")
else:
    # Print an error message if the request failed
    print("Failed to get dataset information:", dsdetails_response.text)

# COMMAND ----------

# MAGIC %md
# MAGIC ####Set the credentials for the Data Source in Power BI to use the Service Principal's Personal Access Token
# MAGIC
# MAGIC Prompt used in Databricks Assistant: ```create an api request to update the credentials for a power bi dataset using the gateway_id and datasource_id variables. update the credentials using the previously created personal_access_token variable```

# COMMAND ----------

# Define the request body for updating datasource credentials in Power BI
request_body = {
    "credentialDetails": {
        "credentialType": "Key",  # Specifies the type of credentials being provided
        "credentials": json.dumps({  # Serializes the credentials into a JSON string
            "credentialData": [
                {"name": "key", "value": personal_access_token}  # The actual credentials, in this case, a personal access token
            ]
        }),
        "encryptedConnection": "Encrypted",  # Indicates that the connection should be encrypted
        "encryptionAlgorithm": "None",  # Specifies the encryption algorithm to use (None in this case)
        "privacyLevel": "None"  # Sets the privacy level for the connection
    }
}

# Make a PATCH request to update the datasource credentials in Power BI
response = requests.patch(
    f"https://api.powerbi.com/v1.0/myorg/gateways/{gateway_id}/datasources/{datasource_id}",
    json=request_body,  # Passes the request body as JSON
    headers=pbi_headers  # Includes the necessary headers (e.g., authorization)
)

# Check the response status code to determine if the update was successful
if response.status_code == 200:
    print("Credentials updated successfully.")  # Success message
else:
    print(f"Failed to update credentials: {response.text}")  # Error message with details
