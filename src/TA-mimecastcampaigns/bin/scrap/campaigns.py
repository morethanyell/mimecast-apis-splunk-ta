import base64
import hashlib
import hmac
import uuid
import datetime
import requests
 
# Setup required variables
base_url = "https://de-api.mimecast.com"
uri = "/api/awareness-training/phishing/campaign/get-campaign"
url = base_url + uri
access_key = "mYtOL3XZCOwG96BOiFTZRkqewayGLqe8aLof4d_wfJnA5ANermTCy9uY0YxJ-27VHny5psGtrksfT8RuvesX4XkOWdWo2aNH1dl8EXqx1vNksCkbuu43nl2B9YS0ia5M5Oszvo4kROg8cQeLc3_zEg"
secret_key = "pgAi7gH0YhYtduYQT927x5ngukyzXDgpg9LEB7xRMnQSILtmRVFFWP4OhqRYb8/L7WP4bE0QB/PiM8pbuQWrNg=="
app_id = "167b3d9f-c3ed-4941-b629-148a862b994a"
app_key = "db28e641-a634-46e3-8f6a-65a6a57cfb1f"
 
# Generate request header values
request_id = str(uuid.uuid4())
hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
 
# DataToSign is used in hmac_sha1
dataToSign = ':'.join([hdr_date, request_id, uri, app_key])
 
# Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
hmac_sha1 = hmac.new(base64.b64decode(secret_key), dataToSign.encode(), digestmod=hashlib.sha1).digest()
 
# Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
sig = base64.b64encode(hmac_sha1).rstrip()
 
# Create request headers
headers = {
    'Authorization': 'MC ' + access_key + ':' + sig.decode(),
    'x-mc-app-id': app_id,
    'x-mc-date': hdr_date,
    'x-mc-req-id': request_id,
    'Content-Type': 'application/json'
}

payload = {
    "data": []
}
 
response = requests.post(url=url, headers=headers, data=str(payload))

if response.status_code != 200:
    pass

data = response.json()

for r in data["data"]:
    print(r)