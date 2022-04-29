import base64
import hashlib
import hmac
import uuid
import datetime
import requests
import json

# Setup required variables
base_url = "https://de-api.mimecast.com"
campaign_endpoint = "/api/awareness-training/phishing/campaign/get-campaign"
userdata_endpoint = "/api/awareness-training/phishing/campaign/get-user-data"
# url = base_url + uri
access_key = "mYtOL3XZCOwG96BOiFTZRkqewayGLqe8aLof4d_wfJnA5ANermTCy9uY0YxJ-27VHny5psGtrksfT8RuvesX4XkOWdWo2aNH1dl8EXqx1vNksCkbuu43nl2B9YS0ia5M5Oszvo4kROg8cQeLc3_zEg"
secret_key = "pgAi7gH0YhYtduYQT927x5ngukyzXDgpg9LEB7xRMnQSILtmRVFFWP4OhqRYb8/L7WP4bE0QB/PiM8pbuQWrNg=="
app_id = "167b3d9f-c3ed-4941-b629-148a862b994a"
app_key = "db28e641-a634-46e3-8f6a-65a6a57cfb1f"

def get_campaigns(_uri):
    uri = _uri
    url = base_url + uri
    request_id = str(uuid.uuid4())
    hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
    dataToSign = ':'.join([hdr_date, request_id, uri, app_key])
    hmac_sha1 = hmac.new(base64.b64decode(secret_key), dataToSign.encode(), digestmod=hashlib.sha1).digest()
    sig = base64.b64encode(hmac_sha1).rstrip()
    
    headers = {
        'Authorization': 'MC ' + access_key + ':' + sig.decode(),
        'x-mc-app-id': app_id,
        'x-mc-date': hdr_date,
        'x-mc-req-id': request_id,
        'Content-Type': 'application/json'
    }

    payload = {
        "meta": {
                "pagination": {
                    "pageSize": 200
                }
            },
        "data": []
    }
    
    response = requests.post(url=url, headers=headers, data=str(payload))

    if response.status_code != 200:
        sys.exit(1)
    
    return response

def get_user_data(_uri, _campaignId, _pageToken):
    uri = _uri
    url = base_url + uri
    
    request_id = str(uuid.uuid4())
    hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
    dataToSign = ':'.join([hdr_date, request_id, uri, app_key])
    hmac_sha1 = hmac.new(base64.b64decode(secret_key), dataToSign.encode(), digestmod=hashlib.sha1).digest()
    sig = base64.b64encode(hmac_sha1).rstrip()
    
    headers = {
        'Authorization': 'MC ' + access_key + ':' + sig.decode(),
        'x-mc-app-id': app_id,
        'x-mc-date': hdr_date,
        'x-mc-req-id': request_id,
        'Content-Type': 'application/json'
    }
 
    payload = {
        'meta': {
            "pagination": {
                "pageSize": 10,
                "pageToken": _pageToken
            }
        },
        'data': [
            {
                "id": _campaignId,
            }
        ]
    }

    
    
    response = requests.post(url=url, headers=headers, data=str(payload))

    if response.status_code != 200:
        sys.exit(1)
    
    return response

if __name__ == "__main__":

    campaignId = "eNoVzVsKgkAUANC93F8FS8nMP_FREEYYiYQg4zjqVUZlxkcS7T1bwOF8QDI6CYYF2BCWSuNVQaoFblyuuXRIdIoeiRHj_ba8n1w0IbbGOdVcK9XW15XofFfqlqIvbXjJ50ThA6jAyZgNNcoauyqjhA8Eqy77B-ZRBTrJsedM0L5gW-l6vukcNjUzIbHvwN5_f2i7MTQ"

    result = json.loads(get_user_data(userdata_endpoint, campaignId, "").text)
    
    # if "next" in result["meta"]["pagination"]:
    #     next_page = result["meta"]["pagination"]["next"]
    # else:
    #     next_page = "lol"

    # for r in result["data"]:
    #     for i in r["items"]:
    #         i["campaignId"] = campaignId
    #         print(i)
