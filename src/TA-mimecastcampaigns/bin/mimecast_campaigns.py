import sys
import requests as req
import json
import base64
import hashlib
import hmac
import uuid
import datetime
import requests
from splunklib.modularinput import *

class MimecastCampaigns(Script):

    def get_scheme(self):
        # Returns scheme
        scheme = Scheme("Mimecast Awareness Training - Campaigns")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "Campaigns API Credentials"

        access_key = Argument("access_key")
        access_key.title = "Access Key"
        access_key.data_type = Argument.data_type_string
        access_key.description = "Access Key"
        access_key.required_on_create = True
        access_key.required_on_edit = True
        scheme.add_argument(access_key)

        secret_key = Argument("secret_key")
        secret_key.title = "Secret Key"
        secret_key.data_type = Argument.data_type_string
        secret_key.description = "Secret Key"
        secret_key.required_on_create = True
        secret_key.required_on_edit = True
        scheme.add_argument(secret_key)

        app_id = Argument("app_id")
        app_id.title = "App Id"
        app_id.data_type = Argument.data_type_string
        app_id.description = "App Id"
        app_id.required_on_create = True
        app_id.required_on_edit = True
        scheme.add_argument(app_id)

        app_key = Argument("app_key")
        app_key.title = "App Key"
        app_key.data_type = Argument.data_type_string
        app_key.description = "App Key"
        app_key.required_on_create = True
        app_key.required_on_edit = True
        scheme.add_argument(app_key)

        return scheme

    def get_campaigns(self, _access_key, _secret_key, _app_id, _app_key):
        
        base_url = "https://de-api.mimecast.com"
        uri = "/api/awareness-training/phishing/campaign/get-campaign"
        url = base_url + uri
        access_key = _access_key
        secret_key = _secret_key
        app_id = _app_id
        app_key = _app_key
        
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
            "data": []
        }

        response = requests.post(url=url, headers=headers, data=str(payload))

        if response.status_code != 200:
            sys.exit(1)
        data = response.json()
        
        return data
    
    def get_userdata(self, _access_key, _secret_key, _app_id, _app_key, _campaignId, _pageToken):
        
        base_url = "https://de-api.mimecast.com"
        uri = "/api/awareness-training/phishing/campaign/get-user-data"
        url = base_url + uri
        access_key = _access_key
        secret_key = _secret_key
        app_id = _app_id
        app_key = _app_key
        
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
                    "pageSize": 100,
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
        data = response.json()
        
        return data

    def validate_input(self, validation_definition):
        pass

    def stream_events(self, inputs, ew):

        for input_name, input_item in inputs.inputs.items():
            
            access_key = input_item["access_key"]
            secret_key = input_item["secret_key"]
            app_id = input_item["app_id"]
            app_key = input_item["app_key"]
            
            campaignsResult = self.get_campaigns(access_key, secret_key, app_id, app_key)

            for c in campaignsResult["data"]:
                c["sourcetype"] = "mc:api:campaigns"
                cEvent = Event()
                cEvent.stanza = input_name
                cEvent.sourceType = "mc:api:response"
                cEvent.data = json.dumps(c)
                ew.write_event(cEvent)

                cId = c["id"]
                cName = c["name"]
                cLaunchDate = c["launchDate"]

                nextPage = ""

                while nextPage != "n/a":
                    
                    userDataResult = self.get_userdata(access_key, secret_key, app_id, app_key, cId, nextPage)
                    
                    if "next" in userDataResult["meta"]["pagination"]:
                        nextPage = userDataResult["meta"]["pagination"]["next"]
                    else: nextPage = "n/a"

                    for uD in userDataResult["data"]:
                        for u in uD["items"]:
                            u["sourcetype"] = "mc:api:userdata"
                            u["campaignId"] = cId
                            u["campaignName"] = cName
                            u["launchDate"] = cLaunchDate
                            uEvent = Event()
                            uEvent.stanza = input_name
                            uEvent.sourceType = "mc:api:response"
                            uEvent.data = json.dumps(u)
                            ew.write_event(uEvent)

if __name__ == "__main__":
    sys.exit(MimecastCampaigns().run(sys.argv))