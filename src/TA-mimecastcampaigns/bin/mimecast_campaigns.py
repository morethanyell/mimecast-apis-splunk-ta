import sys
import json
import requests
import base64
import hashlib
import time
import hmac
import uuid
import datetime
import socket
from splunklib.modularinput import *
import splunklib.client as client


class MimecastCampaigns(Script):

    MASK = "***ENCRYPTED***"
    CREDENTIALS = None

    def get_scheme(self):

        scheme = Scheme("Mimecast Awareness Training - Campaigns")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "Campaigns API Credentials"

        grid_url = Argument("grid_url")
        grid_url.title = "Tenant or Grid URL"
        grid_url.data_type = Argument.data_type_string
        grid_url.description = "Mimecast Grid API URL. E.g.: https://de-api.mimecast.com"
        grid_url.required_on_create = True
        grid_url.required_on_edit = True
        scheme.add_argument(grid_url)

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
        
        campaign_parent_name = Argument("campaign_parent_name")
        campaign_parent_name.title = "Campaign Parent Name"
        campaign_parent_name.data_type = Argument.data_type_string
        campaign_parent_name.description = "Gives a name to this campaign. E.g.: Q3 Phishing Simulation - Confirm iPhone 15 Pro Amazon Order"
        campaign_parent_name.required_on_create = True
        campaign_parent_name.required_on_edit = False
        scheme.add_argument(campaign_parent_name)
        
        launch_date = Argument("launch_date")
        launch_date.title = "Launched Date"
        launch_date.data_type = Argument.data_type_string
        launch_date.description = "Retrieve results for campaigns launched since this date (at least one second earlier). Must use the format YYYY-mm-ddTHH:MM:SS+0000"
        launch_date.required_on_create = True
        launch_date.required_on_edit = False
        scheme.add_argument(launch_date)
        
        campaign_end_date = Argument("campaign_end_date")
        campaign_end_date.title = "Campaign End Date"
        campaign_end_date.data_type = Argument.data_type_string
        campaign_end_date.description = "Stops retrieving data after this date. Must use the format YYYY-mm-ddTHH:MM:SS+0000"
        campaign_end_date.required_on_create = True
        campaign_end_date.required_on_edit = False
        scheme.add_argument(campaign_end_date)

        return scheme

    def get_campaigns(self, _grid_url, _access_key, _secret_key, _app_id, _app_key):

        base_url = _grid_url
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

        return requests.post(url=url, headers=headers, data=str(payload))

    def get_userdata(self, _grid_url, _access_key, _secret_key, _app_id, _app_key, _campaignId, _pageToken):

        base_url = _grid_url
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
        
        return requests.post(url=url, headers=headers, data=str(payload))

    def validate_input(self, definition):
        pass

    def encrypt_keys(self, _access_key, _secret_key, _app_id, _app_key, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"accessKey": _access_key, "secretKey": _secret_key, "appId": _app_id, "appKey": _app_key}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _app_id:
                    service.storage_passwords.delete(
                        username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _app_id)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))

    def mask_credentials(self, _input_name, _grid_url, _app_id, _session_key):

        try:
            args = {'token': _session_key}
            service = client.connect(**args)

            kind, _input_name = _input_name.split("://")
            item = service.inputs.__getitem__((_input_name, kind))

            kwargs = {
                "grid_url": _grid_url,
                "access_key": self.MASK,
                "secret_key": self.MASK,
                "app_id": _app_id,
                "app_key": self.MASK
            }

            item.update(**kwargs).refresh()

        except Exception as e:
            raise Exception("Error updating inputs.conf: %s" % str(e))

    def decrypt_keys(self, _app_id, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        for storage_password in service.storage_passwords:
            if storage_password.username == _app_id:
                return storage_password.content.clear_password

    def stream_events(self, inputs, ew):
        
        start = time.time()
        presult = ""
        
        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        grid_url = self.input_items["grid_url"]
        access_key = self.input_items["access_key"]
        secret_key = self.input_items["secret_key"]
        app_id = self.input_items["app_id"]
        app_key = self.input_items["app_key"]
        campaign_parent_name = self.input_items["campaign_parent_name"]
        launch_date = self.input_items["launch_date"]
        campaign_end_date = self.input_items["campaign_end_date"]

        ew.log("INFO", f'Collecting Mimecast API logs from grid: {str(grid_url)}. Campaign Name: {campaign_parent_name}')
        
        try:
            launch_date_epoch = datetime.datetime.strptime(launch_date, '%Y-%m-%dT%H:%M:%S%z')
            campaign_end_date_epoch = datetime.datetime.strptime(campaign_end_date, '%Y-%m-%dT%H:%M:%S%z')
        except ValueError:
            ew.log("ERROR", f"Parsing Launch Date '{launch_date}' or Campaign End Date '{campaign_end_date}' failed.")
            sys.exit(1)
            
        current_datetime = datetime.datetime.now(campaign_end_date_epoch.tzinfo)
        
        if campaign_end_date_epoch < current_datetime:
            ew.log("INFO", f"{campaign_parent_name} has concluded.")
            sys.exit(1)

        try:
            
            if access_key != self.MASK and secret_key != self.MASK and app_key != self.MASK:
                self.encrypt_keys(access_key, secret_key, app_id, app_key, session_key)
                self.mask_credentials(self.input_name, grid_url, app_id, session_key)

            decrypted = self.decrypt_keys(app_id, session_key)
            self.CREDENTIALS = json.loads(decrypted)

            access_key = self.CREDENTIALS["accessKey"]
            secret_key = self.CREDENTIALS["secretKey"]
            app_key = self.CREDENTIALS["appKey"]

            campaignsResult = self.get_campaigns(grid_url, access_key, secret_key, app_id, app_key)
            
            apiScriptHost = socket.gethostname()

            status_code = campaignsResult.status_code

            if status_code != 200:
                ew.log("ERROR", "Unsuccessful HTTP request for `Campaigns` endpoint. status_code=: %s" % str(status_code))
                sys.exit(1)
            
            campaingsJson = campaignsResult.json()
            
            total_campaigns = len(campaingsJson["data"])
            campaign_ctr = 0
            
            ew.log("INFO", f'Successful API call for `Campaigns` endpoint. Result: {str(total_campaigns)} campaign(s)')

            for c in campaingsJson["data"]:
                c["gridUrl"] = grid_url
                c["sourcetype"] = "mc:api:campaigns"
                c["apiSourceAppId"] = app_id
                c["apiScriptHost"] = apiScriptHost
                cEvent = Event()
                cEvent.stanza = self.input_name
                cEvent.sourceType = "mc:api:response"
                cEvent.data = json.dumps(c)
                ew.write_event(cEvent)

                cId = c["id"]
                cName = c["name"]
                cLaunchDate = c["launchDate"]
                
                cLaunchDate_parse = datetime.datetime.strptime(cLaunchDate, '%Y-%m-%dT%H:%M:%S%z')
                
                if cLaunchDate_parse < launch_date_epoch:
                    ew.log("INFO", f'Skipped {cName} because this campaign was launched before {launch_date_epoch}.')
                    continue
                
                campaign_ctr = campaign_ctr + 1
                page_ctr = 0

                nextPage = ""

                while nextPage != "n/a":

                    userDataResult = self.get_userdata(grid_url, access_key, secret_key, app_id, app_key, cId, nextPage)

                    status_code = userDataResult.status_code

                    if status_code != 200:
                        ew.log("ERROR", f"Unsuccessful HTTP request for `User Data` endpoint. status_code={str(status_code)}")
                        sys.exit(1)

                    userDataResult = userDataResult.json()
                    
                    page_ctr = page_ctr + 1
                    
                    if "next" in userDataResult["meta"]["pagination"]:
                        nextPage = userDataResult["meta"]["pagination"]["next"]
                    else:
                        nextPage = "n/a"
                    
                    for uD in userDataResult["data"]:
                        for u in uD["items"]:
                            u["gridUrl"] = grid_url
                            u["sourcetype"] = "mc:api:userdata"
                            u["apiSourceAppId"] = app_id
                            u["apiScriptHost"] = apiScriptHost
                            u["campaignId"] = cId
                            u["campaignName"] = cName
                            u["campaign"] = campaign_parent_name
                            u["launchDate"] = cLaunchDate
                            u["campaignEndDate"] = campaign_end_date
                            uEvent = Event()
                            uEvent.stanza = self.input_name
                            uEvent.sourceType = "mc:api:response"
                            uEvent.data = json.dumps(u)
                            ew.write_event(uEvent)
                    
                ew.log("INFO", f'Successfully written user-data events for campaign {str(campaign_ctr)} of {str(total_campaigns)}, total_pages={str(page_ctr)}')

            presult = "completed"
        
        except Exception as e:
            presult = "failed"
            ew.log("ERROR", "Error: %s" % str(e))
        
        end = time.time()
        elapsed = round((end - start) * 1000, 2)
        ew.log("INFO", f'Process {presult} in {str(elapsed)} ms. input_name="{self.input_name}"')


if __name__ == "__main__":
    sys.exit(MimecastCampaigns().run(sys.argv))
