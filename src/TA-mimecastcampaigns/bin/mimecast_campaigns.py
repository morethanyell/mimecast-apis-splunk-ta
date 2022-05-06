import sys
import json
import requests
import base64
import hashlib
import hmac
import uuid
import datetime
from splunklib.modularinput import *
import splunklib.client as client


class MimecastCampaigns(Script):

    MASK = "***<encrypted>***"
    CREDENTIALS = None

    def get_scheme(self):

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
        hmac_sha1 = hmac.new(base64.b64decode(
            secret_key), dataToSign.encode(), digestmod=hashlib.sha1).digest()
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
        hmac_sha1 = hmac.new(base64.b64decode(
            secret_key), dataToSign.encode(), digestmod=hashlib.sha1).digest()
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

    def validate_input(self, definition):
        pass

    def encrypt_keys(self, _access_key, _secret_key, _app_id, _app_key, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"accessKey": _access_key,
                       "secretKey": _secret_key, "appId": _app_id, "appKey": _app_key}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _app_id:
                    service.storage_passwords.delete(
                        username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _app_id)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))

    def mask_credentials(self, input_name, _app_id, session_key):

        try:
            args = {'token': session_key}
            service = client.connect(**args)

            kind, input_name = input_name.split("://")
            item = service.inputs.__getitem__((input_name, kind))

            kwargs = {
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

        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        access_key = self.input_items["access_key"]
        secret_key = self.input_items["secret_key"]
        app_id = self.input_items["app_id"]
        app_key = self.input_items["app_key"]

        try:
            if access_key != self.MASK and secret_key != self.MASK and app_key != self.MASK:
                self.encrypt_keys(access_key, secret_key,
                                  app_id, app_key, session_key)
                self.mask_credentials(self.input_name, app_id, session_key)

            decrypted = self.decrypt_keys(app_id, session_key)
            self.CREDENTIALS = json.loads(decrypted)

            access_key = self.CREDENTIALS["accessKey"]
            secret_key = self.CREDENTIALS["secretKey"]
            app_key = self.CREDENTIALS["appKey"]

        except Exception as e:
            ew.log("ERROR", "Error: %s" % str(e))

        campaignsResult = self.get_campaigns(
            access_key, secret_key, app_id, app_key)

        for c in campaignsResult["data"]:
            c["sourcetype"] = "mc:api:campaigns"
            c["api_source"] = app_id
            cEvent = Event()
            cEvent.stanza = self.input_name
            cEvent.sourceType = "mc:api:response"
            cEvent.data = json.dumps(c)
            ew.write_event(cEvent)

            cId = c["id"]
            cName = c["name"]
            cLaunchDate = c["launchDate"]

            nextPage = ""

            while nextPage != "n/a":

                userDataResult = self.get_userdata(
                    access_key, secret_key, app_id, app_key, cId, nextPage)

                if "next" in userDataResult["meta"]["pagination"]:
                    nextPage = userDataResult["meta"]["pagination"]["next"]
                else:
                    nextPage = "n/a"

                for uD in userDataResult["data"]:
                    for u in uD["items"]:
                        u["sourcetype"] = "mc:api:userdata"
                        u["api_source"] = app_id
                        u["campaignId"] = cId
                        u["campaignName"] = cName
                        u["launchDate"] = cLaunchDate
                        uEvent = Event()
                        uEvent.stanza = self.input_name
                        uEvent.sourceType = "mc:api:response"
                        uEvent.data = json.dumps(u)
                        ew.write_event(uEvent)


if __name__ == "__main__":
    sys.exit(MimecastCampaigns().run(sys.argv))
