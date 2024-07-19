# Mimecast Campaigns

## Overview
This TA collects data from Mimecast Awareness Training API, specifically the "Get Campaigns" and "Get User Data" endpoints.  

## Releases
Version 2.0.0 was released on 19 July 2024. It is now built on top of Splunk Add-on Builder.

## Requirements and Configuration
To configure an input after installing this app, go to the app's Inputs landing page and hit Create New Input. You will need to supply the the following:  
- Grid or Tenant API URL  
- Access Key
- Secret Key
- App Id
- App Key
- Launch Date
	- This is your organization's chosen start of Phishing Simulation Campaign
	- Multiple phishing simulation emails may be sent over the course of few days and this date should be the very start of the campaign
- End Date
	- This is the desired end date of the Phishing Simulation Campaign
	- Some users may still action (e.g. Click, Report) on simulated phishing emails but your may not want these data to avoid changes in already-established score or result
- Include All User Data
	- A checkbox that will ignore the Campaign End Date
	- When this is checked, users who actioned on simulated phishing emails will still be ingested but will have a field `isOutsideCampaignPeriod` with a value of `True`
  
The recommended interval for an inputs stanza is once per day. You may immediately turn off the collection after just one successful collection.

## Troubleshooting
See the collection's logs by querying internal logs, such as:

```
index=_internal sourcetype=tamimecastcampaigns:log 
| transaction pid source
```

#### Disclaimer   
The author of this add-on is not employed by Mimecast. This was built out of necessity. The main Splunk TA built by Mimecast is found here: https://splunkbase.splunk.com/app/4075/  
  
For more details about the API, visit https://integrations.mimecast.com/documentation/endpoint-reference/awareness-training/  

#### Support
If you want to translate the logs collected by this TA into a dashboard summary, you may reach out to my personal email daniel.l.astillero@gmail.com. My rate is one pint of IPA per hour.