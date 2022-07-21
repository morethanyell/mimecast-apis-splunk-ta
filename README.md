
## Description
This TA allows Splunk administrators to ingest or onboard data from Mimecast Awareness Training API, specifically the "Get Campaigns" and "Get User Data" endpoints.  
  
To configure an input after installing this app, go to Settings > Data Inputs > Mimecast Awareness Training - Campaigns  
You will need to supply the the following:  
- Grid or Tenant API URL  
- Access Key  
- Secret Key  
- App Id  
- App Key  
  
Once the abovementioned credentials have been entered, click on More Settings and select your index and interval. Since this API endpoint returns data that do not change a lot, it is recommended to set a wide interval, such as "every 12 hours".  
  
NOTE: Do not change the `sourcetype` as there's a renaming that happens in the background / parsing phase.  
  
The author of this add-on is not employed by Mimecast. This was built out of necessity. The main Splunk TA built by Mimecast is found here: https://splunkbase.splunk.com/app/4075/  
  
For more details about the API, visit https://integrations.mimecast.com/documentation/endpoint-reference/awareness-training/  

## Script Logic
- For each Mimecast Phising Campaign
	- Get Mimecast Campaign ID
		- Using the Campaign ID, get the User Data
			- For each user as JSON item, stream (ingest) as single event to Splunk
				- Do above until all pages are exhausted