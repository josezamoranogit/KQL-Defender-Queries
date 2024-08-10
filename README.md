## Title: AAD User Activity Timeline Query
<br></br>
//This alert is great for pulling AADsign ins, non-interactive and interactive as well as cloudapp events (teams, office) <br> 
//This will show you a logon followed by action performed on cloud app, like opening an email. Great for investigating sign in alerts. <br>
<br></br>
let userName = "Enter username here" <br>
AADSignInEventsBeta <br>
| where AccountDisplayName contains userName <br>
|union <br>
CloudAppEvents <br>
| where AccountDisplayName contains userName <br> 
| sort by Timestamp desc <br> 
<br></br>
<br></br>
## Title: Account Logons 
<br></br>
DeviceLogonEvents <br>
| where AccountName contains "Enter username here like first.last (usernames vary)" <br>
| sort by Timestamp desc <br> 
<br></br>
<br></br>
## Title: Downloads Folder Search
<br> </br>
//This query searches all downloads folders on a system. It may take some time for the event to populate in defender. <br> 
<br></br>
DeviceFileEvents <br> 
| where DeviceName contains "Hostname" <br> 
| where FolderPath matches regex @"\\users\\[^\\]+\\Downloads\\" <br> 
| sort by Timestamp desc <br> 
<br></br>
<br></br>
## Title: Email Search by Sender and Recipient Email
<br></br>
EmailEvents <br> 
| where SenderFromAddress contains "sender address" and RecipientEmailAddress contains "recipient address" <br>
//The query results are very verbose, so i projected the fields I wanted to make my investigations quicker. <br>
| project Timestamp, NetworkMessageID,SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes <br> 
<br></br>
<br></br>
## Title: LargeOutboundatHighRateIPSearch-ForSIEMAlertInvestigation
<br></br>
let listofIPs = dynamic (["IP1","IP2","IP3","IP4","IP5"......]) <br> 
let queryResults = <br> 
	DeviceNetworkEvents <br> 
	| where RemoteIP in (listofIPs) <br> 
	| extend RemoteURL = replace_regex(RemoteURL,@"^(https?://)?", "") <br>
	| where RemoteUrl != "" <br>
	| distinct RemoteIP, RemoteURL; <br>
let probeResults= <br>
	range IPIndex from 0 to array_length(listofIPs) -1 step 1 <br>
	| extend IP = tostring (listofIPs[IPIndex]); <br>
let notFoundResults=  <br>
	probeResults <br>
	| join kind=anti (queryResults) on  $left.IP == $right.RemoteIP <br>
	| project IP = IP, Found = "not found"; <br>
let foundResults = <br>
	queryResults <br>
	| join kind=inner (DeviceNetworkEvents) on $left.RemoteIP == $right.RemoteIP <br>
	| project IP = RemoteIP, Found = "found", RemoteIP = RemoteIP, RemoteURL = RemoteURL; <br>
| union notFoundResults, foundResults <br>
| project IP, Found, RemoteIP, RemoteURL <br>
| distinct RemoteIP, RemoteURL, Found, IP <br>
<br></br>
<br></br>
## Title: Network Share Accessed Lookup
// To find any network share that was accessed use this query follow instructions below, it will also show you all the recent logon events and the types (3,4,5,7, etc..) <br>
// The system where the share was accessed from on line 3 <br>
<br></br>
let sourceDevice = "SourceDeviceHostname" <br>
//The system where the share is lcoated at on line 5 <br>
let shareLocation = "hostname where share is located"; <br>
let results =( <br>
	DeviceNetworkEvents <br>
	| where DeviceName contains sourceDevice <br>
	| where * contains shareLocation <br>
	| union <br>
	DeviceProcessEvents <br>
	| where DeviceName contains sourceDevice <br>
	| where * contians shareLocation <br>
	DeviceFileEvents <br>
	| where DeviceName contains sourceDevice <br>
	| where * contains shareLocation <br>
	| union <br>
	DeviceLogonEvents <br>
	| whewre DeviceName contains sourceDevice <br> 
	); <br> 
result <br> 
| project Timestamp, LogonType, DeviceName, AccountName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessSessionDeviceName, InitiatingProcessjSessionIP, ProcessCommandLine, FileName, FolderPath, RemoteUrl, LocalIP, LocalPort, <br> 
| sort by Timestamp desc <br>
<br></br>
// Note: InitiatingProcessRemoteSessionDeviceName, InititatingProcessRemoteSessionIP will show you remote connections such as RDP, etc. <br> 
<br></br>
<br></br>
## Title: Pull Device Events from Host
// This query is very rich in data compared to the gui in Defender, pull the data and analyze in excel or filter in query results for easy investigation.
<br></br>
let hostname  = "hostname here" <br>
let result =( <br> 
	DeviceProcessEvents <br>
	| where DeviceName contains hostname <br>
	| union <br>
	DeviceNetworkEvents <br>
	| where DeviceName contains hostname <br>
	|union <br>
	DeviceFileEvents <br>
	| where DeviceName contains hostname <br>
	|union <br>
	DeviceLogonEvents <br>
	| where DeviceName contains hostname); <br>
result <br>
| sort by Timestamp desc <br>
<br></br>
<br></br>
## Title: Search for Vulnerabilities by CVE
//This query is great for finding the amount of devices that have a particular CVE. It will give you severity info as well as CvssScore.
<br></br>
let CVE = "Enter CVE here" <br>
DeviceTvmSoftwareVulnerabilities <br>
| where CveID == CVE <br>
| summarize VulnerableDevices = make_set(DeviceName) by CveID <br> 
| join DeviceTvmSoftwareVulnerabilitiesKB on CveID <br> 
| extend TotalDevices = array_length(VulnerableDevices) <br> 
| project TotalDevices, CveID, VulnerabilitySeverityLevel,CvssScore, VulnerabilityDescription, VulnerableDevices <br>
<br></br>
<br></br> 
## Title: Search for File on Endpoint by MD5, SHA1, SHA256
<br></br>
DeviceFileEvents <br> 
//Note: to search for other hash types replace MD5 with Sha1, sha256 <br> 
| where MD5 contains "enter md5 hash here" <br>
| where DeviceName contains "Enter hostname here" <br> 
<br></br>
<br></br>
## Title: Search URL Clicks
<br></br>
UrlClickEvents | where URL contains " Enter URL here" <br>
<br></br>
<br></br>
## Title: Remote Failed Logons to Systems | Pie Chart 
<br></br>
//Great for seeing most failed logons in the organization for hunting or for troubleshooting. <br> 
<br></br>
DeviceLogonEvents <br>
| where ActionType contains "Failed" <br>
| where AccountName !contains " " <br>
//I highly recommend you remove service accounts from this query as they are noisy. <br>
| project Timestamp, DeviceName, AccountName, FailureReason, DeviceId, ActionType <br>
| Summarize UsernameAttempts = count() by AccountName | where UsernameAttempts > 4 <br>
| render piechart <br>
<br></br>
