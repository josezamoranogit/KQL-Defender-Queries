##//Title: AAD User Activity Timeline Query
<br></br>
//This alert is great for pulling AADsign ins, non-interactive and interactive as well as cloudapp events (teams, office)
//This will show you a logon followed by action performed on cloud app, like opening an email. Great for investigating sign in alerts.
<br></br>
let userName = "Enter username here"
AADSignInEventsBeta
| where AccountDisplayNamej contains userName
|union
CloudAppEvents
| where AccountDisplayName contains userName
| sort by Timestamp desc
<br></br>
<br></br>
##//Title: Account Logons
<br></br>
DeviceLogonEvents
| where AccountName contains "Enter username here like first.last (usernames vary)"
| sort by Timestamp desc
<br></br>
<br></br>
##//Title: Downloads Folder Search
//This query searches all downloads folders on a system. It may take some time for the event to populate in defender.
<br></br>
DeviceFileEvents
| where DeviceName contains "Hostname"
| where FolderPath matches regex @"\\users\\[^\\]+\\Downloads\\"
| sort by Timestamp desc
<br></br>
<br></br>
##//Title: Email Search by Sender and Recipient Email
<br></br>
EmailEvents
| where SenderFromAddress contains "sender address" and RecipientEmailAddress contains "recipient address"
//The query results are very verbose, so i projected the fields I wanted to make my investigations quicker.
| project Timestamp, NetworkMessageID,SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes
<br></br>
<br></br>
##//Title: LargeOutboundatHighRateIPSearch-ForSIEMAlertInvestigation
<br></br>
let listofIPs = dynamic (["IP1","IP2","IP3","IP4","IP5"......])
let queryResults =
	DeviceNetworkEvents
	| where RemoteIP in (listofIPs)
	| extend RemoteURL = replace_regex(RemoteURL,@"^(https?://)?", "")
	| where RemoteUrl != ""
	| distinct RemoteIP, RemoteURL
let probeResults=
	range IPIndex from 0 to array_length(listofIPs) -1 step 1
	| extend IP = tostring (listofIPs[IPIndex]);
let notFoundResults=
	probeResults
	| join kind=anti (queryResults) on  $left.IP == $right.RemoteIP
	| project IP = IP, Found = "not found";
let foundResults =
	queryResults
	| join kind=inner (DeviceNetworkEvents) on $left.RemoteIP == $right.RemoteIP
	| project IP = RemoteIP, Found = "found", RemoteIP = RemoteIP, RemoteURL = RemoteURL;
union notFoundResults, foundResults
| project IP, Found, RemoteIP, RemoteURL
| distinct RemoteIP, RemoteURL, Found, IP
<br></br>
<br></br>
##//Title: Network Share Accessed Lookup
// To find any network share that was accessed use this query follow instructions below, it will also show you all the recent logon events and the types (3,4,5,7, etc..)
// The system where the share was accessed from on line 3
<br></br>
let sourceDevice = "SourceDeviceHostname"
//The system where the share is lcoated at on line 5
let shareLocation = "hostname where share is located";
let results =(
	DeviceNetworkEvents
	| where DeviceName contains sourceDevice
	| where * contains shareLocation
	| union
	DeviceProcessEvents
	| where DeviceName contains sourceDevice
	| where * contians shareLocation
	DeviceFileEvents
	| where DeviceName contains sourceDevice
	| where * contains shareLocation
	| union
	DeviceLogonEvents
	| whewre DeviceName contains sourceDevice
	);
result
| project Timestamp, LogonType, DeviceName, AccountName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessSessionDeviceName, InitiatingProcessjSessionIP, ProcessCommandLine, FileName, FolderPath, RemoteUrl, LocalIP, LocalPort,
| sort by Timestamp desc
<br></br>
// Note: InitiatingProcessRemoteSessionDeviceName, InititatingProcessRemoteSessionIP will show you remote connections such as RDP, etc.
<br></br>
<br></br>
##//Title: Pull Device Events from Host
// This query is very rich in data compared to the gui in Defender, pull the data and analyze in excel or filter in query results for easy investigation.
<br></br>
let hostname  = "hostname here"
let result =(
	DeviceProcessEvents
	| where DeviceName contains hostname
	| union
	DeviceNetworkEvents
	| where DeviceName contains hostname
	|union
	DeviceFileEvents
	| where DeviceName contains hostname
	|union
	DeviceLogonEvents
	| where DeviceName contains hostname);
result
| sort by Timestamp desc
<br></br>
<br></br>
##//Title: Search for Vulnerabilities by CVE
//This query is great for finding the amount of devices that have a particular CVE. It will give you severity info as well as CvssScore.
<br></br>
let CVE = "Enter CVE here"
DeviceTvmSoftwareVulnerabilities
| where CveID == CVE
| summarize VulnerableDevices = make_set(DeviceName) by CveID
| join DeviceTvmSoftwareVulnerabilitiesKB on CveID
| extend TotalDevices = array_length(VulnerableDevices)
| project TotalDevices, CveID, VulnerabilitySeverityLevel,CvssScore, VulnerabilityDescription, VulnerableDevices
<br></br>
<br></br>
##//Title: Search for File on Endpoint by MD5, SHA1, SHA256
<br></br>
DeviceFileEvents
//Note: to search for other hash types replace MD5 with Sha1, sha256
| where MD5 contains "enter md5 hash here"
| where DeviceName contains "Enter hostname here"
<br></br>
<br></br>
##//Title: Search URL Clicks
UrlClickEvents | where URL contains " Enter URL here"
<br></br>
<br></br>
##//Title: Remote Failed Logons to Systems | Pie Chart
//Great for seeing most failed logons in the organization for hunting or for troubleshooting.
<br></br>
DeviceLogonEvents
| where ActionType contains "Failed"
| where AccountName !contains " "
//I highly recommend you remove service accounts from this query as they are noisy.
| project Timestamp, DeviceName, AccountName, FailureReason, DeviceId, ActionType
| Summarize UsernameAttempts = count() by AccountName | where UsernameAttempts > 4
| render piechart
<br></br>
