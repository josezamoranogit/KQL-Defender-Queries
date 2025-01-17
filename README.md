## Title: Detect Uncommon Software Installed
<br></br>
// Find uncommon/unauthorized software installs.
// This query uses DeviceTvmSoftwareInventory to pull software inventory from all devices, count by softwarename and filter out high prevalence software (higher count software will more than likely be legitimate). This table is joined with "DeviceTvmSoftwareEvidenceBeta" to get the RegistrPath column. 
// That column is then mapped to "Registry Key" from DeviceRegistryEvents to get the timestamp of when the software was installed. 
//
//
//
//
let allowedSoftwareVendor = dynamic(["legitimatefile1", "legitimatefile2"]);  // Define allowed software vendors list
let lowPrevalenceSoftware= (
DeviceTvmSoftwareInventory
| summarize SoftwarePrevalence = dcount(DeviceId) by SoftwareName  // Summarize by software name, sum the count up so we can trim out high prevalence software
| where SoftwarePrevalence <= 100  // Optional: limit results to software installed on fewer devices, if its not allowed it will probably only be installed on few devices. //INCREASE THIS NUMBER TO TEST THE QUERY.
| join DeviceTvmSoftwareEvidenceBeta on SoftwareName  // Join with DeviceTvmSoftwareEvidenceBeta on SoftwareName to get RegistryPaths
| where RegistryPaths != "[]"  // Only include rows with non-empty registry paths, very few actionable columns to search for software installs this is the best column and if no data present there is no way to search anyway.
| where not (SoftwareVendor has_any (allowedSoftwareVendor)) //remove comment on line 8
| extend RegistryPathsString = tostring(RegistryPaths[0]) // Convert dynamic RegistryPaths to string for compatibility... Dont know why MS did not make it easier for us here... Pulling the first value (only) of the array.
| project DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, RegistryPathsString, SoftwarePrevalence
);
lowPrevalenceSoftware
| join kind=innerunique (DeviceRegistryEvents) on $left.RegistryPathsString==$right.RegistryKey //Because a common column name does not exist, I joined my custom column to RegistryKey from DeviceRegistryEvents.
| where ActionType == "RegistryKeyCreated" //Only RegistryKeyCreations since an update to software can make registry modifications this helps narrow down software installs.
| summarize Timestamp=min(Timestamp) by  DeviceName, SoftwareVendor, SoftwareName, RegistryPathsString, InitiatingProcessAccountName, InitiatingProcessFileName, SoftwarePrevalence, ReportId // This will show the oldest evidence of the software and all other columns must be unique (remove duplicates)
| project Timestamp, DeviceName, SoftwareVendor, SoftwareName, RegistryPathsString, InitiatingProcessAccountName, InitiatingProcessFileName, SoftwarePrevalence, ReportId
| where InitiatingProcessAccountName != @"system" //This tunes out A LOT of updates, patches, drivers, etc, I want to see when people are manually installing software..
<br></br>
<br></br>
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
<br></br>
## Title: Detect Encoded Powershell
<br></br>
//Find encoded PowerShell commands and then decodes the encoded command
//Query modified from this post - https://techcommunity.microsoft.com/t5/microsoft-sentinel/finding-base64-encoded-commands/m-p/1891876
//
// (When the alert was created there were 3 results in last 30 days keep this in mind for tuning)
//
//Creating arrays to define what will be excluded in the results to get rid of the noise/expected encoded commands in our environment. Add more values here to "Tune" them out.
let cleanedencodedcmdexclusions = dynamic([@"tuneencodedpowershellcommands"]);
let initiatingprocesscmdlineexclusions = dynamic(["excludeexecutables"]);
DeviceProcessEvents
//Looking for process command lines including powershell and the encodedcommand parameter.
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine contains "-enc"
    or ProcessCommandLine contains "-encodedcommand"
    or InitiatingProcessCommandLine contains "-enc"
    or InitiatingProcessCommandLine contains "-encodedcommand"
//Extract encoded command using regex
//This query will only return results when the command can be matched via regex and decoded, if you run only the above lines it will return all encoded commands without attempting to match and decode
| extend EncodedCommand = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| where EncodedCommand != ""
//If you do not remove the null bytes it will be jumbled garbage. That is why the replace string is used here to replace null bytes.
| extend CleanedCommand = replace_string(base64_decode_tostring(EncodedCommand), "\0", "")
| where CleanedCommand != ""
//Using the arrays on line 7/8 and referencing them to remove annoying garbage.
| where not (InitiatingProcessCommandLine has_any (initiatingprocesscmdlineexclusions))
| where not (CleanedCommand has_any (cleanedencodedcmdexclusions))
//Projecting desired columns, more can be added/removed as desired.
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ReportId,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    ProcessCommandLine,
    EncodedCommand,
    CleanedCommand
<br></br>
<br></br>
## Title: Detect DLL Loading from Unusual Location
<br></br>
//This detection has been created to find DLL sideloading. If it has been filtered out (hashes below) please do not assume it is legitimate activity as the tuned DLLs could be an attacker leveraging the vulnerable software loading DLLs from unusual locations.
//Updates to software below could cause multiple alerts to fire....
//
//
//Unusual locations where DLLs may be loaded from. 
let uncommonDirectories = dynamic([ 
    "C:\\Users\\.*\\AppData\\Roaming", 
    "C:\\Users\\.*\\AppData\\LocalLow", 
    "C:\\Windows\\Temp", 
    "C:\\Users\\.*\\AppData\\Local\\Temp", 
    "C:\\Temp", 
    "\\\\.*\\\\SharedFolder", 
    "C:\\Windows\\System32\\Tasks", 
    "C:\\Users\\.*\\Documents\\.hidden"
]);
//filterOutSHA1 >> Tuned out hashes for low or empty GlobalPrevalence fields, if you see an event fire for any of these DLL's that have been "tuned out" with a different hash, verify if it is malicious before proceeding as attackers leverage vulnerable software that loads DLLs from unprotected locations like Temp or User profile.
let filterOutSHA1 = dynamic(["enterhashhere"]);
let filterOutSoftwareName = dynamic(["allowedsoftwarehere"]);
//This table looks for loaded DLLs
DeviceImageLoadEvents
//Checking the folder paths below and referencing that array we created called uncommonDirectories
| where FolderPath matches regex @"\\\\.*\\\\SharedFolder" or FolderPath in (uncommonDirectories)
//Tuned out hashes here from filterOutSHA1 array.
| where SHA1 !in (filterOutSHA1)
| where InitiatingProcessCommandLine !in (filterOutSoftwareName)
//Making sure we are getting Dlls
| where FileName endswith ".dll"
//FileProfile() can be found in the functions tab, essentially there are some good fields we can pull from this like "SignatureState", "GlobalPrevalence", etc.
| invoke FileProfile()
//Looking for anything unsigned of course.
| where SignatureState == "Unsigned"
//Filtering out DLLs that are popular globally as those are more than likely not malicious.
| where GlobalPrevalence  <= 1500 or isempty(GlobalPrevalence)
| project DeviceId, Timestamp, ReportId, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, GlobalPrevalence, SignatureState, SoftwareName, GlobalFirstSeen, GlobalLastSeen
<br></br>
<br></br>
