# The Endpoint Security Checklist


![image](https://user-images.githubusercontent.com/41551654/211865537-cdc628d0-df8f-4cb9-b6b4-526b22cc7c9c.png)


Today, cyber-attacks are as common as breaking news. Personal and organizational machines both have more vulnerability and attackers are attempting to exploit such weaknesses to get access to the endpoint.  Here we are going to discuss how an initial compromise has occurred and all the steps we need to do after exploitation.

# Top methods to prevent initial compromise:

It’s not always simple to avoid initial compromise. Preventing attackers from obtaining access to a machine in the first place is the best security against cyber attacks.

# **Method 1 – Ports and services which are exposed to public:**

In most organizations, sensitive ports will be closed for external connections because there are various ways to identify open ports. For attackers, open RDP ports that are exposed to the public service as beacons. Place RDP listening ports behind a firewall and use an RDP Gateway to restrict access. 

It’s also a good idea to enable network-level authentication and change the default listening port (TCP 3389). Disable SMB and use firewalls to restrict SMB network activity.

# **Method 2 – Patching Vulnerable Application/Software:**

We are using more software and applications in day-to-day life to handle our work.  It will only take a few minutes to start exploiting vulnerabilities that are publicly published. A system for assessing, testing, and deploying patches is a key first line of security against attacks. Recently more vulnerabilities were disclosed but patches were released after more months. For example, log4j vulnerability has released its patch after more days. In this situation, restricting network access to isolate systems that can’t be patched fast.

Also Read: Apache Log4j Vulnerability – Detection and Mitigation

# **Method 3 – Email related attacks:**

Email gateways are a very common application in organizations. Create custom rules in email gateways to block malicious script files (.JS, .VBS, etc.) and archive files (.ZIP, .SFX, .7z). And keep emails in the hold which have malicious Office files (.DOC, .DOCX, etc.) and PDFs. Increase the spam score in the email gateway to reject spam emails. End-users should be trained and informed about deception and social engineering attacks.

# **Method 4 – Common prevention techniques:**

Macros are abused to download malware and launch malicious scripts. So, block macros in Office files, unwanted Ads, and third-party services in the browser. To prevent misuse of the DDE capability (now deactivated by default), uncheck “Update Automatic Links At Open” in Microsoft Word and disable OLE Packages. 

**Mitigation:**

Once an attacker has gained access to a machine, they can use fileless tactics and genuine system administration tools to accomplish their nasty work to avoid discovery. So here are some Post-Exploitation techniques which we need to pursue further.

# **1 -Impose least privileges and access controls:**

- Keeping our credentials in the cache is the similar as sending our password to an attacker via email. It is simple to obtain and employ for their hack. As a result, don’t save passwords for network authentication. Credential Caching should be disabled.

- If valid credentials are obtained, avoiding credential overlap across systems will help to prevent lateral movement opportunities.
Staying logged in on remote systems is risky since it allows attackers to take over your admin access and privileges.

- Even if attackers have successfully obtained passwords, using two-factor authentication (2FA) can help keep them out and keep in mind that strong passwords will also prevent us from being hacked.

- Open shares can be used as a pivot point or a way to extend an attack to other network users. We can get rid of them by disabling anonymous login for read and write access to Network File Shares (NFS) and File Transfer Protocol (FTP).

Also Read: Latest IOCs – Threat Actor URLs , IP’s & Malware Hashes

- Enabling Admin Approval Mode for the built-in Administrator enforces UAC, and removing users from the Local Administrators Group prevents privilege escalation and lateral movement attempts.

- To prevent brute force attempts, apply account policies or progressive delays for logins.

- Users should only have the bare minimum of access and privileges to reduce the amount of damage they may cause if they are compromised.

- Use the highest level of UAC enforcement, which includes setting UAC to “always notify,” which will prompt you whenever an application tries to change Windows settings or the computer, but this can be bothersome.

# **2 -Powershell related technique:**

Why do attackers use PowerShell?

- Malicious actors utilize PowerShell to execute local scripts and execute remote resources after retrieving them using multiple network protocols. 

- They can also encode payloads using the command line and load PowerShell into other processes. 

- We can disable PowerShell for normal users and make it only available for admin users.

**Techniques:**

- Attackers can bypass unsigned PowerShell scripts, old PowerShell versions and other execution policy. So block unsigned PowerShell scripts and update to latest version of PowerShell.

- Consider using PowerShell Constrained Language Mode, which restricts PowerShell to its most basic capabilities, rendering many fileless attack techniques worthless.

- Extensive PowerShell Logging should be enabled and monitored. It’s possible that it’ll result in more false positives.
Also Read: Threat Hunting Using Powershell and Fileless Malware Attacks

# **3 -How to use WMI to prevent Exploitation:**

What is WMI Script?

You can write WMI scripts or applications to automate administrative tasks on remote computers, but WMI also supplies management data to other parts of the operating system and products.

**Techniques:**

- WMI’s extensive administrative capabilities make it a popular target for abuse, but they also make it a useful tool for detecting and responding to unwanted activities. Create WMI Event Subscriptions that are Defensive and Permanent.

- Set a fixed port for WMI and block it if we no need it longer.

Also Read: Windows Management Instrumentation Attacks – Detection & Response

# **4 -Set Application controls:**

- There is always a method to bypass AppLocker, no matter what security measures are in place. 

- Limit the Execution of Executables, DLLs, and Scripts with AppLocker and take additional steps to harden AppLocker.

**Suggestions for defensive team to detect the end-point attacks:**

- Usually blue team will be enabling more rules to detect malicious activities. It will be more good if the below activities also be monitored:
To establish persistence and escalate privileges, scheduled tasks might be used. Create a rule based on scheduled task Creation which holds PowerShell scripts.

- Monitoring for suspicious processes and API specific calls in the PowerShell operational log can provide strong indication of attacks. Toolkits such as Sysinternals Process Explorer and Get-InjectedThreads can also be useful.

- Create a rule based on processes spawned with the CREATE_SUSPENDED flag, as this is a good indicator of process hollowing.

- One of the most popular ways for attackers to obtain persistence is via hiding scripts in the registry. 

- Using WMI subscription events and/or tools like sysinternals autoruns can help to detect the changes in the registry and create a rule based on it.

- Creating defensive WMI subscription events to monitor suspect WMI activities can also help.

Also Read: Latest Cyber Security News – Hacker News !

**Conclusion:**

End-point attack prevention is a challenging task. However, it is possible if proper guidelines are followed and skilled analysts are employed. Even though we have more defensive technologies to detect and prevent threats, our analysts remain always our first line of defense. To make your company healthy, follow the steps outlined above.
