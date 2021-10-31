# Pentest-Tools

* [General usefull Powershell Scripts](#General-usefull-Powershell-Scripts)
* [AMSI Bypass restriction Bypass](#AMSI-Bypass-restriction-Bypass)
* [Payload Hosting](#Payload-Hosting)
* [Network Share Scanner](#Network-Share-Scanner)
* [Lateral Movement](#Lateral-Movement)
* [Reverse Shellz](#Reverse-Shellz)
* [POST Exploitation](#POST-Exploitation)
* [Pivot](#Pivot)
* [Backdoor finder](#Backdoor-finder)
* [Persistence on windows](#Persistence-on-windows)
* [Web Application Pentest](#Web-Application-Pentest)
* [Framework Discovery](#Framework-Discovery)
* [Framework Scanner / Exploitation](#Framework-Scanner-/-Exploitation)
* [Web Vulnerability Scanner / Burp Plugins](#Web-Vulnerability-Scanner-/-Burp-Plugins)
* [Network- / Service-level Vulnerability Scanner](#Network--/-Service--level-Vulnerability-Scanner)
* [Crawler](#Crawler)
* [Web Exploitation Tools](#Web-Exploitation-Tools)
* [Windows Privilege Escalation / Audit](#Windows-Privilege-Escalation-/-Audit)
* [T3 Enumeration](#T3-Enumeration)
* [Linux Privilege Escalation / Audit](#Linux-Privilege-Escalation-/-Audit)
* [Credential harvesting Windows Specific](#Credential-harvesting-Windows-Specific)
* [Credential harvesting Linux Specific](#Credential-harvesting-Linux-Specific)
* [Data Exfiltration - DNS/ICMP/Wifi Exfiltration](#Data-Exfiltration---DNS/ICMP/Wifi-Exfiltration)
* [Git Specific](#Git-Specific)
* [Reverse Engineering / decompiler](#Reverse-Engineering-/-decompiler)
* [Forensics](#Forensics)
* [Network Attacks](#Network-Attacks)
* [Specific MITM service Exploitation](#Specific-MITM-service-Exploitation)
* [Sniffing / Evaluation / Filtering](#Sniffing-/-Evaluation-/-Filtering)
* [Scanner / Exploitation-Frameworks / Automation](#Scanner-/-Exploitation-Frameworks-/-Automation)
* [Default Credential Scanner](#Default-Credential-Scanner)
* [Payload Generation / AV-Evasion / Malware Creation](#Payload-Generation-/-AV-Evasion-/-Malware-Creation)
* [Domain Finding / Subdomain Enumeration](#Domain-Finding-/-Subdomain-Enumeration)
* [Scanner network level](#Scanner)
* [Email Gathering](#Email-Gathering)
* [Domain Auth + Exploitation](#Domain-Auth-+-Exploitation)
* [Network service - Login Brute Force + Wordlist attacks](#Login-Brute-Force-+-Wordlist-attacks)
* [Command & Control Frameworks](#Command-&-Control-Frameworks)
* [Wifi Tools](#Wifi-Tools)
* [Raspberri PI Exploitation](#Raspberri-PI-Exploitation)
* [Social Engeneering](#Social-Engeneering)
* [Wordlists / Wordlist generators](#Wordlists-/-Wordlist-generators)
* [Obfuscation](#Obfuscation)
* [Source Code Analysis](#Source-Code-Analysis)
* [No category yet](#No-category-yet)
* [Industrial Control Systems](#Industrial-Control-Systems)
* [NAC bypass](#Network-access-control-bypass)
* [JMX Exploitation](#JMX-Exploitation)

And many more. I created this repo to have an overview over my starred repos. I was not able to filter in categories before. Feel free to use it for yourself. I do not list Kali default tools as well as several testing tools which are state of the art. STRG+F searches are helpful here.

# Windows Active Directory Pentest

### General usefull Powershell Scripts

https://github.com/S3cur3Th1sSh1t/WinPwn - :sunglasses:

https://github.com/dafthack/MailSniper

https://github.com/putterpanda/mimikittenz

https://github.com/dafthack/DomainPasswordSpray

https://github.com/mdavis332/DomainPasswordSpray - same but kerberos auth for more stealth and lockout-sleep

https://github.com/jnqpblc/SharpSpray - domainpasswordspray executable with lockout-sleep

https://github.com/Arvanaghi/SessionGopher

https://github.com/samratashok/nishang

https://github.com/PowerShellMafia/PowerSploit

https://github.com/fdiskyou/PowerOPS

https://github.com/giMini/PowerMemory

https://github.com/Kevin-Robertson/Inveigh

https://github.com/MichaelGrafnetter/DSInternals

https://github.com/PowerShellEmpire/PowerTools

https://github.com/FuzzySecurity/PowerShell-Suite

https://github.com/hlldz/Invoke-Phant0m

https://github.com/leoloobeek/LAPSToolkit

https://github.com/sense-of-security/ADRecon

https://github.com/adrecon/ADRecon - supported version - really nice Excel-Sheet for an AD-Overview

https://github.com/Arno0x/PowerShellScripts

https://github.com/S3cur3Th1sSh1t/Grouper

https://github.com/l0ss/Grouper2

https://github.com/NetSPI/PowerShell

https://github.com/NetSPI/PowerUpSQL

https://github.com/GhostPack - Various Powersploit Tasks in C#

https://github.com/Kevin-Robertson/Powermad - Adidns Attacks


## AMSI Bypass restriction Bypass

https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

https://github.com/Flangvik/AMSI.fail

https://github.com/p3nt4/PowerShdll

https://github.com/jaredhaight/PSAttack

https://github.com/cobbr/InsecurePowerShell

https://github.com/Mr-Un1k0d3r/PowerLessShell

https://github.com/tothi/PowerLessShell - modified PowerLessShell

https://github.com/bitsadmin/nopowershell C# Powershell

https://github.com/OmerYa/Invisi-Shell

https://github.com/Hackplayers/Salsa-tools - Salsa Tools - ShellReverse TCP/UDP/ICMP/DNS/SSL/BINDTCP and AV bypass, AMSI patched 

https://github.com/padovah4ck/PSByPassCLM - Constrained language mode bypass

https://github.com/rasta-mouse/AmsiScanBufferBypass

https://github.com/itm4n/VBA-RunPE - Applocker Bypass

https://github.com/cfalta/PowerShellArmoury 

https://github.com/Mr-B0b/SpaceRunner - This tool enables the compilation of a C# program that will execute arbitrary PowerShell code, without launching PowerShell processes through the use of runspace.

https://github.com/RythmStick/AMSITrigger - The Hunt for Malicious Strings

https://github.com/rmdavy/AMSI_Ordinal_Bypass - Bypass AMSI and Defender using Ordinal Values in VBS

https://github.com/mgeeky/Stracciatella - OpSec-safe Powershell runspace from within C# (aka SharpPick) with AMSI, CLM and Script Block Logging disabled at startup

https://github.com/med0x2e/NoAmci - Using DInvoke to patch AMSI.dll in order to bypass AMSI detections triggered when loading .NET tradecraft via Assembly.Load().

https://github.com/rvrsh3ll/NoMSBuild - MSBuild without MSbuild.exe

https://github.com/Cn33liz/MSBuildShell - MSBuildShell, a Powershell Host running within MSBuild.exe

https://github.com/secdev-01/AllTheThingsExec - Executes Blended Managed/Unmanged Exports

https://github.com/cyberark/Evasor - A tool to be used in post exploitation phase for blue and red teams to bypass APPLICATIONCONTROL policies / Applocker Bypass Scan

https://github.com/tomcarver16/AmsiHook - AmsiHook is a project I created to figure out a bypass to AMSI via function hooking.

https://github.com/G0ldenGunSec/SharpTransactedLoad - Load .net assemblies from memory while having them appear to be loaded from an on-disk location.

https://github.com/itm4n/PPLdump - Bypass LSA Protection - Dump the memory of a PPL with a userland exploit

## Payload Hosting

https://github.com/kgretzky/pwndrop - Self-deployable file hosting service for red teamers, allowing to easily upload and share payloads over HTTP and WebDAV.

https://github.com/sc0tfree/updog - Updog is a replacement for Python's SimpleHTTPServer. It allows uploading and downloading via HTTP/S, can set ad hoc SSL certificates and use http basic auth.


## Network Share Scanner 

Find Juicy Stuff

https://github.com/SnaffCon/Snaffler - a tool for pentesters to help find delicious candy, by @l0ss and @Sh3r4

https://github.com/djhohnstein/SharpShares - Enumerate all network shares in the current domain. Also, can resolve names to IP addresses.

https://github.com/vivami/SauronEye - Search tool to find specific files containing specific words, i.e. files containing passwords..

https://github.com/leftp/VmdkReader - .NET 4.0 Console App to browse VMDK / VHD images and extract files

https://github.com/mitchmoser/SharpShares - Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain

## Reverse Shellz

https://github.com/xct/xc - A small reverse shell for Linux & Windows

https://github.com/cytopia/pwncat - netcat on steroids with Firewall, IDS/IPS evasion, bind and reverse shell, self-injecting shell and port forwarding magic - and its fully scriptable with Python (PSE)

https://github.com/Kudaes/LOLBITS - C# reverse shell using Background Intelligent Transfer Service (BITS) as communication protocol and direct syscalls for EDR user-mode hooking evasion.

## Backdoor finder

https://github.com/linuz/Sticky-Keys-Slayer

https://github.com/ztgrace/sticky_keys_hunter

https://github.com/countercept/doublepulsar-detection-script

# Lateral Movement

https://github.com/0xthirteen/SharpRDP

https://github.com/0xthirteen/MoveKit - WMI,SMB,RDP,SCM,DCOM Lateral Movement techniques

https://github.com/0xthirteen/SharpMove - WMI, SCM, DCOM, Task Scheduler and more

https://github.com/rvrsh3ll/SharpCOM - C# Port of Invoke-DCOM

https://github.com/malcomvetter/CSExec - An implementation of PSExec in C#

https://github.com/byt3bl33d3r/CrackMapExec

https://github.com/cube0x0/SharpMapExec

https://github.com/nccgroup/WMIcmd

https://github.com/rasta-mouse/MiscTools - CsExec, CsPosh (Remote Powershell Runspace), CsWMI,CsDCOM

https://github.com/byt3bl33d3r/DeathStar - Automate Getting Dom-Adm

https://github.com/SpiderLabs/portia - automated lateral movement

https://github.com/Screetsec/Vegile - backdoor / rootkit

https://github.com/DanMcInerney/icebreaker - automation for various mitm attacks + vulns

https://github.com/MooseDojo/apt2 - automated penetration toolkit

https://github.com/hdm/nextnet - Netbios Network interface Enumeration (discovery of dual homed hosts)

https://github.com/mubix/IOXIDResolver - Find dual homed hosts over DCOM

https://github.com/Hackplayers/evil-winrm 

https://github.com/bohops/WSMan-WinRM - A collection of proof-of-concept source code and scripts for executing remote commands over WinRM using the WSMan.Automation COM object

https://github.com/dirkjanm/krbrelayx - unconstrained delegation, printer bug (MS-RPRN) exploitation, Remote ADIDNS attacks

https://github.com/Mr-Un1k0d3r/SCShell - Fileless lateral movement tool that relies on ChangeServiceConfigA to run command

https://github.com/rvazarkar/GMSAPasswordReader - AD Bloodhound 3.0 Path

https://github.com/fdiskyou/hunter

https://github.com/360-Linton-Lab/WMIHACKER - A Bypass Anti-virus Software Lateral Movement Command Execution Tool

https://github.com/leechristensen/SpoolSample - PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface.

https://github.com/cube0x0/SharpSystemTriggers - Collection of remote authentication triggers in C#

https://github.com/leftp/SpoolSamplerNET - Implementation of SpoolSample without rDLL

https://github.com/topotam/PetitPotam - PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.

https://github.com/lexfo/rpc2socks - Post-exploit tool that enables a SOCKS tunnel via a Windows host using an extensible custom RPC proto over SMB through a named pipe.

https://github.com/checkymander/sshiva - C# application that allows you to quick run SSH commands against a host or list of hosts

https://github.com/dev-2null/ADCollector - A lightweight tool to quickly extract valuable information from the Active Directory environment for both attacking and defending.

https://github.com/mez-0/MoveScheduler - .NET 4.0 Scheduled Job Lateral Movement

https://github.com/GhostPack/RestrictedAdmin - Remotely enables Restricted Admin Mode

https://github.com/RiccardoAncarani/LiquidSnake - LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript

https://github.com/Hackndo/WebclientServiceScanner - Python tool to Check running WebClient services on multiple targets based on @leechristensen - https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb

https://github.com/dirkjanm/PKINITtools - Tools for Kerberos PKINIT and relaying to AD CS

https://github.com/juliourena/SharpNoPSExec - Get file less command execution for lateral movement.

# POST Exploitation

https://github.com/mubix/post-exploitation

https://github.com/emilyanncr/Windows-Post-Exploitation

https://github.com/nettitude/Invoke-PowerThIEf - Automatically scan any windows or tabs for login forms and then record what gets posted. A notification will appear when some have arrived.

https://github.com/ThunderGunExpress/BADministration - McAfee Epo or Solarwinds post exploitation

https://github.com/bohops/SharpRDPHijack - A POC Remote Desktop (RDP) session hijack utility for disconnected sessions

https://github.com/antonioCoco/RunasCs - RunasCs - Csharp and open version of windows builtin runas.exe

https://github.com/klsecservices/Invoke-Vnc - Powershell VNC injector

https://github.com/mandatoryprogrammer/CursedChrome - Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies, allowing you to browse sites as your victims.

https://github.com/djhohnstein/WireTap - .NET 4.0 Project to interact with video, audio and keyboard hardware.

https://github.com/GhostPack/Lockless - Lockless allows for the copying of locked files.

https://github.com/slyd0g/SharpClipboard - C# Clipboard Monitor

https://github.com/infosecn1nja/SharpDoor - SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.

https://github.com/qwqdanchum/MultiRDP - MultiRDP is a C# consosle application to make multiple RDP (Remote Desktop) sessions possible by patching termsrv.dll correctly.

https://github.com/Yaxser/SharpPhish - Using outlook COM objects to create convincing phishing emails without the user noticing. This project is meant for internal phishing.

https://github.com/eksperience/KnockOutlook - A little tool to play with Outlook

https://github.com/checkymander/Carbuncle - Tool for interacting with outlook interop during red team engagements

https://github.com/3gstudent/PasswordFilter - 2 ways of Password Filter DLL to record the plaintext password

https://github.com/TheWover/CertStealer - A .NET tool for exporting and importing certificates without touching disk.

https://github.com/swisskyrepo/SharpLAPS - Retrieve LAPS password from LDAP

https://github.com/n00py/LAPSDumper - remote LAPS dumping from linux

## Post Exploitation - Phish Credentials

https://github.com/hlldz/pickl3 - Windows active user credential phishing tool

https://github.com/shantanu561993/SharpLoginPrompt - Creates a login prompt to gather username and password of the current user. This project allows red team to phish username and password of the current user without touching lsass and having adminitrator credentials on the system.

https://github.com/Dviros/CredsLeaker

https://github.com/bitsadmin/fakelogonscreen

https://github.com/CCob/PinSwipe - Phish Smartcard PIN

https://github.com/IlanKalendarov/PyHook - PyHook is an offensive API hooking tool written in python designed to catch various credentials within the API call.

https://github.com/IlanKalendarov/SharpHook - SharpHook is an offensive API hooking tool designed to catch various credentials within the API call.

# Wrapper for various tools

https://github.com/S3cur3Th1sSh1t/PowerSharpPack - Various .NET Tools wrapped in Powershell

https://github.com/bohops/GhostBuild - GhostBuild is a collection of simple MSBuild launchers for various GhostPack/.NET projects

https://github.com/rvrsh3ll/Rubeus-Rundll32 - rundll32 Wrapper for Rubeus

https://github.com/checkymander/Zolom - execute Python in C# via ironpython

# Pivot 

https://github.com/0x36/VPNPivot

https://github.com/securesocketfunneling/ssf

https://github.com/p3nt4/Invoke-SocksProxy

https://github.com/sensepost/reGeorg - Webshell tunnel over socks proxy - pentesters dream

https://github.com/hayasec/reGeorg-Weblogic - reGeorg customized for weblogic

https://github.com/nccgroup/ABPTTS TCP tunneling over HTTP/HTTPS for web application servers like reGeorg

https://github.com/RedTeamOperations/PivotSuite

https://github.com/trustedsec/egressbuster - check for internet access over open ports /  egress filtering

https://github.com/vincentcox/bypass-firewalls-by-DNS-history

https://github.com/shantanu561993/SharpChisel - C# Wrapper around Chisel from

https://github.com/jpillora/chisel - A fast TCP tunnel over HTTP

https://github.com/esrrhs/pingtunnel - ping tunnel is a tool that advertises tcp/udp/socks5 traffic as icmp traffic for forwarding.

https://github.com/sysdream/ligolo - Reverse Tunneling made easy for pentesters, by pentesters

https://github.com/tnpitsecurity/ligolo-ng - An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface.

https://github.com/nccgroup/SocksOverRDP - Socks5/4/4a Proxy support for Remote Desktop Protocol / Terminal Services / Citrix / XenApp / XenDesktop

https://github.com/blackarrowsec/mssqlproxy - mssqlproxy is a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse

https://github.com/zeronetworks/cornershot - Amplify network visibility from multiple POV of other hosts

https://github.com/blackarrowsec/pivotnacci - A tool to make socks connections through HTTP agents

https://github.com/praetorian-inc/PortBender - TCP Port Redirection Utility

https://github.com/klsecservices/rpivot - socks4 reverse proxy for penetration testing

# Active Directory Audit and exploit tools 

https://github.com/mwrlabs/SharpGPOAbuse

https://github.com/BloodHoundAD/BloodHound

https://github.com/BloodHoundAD/SharpHound3 - C# Data Collector for the BloodHound Project, Version 3

https://github.com/chryzsh/awesome-bloodhound

https://github.com/hausec/Bloodhound-Custom-Queries

https://github.com/CompassSecurity/BloodHoundQueries

https://github.com/knavesec/Max - Maximizing BloodHound. Max is a good boy.

https://github.com/vletoux/pingcastle

https://github.com/cyberark/ACLight 

https://github.com/canix1/ADACLScanner

https://github.com/fox-it/Invoke-ACLPwn

https://github.com/fox-it/aclpwn.py - same as invoke-aclpwn but in python

https://github.com/dirkjanm/ldapdomaindump - Active Directory information dumper via LDAP

https://github.com/tothi/rbcd-attack - Kerberos Resource-Based Constrained Delegation Attack from Outside using Impacket

https://github.com/NotMedic/NetNTLMtoSilverTicket - SpoolSample -> Responder w/NetNTLM Downgrade -> NetNTLMv1 -> NTLM -> Kerberos Silver Ticket

https://github.com/FatRodzianko/Get-RBCD-Threaded - Tool to discover Resource-Based Constrained Delegation attack paths in Active Directory environments

https://github.com/NinjaStyle82/rbcd_permissions - Add SD for controlled computer object to a target object for RBCD using LDAP

https://github.com/GhostPack/Certify - Active Directory certificate abuse.

https://github.com/ly4k/Certipy - Python implementation for Active Directory certificate abuse

https://github.com/zer1t0/certi - ADCS abuser

https://github.com/GhostPack/PSPKIAudit - PowerShell toolkit for AD CS auditing based on the PSPKI toolkit.

https://github.com/cfalta/PoshADCS - A proof of concept on attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)

https://github.com/Kevin-Robertson/Sharpmad - C# version of Powermad

# Persistence on windows

https://github.com/fireeye/SharPersist

https://github.com/outflanknl/SharpHide

https://github.com/HarmJ0y/DAMP - The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification

https://github.com/ShutdownRepo/pywhisker - Python version of the C# tool for "Shadow Credentials" attacks

https://github.com/Ridter/pyForgeCert - pyForgeCert is a Python equivalent of the ForgeCert.

https://github.com/eladshamir/Whisker - Whisker is a C# tool for taking over Active Directory user and computer accounts by manipulating their msDS-KeyCredentialLink attribute, effectively adding "Shadow Credentials" to the target account.

https://github.com/GhostPack/ForgeCert - "Golden" certificates

https://github.com/RedSection/printjacker - Hijack Printconfig.dll to execute shellcode

# Web Application Pentest

# Framework Discovery

https://github.com/Tuhinshubhra/CMSeeK

https://github.com/Dionach/CMSmap - Wordpress, Joomla, Drupal Scanner

https://github.com/wpscanteam/wpscan

https://github.com/Ekultek/WhatWaf

# Framework Scanner / Exploitation

https://github.com/wpscanteam/wpscan - wordpress

https://github.com/n00py/WPForce

https://github.com/m4ll0k/WPSeku

https://github.com/swisskyrepo/Wordpresscan

https://github.com/rastating/wordpress-exploit-framework

https://github.com/coldfusion39/domi-owned - lotus domino

https://github.com/droope/droopescan - Drupal

https://github.com/whoot/Typo-Enumerator - Typo3

https://github.com/rezasp/joomscan - Joomla


# Web Vulnerability Scanner / Burp Plugins

https://github.com/m4ll0k/WAScan - all in one scanner

https://github.com/s0md3v/XSStrike - XSS discovery

https://github.com/federicodotta/Java-Deserialization-Scanner

https://github.com/d3vilbug/HackBar

https://github.com/gyoisamurai/GyoiThon

https://github.com/snoopysecurity/awesome-burp-extensions

https://github.com/sting8k/BurpSuite_403Bypasser - Burpsuite Extension to bypass 403 restricted directory

https://github.com/BishopFox/GadgetProbe - Probe endpoints consuming Java serialized objects to identify classes, libraries, and library versions on remote Java classpaths.

# Network- / Service-level Vulnerability Scanner

https://github.com/scipag/vulscan

https://github.com/zdresearch/OWASP-Nettacker

# File / Directory / Parameter discovery

https://github.com/OJ/gobuster

https://github.com/nccgroup/dirble

https://github.com/maK-/parameth

https://github.com/devanshbatham/ParamSpider - Mining parameters from dark corners of Web Archives

https://github.com/s0md3v/Arjun - :heartpulse:

https://github.com/Cillian-Collins/dirscraper - Directory lookup from Javascript files

https://github.com/KathanP19/JSFScan.sh - Automation for javascript recon in bug bounty.

https://github.com/hannob/snallygaster

https://github.com/maurosoria/dirsearch

https://github.com/s0md3v/Breacher - Admin Panel Finder

https://github.com/mazen160/server-status_PWN 

# Crawler

https://github.com/jonaslejon/lolcrawler - Headless web crawler for bugbounty and penetration-testing/redteaming

https://github.com/s0md3v/Photon - :heartpulse:

https://github.com/kgretzky/dcrawl

https://github.com/lc/gau - Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl.

# Web Exploitation Tools

https://github.com/OsandaMalith/LFiFreak - lfi

https://github.com/enjoiz/XXEinjector - xxe

https://github.com/tennc/webshell - shellz

https://github.com/flozz/p0wny-shell

https://github.com/epinna/tplmap - ssti

https://github.com/orf/xcat - xpath injection

https://github.com/almandin/fuxploider - File Uploads

https://github.com/nccgroup/freddy - deserialization

https://github.com/irsdl/IIS-ShortName-Scanner - IIS Short Filename Vuln. exploitation

https://github.com/frohoff/ysoserial - Deserialize Java Exploitation

https://github.com/pwntester/ysoserial.net - Deserialize .NET Exploitation

https://github.com/internetwache/GitTools - Exploit .git Folder Existence

https://github.com/liamg/gitjacker - Leak git repositories from misconfigured websites

https://github.com/cujanovic/SSRF-Testing - SSRF Tutorials

https://github.com/ambionics/phpggc - PHP Unserialize Payload generator

https://github.com/BuffaloWill/oxml_xxe - Malicious Office XXE payload generator

https://github.com/tijme/angularjs-csti-scanner - Angularjs Csti Scanner

https://github.com/0xacb/viewgen - Deserialize .NET Viewstates

https://github.com/Illuminopi/RCEvil.NET - Deserialize .NET Viewstates

# REST API Audit

https://github.com/microsoft/restler-fuzzer - RESTler is the first stateful REST API fuzzing tool for automatically testing cloud services through their REST APIs and finding security and reliability bugs in these services.

https://github.com/flipkart-incubator/Astra

# SAML Login

https://github.com/LuemmelSec/SAML2Spray - Python Script for SAML2 Authentication Passwordspray

# Swagger File API Attack

https://github.com/imperva/automatic-api-attack-tool

# Windows Privilege Escalation / Audit

https://github.com/itm4n/PrivescCheck - Privilege Escalation Enumeration Script for Windows

https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS - powerfull Privilege Escalation Check Script with nice output

https://github.com/AlessandroZ/BeRoot

https://github.com/rasta-mouse/Sherlock

https://github.com/hfiref0x/UACME - UAC

https://github.com/FatRodzianko/SharpBypassUAC - C# tool for UAC bypasses

https://github.com/AzAgarampur/byeintegrity8-uac - Bypass UAC at any level by abusing the Program Compatibility Assistant with RPC, WDI, and more Windows components

https://github.com/rootm0s/WinPwnage - UAC

https://github.com/abatchy17/WindowsExploits

https://github.com/dafthack/HostRecon

https://github.com/sensepost/rattler - find vulnerable dlls for preloading attack

https://github.com/WindowsExploits/Exploits

https://github.com/Cybereason/siofra - dll hijack scanner

https://github.com/0xbadjuju/Tokenvator - admin to system

https://github.com/MojtabaTajik/Robber

https://github.com/411Hall/JAWS

https://github.com/GhostPack/SharpUp

https://github.com/GhostPack/Seatbelt

https://github.com/A-mIn3/WINspect

https://github.com/hausec/ADAPE-Script

https://github.com/SecWiki/windows-kernel-exploits

https://github.com/bitsadmin/wesng

https://github.com/itm4n/Perfusion - Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)

# Windows Privilege Abuse (Privilege Escalation)

https://github.com/gtworek/Priv2Admin - Abuse Windows Privileges

https://github.com/itm4n/UsoDllLoader - load malicious dlls from system32

https://github.com/TsukiCTF/Lovely-Potato - Exploit potatoes with automation

https://github.com/antonioCoco/RogueWinRM - from Service Account to System

https://github.com/antonioCoco/RoguePotato - Another Windows Local Privilege Escalation from Service Account to System

https://github.com/itm4n/PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019

https://github.com/BeichenDream/BadPotato - itm4ns Printspoofer in C#

https://github.com/zcgonvh/EfsPotato - Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability).

https://github.com/antonioCoco/RemotePotato0 - Just another "Won't Fix" Windows Privilege Escalation from User to Domain Admin.

https://github.com/itm4n/FullPowers - Recover the default privilege set of a LOCAL/NETWORK SERVICE account

# T3 Enumeration 

https://github.com/quentinhardy/jndiat

# Linux Privilege Escalation / Audit

https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS - powerfull Privilege Escalation Check Script with nice output

https://github.com/mzet-/linux-exploit-suggester

https://github.com/rebootuser/LinEnum

https://github.com/diego-treitos/linux-smart-enumeration

https://github.com/CISOfy/lynis

https://github.com/AlessandroZ/BeRoot

https://github.com/future-architect/vuls

https://github.com/ngalongc/AutoLocalPrivilegeEscalation

https://github.com/b3rito/yodo

https://github.com/belane/linux-soft-exploit-suggester - lookup vulnerable installed software

https://github.com/sevagas/swap_digger

https://github.com/NullArray/RootHelper

https://github.com/NullArray/MIDA-Multitool

https://github.com/initstring/dirty_sock

https://github.com/jondonas/linux-exploit-suggester-2

https://github.com/sosdave/KeyTabExtract

https://github.com/DominicBreuker/pspy

https://github.com/itsKindred/modDetective

https://github.com/nongiach/sudo_inject

https://github.com/Anon-Exploiter/SUID3NUM - find suid bins and look them up under gtfobins / exploitable or not

https://github.com/nccgroup/GTFOBLookup - Offline GTFOBins

https://github.com/TH3xACE/SUDO_KILLER - sudo misconfiguration exploitation

https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py

https://github.com/inquisb/unix-privesc-check

https://github.com/hc0d3r/tas - easily manipulate the tty and create fake binaries

https://github.com/SecWiki/linux-kernel-exploits

https://github.com/initstring/uptux

https://github.com/andrew-d/static-binaries - not really privesc but helpfull

https://github.com/liamg/traitor - Automatic Linux privesc via exploitation of low-hanging fruit e.g. gtfobins, polkit, docker socket

# Exfiltration

## Credential harvesting Windows Specific

https://github.com/gentilkiwi/mimikatz

https://github.com/GhostPack/SafetyKatz

https://github.com/Flangvik/BetterSafetyKatz - Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory.

https://github.com/GhostPack/Rubeus

https://github.com/ShutdownRepo/targetedKerberoast - Kerberoast with ACL abuse capabilities

https://github.com/Arvanaghi/SessionGopher

https://github.com/peewpw/Invoke-WCMDump

https://github.com/tiagorlampert/sAINT

https://github.com/AlessandroZ/LaZagneForensic - remote lazagne

https://github.com/eladshamir/Internal-Monologue

https://github.com/djhohnstein/SharpWeb - Browser Creds gathering

https://github.com/moonD4rk/HackBrowserData - hack-browser-data is an open-source tool that could help you decrypt data[passwords|bookmarks|cookies|history] from the browser.

https://github.com/mwrlabs/SharpClipHistory - ClipHistory feature get the last 25 copy paste actions

https://github.com/0x09AL/RdpThief - extract live rdp logins

https://github.com/chrismaddalena/SharpCloud - Simple C# for checking for the existence of credential files related to AWS, Microsoft Azure, and Google Compute.

https://github.com/djhohnstein/SharpChromium - .NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins.

https://github.com/rxwx/chlonium - Chromium Cookie import / export tool

https://github.com/V1V1/SharpScribbles - ThunderFox for Firefox Credentials, SitkyNotesExtract for "Notes as passwords"

https://github.com/securesean/DecryptAutoLogon - Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon

https://github.com/G0ldenGunSec/SharpSecDump - .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py

https://github.com/EncodeGroup/Gopher - C# tool to discover low hanging fruits like SessionGopher

https://github.com/GhostPack/SharpDPAPI - DPAPI Creds via C#

https://github.com/Hackndo/lsassy 

https://github.com/aas-n/spraykatz

https://github.com/b4rtik/SharpKatz - C# porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands

https://github.com/login-securite/DonPAPI - Dumping DPAPI credz remotely

https://github.com/Barbarisch/forkatz - credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege

https://github.com/skelsec/pypykatz - Mimikatz implementation in pure Python

## LSASS dumper / process dumper

https://github.com/codewhitesec/HandleKatz - PIC lsass dumper using cloned handles

https://github.com/m0rv4i/SafetyDump - Dump stuff without touching disk

https://github.com/CCob/MirrorDump - Another LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory

https://github.com/deepinstinct/LsassSilentProcessExit - Command line interface to dump LSASS memory to disk via SilentProcessExit

https://github.com/outflanknl/Dumpert - dump lsass using direct system calls and API unhooking

https://github.com/cube0x0/MiniDump - C# Lsass parser

https://github.com/b4rtik/SharpMiniDump - Create a minidump of the LSASS process from memory - using Dumpert

https://github.com/b4rtik/ATPMiniDump - Evade WinDefender ATP credential-theft

https://github.com/aas-n/spraykatz - remote procdump.exe, copy dump file to local system and pypykatz for analysis/extraction

https://github.com/jfmaes/SharpHandler - This project reuses open handles to lsass to parse or minidump lsass

## Credential harvesting Linux Specific

https://github.com/huntergregal/mimipenguin

https://github.com/n1nj4sec/mimipy

https://github.com/dirtycow/dirtycow.github.io

https://github.com/mthbernardes/sshLooterC - SSH Credential loot

https://github.com/blendin/3snake - SSH / Sudo / SU Credential loot

https://github.com/0xmitsurugi/gimmecredz

https://github.com/TarlogicSecurity/tickey - Tool to extract Kerberos tickets from Linux kernel keys.

## Data Exfiltration - DNS/ICMP/Wifi Exfiltration

https://github.com/FortyNorthSecurity/Egress-Assess

https://github.com/p3nt4/Invoke-TmpDavFS

https://github.com/DhavalKapil/icmptunnel

https://github.com/iagox86/dnscat2

https://github.com/Arno0x/DNSExfiltrator

https://github.com/spieglt/FlyingCarpet - Wifi Exfiltration

https://github.com/SECFORCE/Tunna - Tunna is a set of tools which will wrap and tunnel any TCP communication over HTTP

https://github.com/sysdream/chashell

https://github.com/no0be/DNSlivery - Easy files and payloads delivery over DNS

https://github.com/mhaskar/DNSStager - Hide your payload in DNS

https://github.com/Flangvik/SharpExfiltrate - Modular C# framework to exfiltrate loot over secure and trusted channels.

## Git Specific

https://github.com/dxa4481/truffleHog

https://github.com/zricethezav/gitleaks

https://github.com/adamtlangley/gitscraper


## Windows / Linux
https://github.com/AlessandroZ/LaZagne

https://github.com/Dionach/PassHunt

https://github.com/vulmon/Vulmap

# Reverse Engineering / decompiler

https://github.com/mattifestation/PowerShellArsenal

https://github.com/0xd4d/dnSpy - .NET Disassembler

https://github.com/NationalSecurityAgency/ghidra

https://github.com/icsharpcode/ILSpy

# Forensics
https://github.com/Invoke-IR/PowerForensics

https://github.com/Neo23x0/Loki

https://github.com/gfoss/PSRecon

# Network Attacks

https://github.com/bettercap/bettercap - :heartpulse:

https://github.com/SpiderLabs/Responder

https://github.com/lgandx/Responder - more up to date

https://github.com/evilsocket/bettercap - Deprecated but still good

https://github.com/r00t-3xp10it/morpheus

https://github.com/fox-it/mitm6

https://github.com/Kevin-Robertson/InveighZero - mitm6 in C# + Inveigh default features

https://github.com/mdsecactivebreach/Farmer - Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.

https://github.com/audibleblink/davil - leaking net-ntlm with webdav

https://github.com/mgeeky/SharpWebServer - Red Team oriented C# Simple HTTP & WebDAV Server with Net-NTLM hashes capture functionality

https://github.com/DanMcInerney/LANs.py

## Specific MITM service Exploitation

https://github.com/jtesta/ssh-mitm - SSH

https://github.com/pimps/wsuxploit - WSUS

https://github.com/GoSecure/WSuspicious - WSuspicious - A tool to abuse insecure WSUS connections for privilege escalations

https://github.com/GoSecure/pywsus - WSUS mitm - Standalone implementation of a part of the WSUS spec. Built for offensive security purposes.

https://github.com/SySS-Research/Seth - RDP

https://github.com/GoSecure/pyrdp - RDP man-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact

https://github.com/infobyte/evilgrade - Fake Updates for various Software

https://github.com/samdenty/injectify - web application live recording, keystroke logger

https://github.com/skorov/ridrelay - User Enumeration with SMB Relay Attacks

https://github.com/Kevin-Robertson/Invoke-TheHash

## Sniffing / Evaluation / Filtering

https://github.com/DanMcInerney/net-creds

https://github.com/odedshimon/BruteShark - 

https://github.com/lgandx/PCredz

https://github.com/Srinivas11789/PcapXray

# Red-Team SIEM

https://github.com/outflanknl/RedELK - Red Team's SIEM - tool for Red Teams used for tracking and alarming about Blue Team activities as well as better usability in long term operations.

# Scanner / Exploitation-Frameworks / Automation

https://github.com/threat9/routersploit

https://github.com/nccgroup/autopwn

https://github.com/1N3/Sn1per

https://github.com/byt3bl33d3r/CrackMapExec

https://github.com/Cn33liz/p0wnedShell

https://github.com/archerysec/archerysec

https://github.com/vulnersCom/nmap-vulners

https://github.com/m4ll0k/AutoNSE - automate nmap with scripting capabilities

https://github.com/v3n0m-Scanner/V3n0M-Scanner

https://github.com/zdresearch/OWASP-Nettacker

https://github.com/rvrsh3ll/SharpSMBSpray - Spray a hash via smb to check for local administrator access

## Default Credential Scanner

https://github.com/ztgrace/changeme

https://github.com/InfosecMatter/default-http-login-hunter - Login hunter of default credentials for administrative web interfaces leveraging NNdefaccts dataset.

https://github.com/FortyNorthSecurity/EyeWitness

https://github.com/byt3bl33d3r/WitnessMe - screenshot for webservers

https://github.com/ihebski/DefaultCreds-cheat-sheet - One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password

## Default Credential Lookup
https://github.com/Viralmaniar/Passhunt

# Payload Generation / AV-Evasion / Malware Creation

https://github.com/nccgroup/Winpayloads

https://github.com/Screetsec/TheFatRat

https://github.com/xillwillx/tricky.lnk

https://github.com/trustedsec/unicorn

https://github.com/z0noxz/powerstager

https://github.com/curi0usJack/luckystrike

https://github.com/enigma0x3/Generate-Macro

https://github.com/Cn33liz/JSMeter

https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator

https://github.com/Cn33liz/StarFighters

https://github.com/BorjaMerino/Pazuzu

https://github.com/mwrlabs/wePWNise

https://github.com/Mr-Un1k0d3r/UniByAv

https://github.com/govolution/avet

https://github.com/Pepitoh/VBad

https://github.com/mdsecactivebreach/CACTUSTORCH

https://github.com/D4Vinci/Dr0p1t-Framework

https://github.com/g0tmi1k/msfpc

https://github.com/bhdresh/CVE-2017-0199 - Office RCE POC

https://github.com/jacob-baines/concealed_position - Bring your own print driver privilege escalation tool

https://github.com/GreatSCT/GreatSCT

https://github.com/mthbernardes/rsg - reverse shell generator

https://github.com/sevagas/macro_pack

https://github.com/mdsecactivebreach/SharpShooter

https://github.com/hlldz/SpookFlare

https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads

https://github.com/peewpw/Invoke-PSImage

https://github.com/Arvanaghi/CheckPlease - Sandbox Evasion techniques

https://github.com/Aetsu/SLib - SandBox Evasion in C#

https://github.com/trustedsec/nps_payload

https://github.com/stormshadow07/HackTheWorld

https://github.com/r00t-3xp10it/FakeImageExploiter

https://github.com/nccgroup/demiguise - Encrypted HTA Generation

https://github.com/med0x2e/genxlm

https://github.com/med0x2e/GadgetToJScript

https://github.com/rasta-mouse/GadgetToJScript - Optimized GadgetToJScript version 

https://github.com/EgeBalci/sgn - Shikata ga nai (仕方がない) encoder ported into go with several improvements

https://github.com/matterpreter/spotter - Spotter is a tool to wrap payloads in environmentally-keyed, AES256-encrypted launchers. 

https://github.com/s0lst1c3/dropengine - Malleable payload generation framework.

https://github.com/gigajew/PowerDropper - Build Powershell Script from .NET Executable

https://github.com/FortyNorthSecurity/EXCELntDonut - Excel 4.0 (XLM) Macro Generator for injecting DLLs and EXEs into memory.

https://github.com/Greenwolf/ntlm_theft - A tool for generating multiple types of NTLMv2 hash theft files by Jacob Wilkin (Greenwolf)

https://github.com/phackt/stager.dll - AES Encrypt payloads

https://github.com/Arno0x/EmbedInHTML - Embed and hide any file in an HTML file

https://github.com/bats3c/darkarmour - AES Encrypt C/C++ Compiled binaries and decrypt at runtime

https://github.com/christophetd/spoofing-office-macro - PoC of a VBA macro spawning a process with a spoofed parent and command line.

https://github.com/infosecn1nja/MaliciousMacroMSBuild - Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.

https://github.com/outflanknl/EvilClippy - A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows.

https://github.com/FortyNorthSecurity/EXCELntDonut - Excel 4.0 (XLM) Macro Generator for injecting DLLs and EXEs into memory.

https://github.com/STMCyber/boobsnail - BoobSnail allows generating Excel 4.0 XLM macro. Its purpose is to support the RedTeam and BlueTeam in XLM macro generation.

https://github.com/michaelweber/Macrome - Excel Macro Document Reader/Writer for Red Teamers & Analysts

https://github.com/aaaddress1/xlsKami - Out-of-the-Box Tool to Obfuscate Excel XLS. Include Obfuscation & Hide for Cell Labels & BoundSheets

https://github.com/CCob/PwnyForm - PwnyForm will take an MSI installer as input and generate an MSI transform (mst) that can be used to inject arbitrary command execution by adding a custom action that will execute during the UI or Install sequence of an MSI file.

https://github.com/fireeye/OfficePurge - VBA purge your Office documents with OfficePurge. VBA purging removes P-code from module streams within Office documents. Documents that only contain source code and no compiled code are more likely to evade AV detection and YARA rules.

https://github.com/TestingPens/CPLDropper - A Control Panel Applet dropper project. It has a high success rate on engagements since nobody cares about .CPL files and you can just double click them.

https://github.com/FortyNorthSecurity/hot-manchego - Macro-Enabled Excel File Generator (.xlsm) using the EPPlus Library.

https://github.com/knight0x07/ImpulsiveDLLHijack - C# based tool which automates the process of discovering and exploiting DLL Hijacks in target binaries. The Hijacked paths discovered can later be weaponized during Red Team Operations to evade EDR's.

https://github.com/Flangvik/SharpDllProxy - Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading

https://github.com/jfmaes/Invoke-DLLClone - Koppeling x Metatwin x LazySign

https://github.com/paranoidninja/CarbonCopy - Sign an executable for AV-Evasion

https://github.com/Tylous/Limelighter - A tool for generating fake code signing certificates or signing real ones

https://github.com/duc-nt/RCE-0-day-for-GhostScript-9.50 - RCE 0-day for GhostScript 9.50 - Payload generator - ImageMagick

https://github.com/X-C3LL/xlsxPoison - Just a PoC to turn xlsx (regular Excel files) into xlsm (Excel file with macro) and slipping inside a macro (vbaProject.bin)

https://github.com/med0x2e/SigFlip - SigFlip is a tool for patching authenticode signed PE files (exe, dll, sys ..etc) without invalidating or breaking the existing signature.

https://github.com/klezVirus/inceptor - Template-Driven AV/EDR Evasion Framework

https://github.com/Inf0secRabbit/BadAssMacros - BadAssMacros - C# based automated Malicous Macro Generator.

https://github.com/connormcgarr/LittleCorporal - LittleCorporal: A C# Automated Maldoc Generator

https://github.com/hasherezade/process_ghosting - Process Ghosting - a PE injection technique, similar to Process Doppelgänging, but using a delete-pending file instead of a transacted file

https://github.com/optiv/ScareCrow - ScareCrow - Payload creation framework designed around EDR bypass.

https://github.com/persianhydra/Xeexe-TopAntivirusEvasion - Undetectable & Xor encrypting with custom KEY (FUD Metasploit Rat) bypass Top Antivirus like BitDefender,Malwarebytes,Avast,ESET-NOD32,AVG,... & Automatically Add ICON and MANIFEST to excitable

# Shellcode Injection

https://github.com/TheWover/donut - Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters

https://github.com/rasta-mouse/RuralBishop - D/Invoke port of UrbanBishop

https://github.com/slyd0g/UrbanBishopLocal - A port of FuzzySecurity's UrbanBishop project for inline shellcode execution

https://github.com/FuzzySecurity/Sharp-Suite/tree/master/UrbanBishop - Donut for Shellcode Injection

https://github.com/antonioCoco/Mapping-Injection - Mapping injection is a process injection technique that avoids the usage of common monitored syscall VirtualAllocEx, WriteProcessMemory and CreateRemoteThread.

https://github.com/SolomonSklash/SyscallPOC - Shellcode injection POC using syscalls.

https://github.com/Arno0x/ShellcodeWrapper - Shellcode wrapper with encryption for multiple target languages

https://github.com/Ne0nd0g/go-shellcode - A repository of Windows Shellcode runners and supporting utilities. The applications load and execute Shellcode using various API calls or techniques.

https://github.com/djhohnstein/CSharpSetThreadContext - C# Shellcode Runner to execute shellcode via CreateRemoteThread and SetThreadContext to evade Get-InjectedThread

https://github.com/pwndizzle/c-sharp-memory-injection - A set of scripts that demonstrate how to perform memory injection in C#

https://github.com/jthuraisamy/SysWhispers2 - SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.

https://github.com/mai1zhi2/SysWhispers2_x86 - X86 version of syswhispers2 / x86 direct system call

https://github.com/knownsec/shellcodeloader - CreateThreadpoolWait, Fiber Load, NtTestAlert Load, SEH Except Load, TLS CallBack Load, Dynamic Load, Dynamic Load plus, Syscall Load, APC-Inject Load, Early Brid APC-Inject Load, NtCreateSection-Inject Load, OEP Hiijack-Inject Load, Thread Hiijack-Inject Load

https://github.com/djhohnstein/ScatterBrain - Suite of Shellcode Running Utilities

https://github.com/D00MFist/Go4aRun - Shellcode runner in GO that incorporates shellcode encryption, remote process injection, block dlls, and spoofed parent process

https://github.com/sh4hin/GoPurple - Yet another shellcode runner consists of different techniques for evaluating detection capabilities of endpoint security solutions

https://github.com/C-Sto/BananaPhone - It's a go variant of Hells gate! (directly calling windows kernel functions, but from Go!)

https://github.com/3xpl01tc0d3r/ProcessInjection - This program is designed to demonstrate various process injection techniques

https://github.com/plackyhacker/Shellcode-Injection-Techniques - A collection of C# shellcode injection techniques. All techniques use an AES encrypted meterpreter payload. I will be building this project up as I learn, discover or develop more techniques. Some techniques are better than others at bypassing AV.

https://github.com/snovvcrash/DInjector - Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL

https://github.com/plackyhacker/Suspended-Thread-Injection - Another meterpreter injection technique using C# that attempts to bypass Defender

https://github.com/boku7/Ninja_UUID_Dropper - Module Stomping, No New Thread, HellsGate syscaller, UUID Dropper for x64 Windows 10!

https://github.com/mobdk/Upsilon - Upsilon execute shellcode with syscalls - no API like NtProtectVirtualMemory is used

https://github.com/0xDivyanshu/Injector - Complete Arsenal of Memory injection and other techniques for red-teaming in Windows

https://github.com/JohnWoodman/stealthInjector - Injects shellcode into remote processes using direct syscalls

https://github.com/xpn/NautilusProject - A collection of weird ways to execute unmanaged code in .NET

https://github.com/xinbailu/DripLoader - Evasive shellcode loader for bypassing event-based injection detection (PoC)

https://github.com/cribdragg3r/Alaris - A protective and Low Level Shellcode Loader that defeats modern EDR systems.

https://github.com/theevilbit/injection - C++ Injection techniques

https://github.com/RomanRII/shellcode-through-ICMP - https://blog.romanrii.com/using-icmp-to-deliver-shellcode

https://github.com/ChaitanyaHaritash/Callback_Shellcode_Injection - POCs for Shellcode Injection via Callbacks

https://github.com/ChoiSG/UuidShellcodeExec - PoC for UUID shellcode execution using DInvoke

https://github.com/S4R1N/AlternativeShellcodeExec - Alternative Shellcode Execution Via Callbacks

https://github.com/DamonMohammadbagher/NativePayload_CBT - NativePayload_CallBackTechniques C# Codes (Code Execution via Callback Functions Technique, without CreateThread Native API)

https://github.com/S3cur3Th1sSh1t/Nim_CBT_Shellcode - CallBack-Techniques for Shellcode execution ported to Nim

# Loader / Packer / Injectors

https://github.com/med0x2e/ExecuteAssembly - Load/Inject .NET assemblies by; reusing the host (spawnto) process loaded CLR AppDomainManager, Stomping Loader/.NET assembly PE DOS headers, Unlinking .NET related modules, bypassing ETW+AMSI, avoiding EDR hooks via NT static syscalls (x64) and hiding imports by dynamically resolving APIs (hash)

https://github.com/EgeBalci/amber - Reflective PE packer.

https://github.com/djhohnstein/ScatterBrain - Suite of Shellcode Running Utilities

https://github.com/phra/PEzor - Open-Source PE Packer

https://github.com/dretax/DynamicDllLoader - This project describes a technique how a NATIVE dynamic link library (DLL) can be loaded from memory (In C#) without storing it on the hard-disk first.

https://github.com/nettitude/RunPE - C# Reflective loader for unmanaged binaries.

# EDR Evasion - Logging Evasion

https://github.com/CCob/SharpBlock - A method of bypassing EDR's active projection DLL's by preventing entry point execution

https://github.com/bats3c/Ghost-In-The-Logs - Evade sysmon and windows event logging

https://github.com/am0nsec/SharpHellsGate - C# Implementation of the Hell's Gate VX Technique

https://github.com/am0nsec/HellsGate - Original C Implementation of the Hell's Gate VX Technique

https://github.com/3gstudent/Windows-EventLog-Bypass - C++ Version of Invoke-Phantom

https://github.com/jfmaes/SharpNukeEventLog - C# version of Invoke-Phantom

https://github.com/Soledge/BlockEtw - .Net Assembly to block ETW telemetry in current process

https://github.com/ionescu007/faxhell - A Bind Shell Using the Fax Service and a DLL Hijack

https://github.com/realoriginal/ppdump-public - Protected Process (Light) Dump: Uses Zemana AntiMalware Engine To Open a Privileged Handle to a PP/PPL Process And Inject MiniDumpWriteDump() Shellcode

https://github.com/bats3c/EvtMute - This is a tool that allows you to offensively use YARA to apply a filter to the events being reported by windows event logging.

https://github.com/GetRektBoy724/TripleS - Extracting Syscall Stub, Modernized

https://github.com/call-042PE/UCantSeeM3 - Hiding your process in ProcessHacker,Task Manager,etc by patching NtQuerySystemInformation

https://github.com/bats3c/DarkLoadLibrary - LoadLibrary for offensive operations

https://github.com/moloch--/DarkLoadLibrary - Same but with LLVM support

https://github.com/scythe-io/memory-module-loader - An implementation of a Windows loader that can load dynamic-linked libraries (DLLs) directly from memory

https://github.com/Yaxser/Backstab - A tool to kill antimalware protected processes

https://github.com/RedCursorSecurityConsulting/PPLKiller - Tool to bypass LSA Protection (aka Protected Process Light)

https://github.com/passthehashbrowns/suspendedunhook - get NTDLL copy from suspended process

https://github.com/LloydLabs/delete-self-poc - A way to delete a locked file, or current running executable, on disk.

https://github.com/klezVirus/SharpSelfDelete - C# implementation of the research by @jonaslyk and the drafted PoC from @LloydLabs

https://github.com/jxy-s/herpaderping - Process Herpaderping proof of concept, tool, and technical deep dive. Process Herpaderping bypasses security products by obscuring the intentions of a process.

https://github.com/bohops/UltimateWDACBypassList - A centralized resource for previously documented WDAC bypass techniques

https://github.com/mgeeky/ShellcodeFluctuation - An advanced in-memory evasion technique fluctuating shellcode's memory protection between RW/NoAccess & RX and then encrypting/decrypting its contents

https://github.com/mgeeky/ThreadStackSpoofer - Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.

https://github.com/SolomonSklash/SleepyCrypt - A shellcode function to encrypt a running process image when sleeping.

https://github.com/aaaddress1/PR0CESS - some gadgets about windows process and ready to use :)

https://github.com/JLospinoso/gargoyle - A memory scanning evasion technique

https://github.com/passthehashbrowns/hiding-your-syscalls - Some source code to demonstrate avoiding certain direct syscall detections by locating and JMPing to a legitimate syscall instruction within NTDLL.

https://github.com/hasherezade/module_overloading - A more stealthy variant of "DLL hollowing"

https://github.com/forrest-orr/phantom-dll-hollower-poc - Phantom DLL hollowing PoC

https://github.com/hasherezade/transacted_hollowing - Transacted Hollowing - a PE injection technique, hybrid between ProcessHollowing and ProcessDoppelgänging

https://github.com/GetRektBoy724/SharpUnhooker - C# Based Universal API Unhooker

https://github.com/mgeeky/UnhookMe - UnhookMe is an universal Windows API resolver & unhooker addressing problem of invoking unmonitored system calls from within of your Red Teams malware

https://github.com/aaaddress1/wowInjector - PoC: Exploit 32-bit Thread Snapshot of WOW64 to Take Over $RIP & Inject & Bypass Antivirus HIPS (HITB 2021)

https://github.com/RedSection/OffensivePH - OffensivePH - use old Process Hacker driver to bypass several user-mode access controls

https://github.com/optiv/Dent - A framework for creating COM-based bypasses utilizing vulnerabilities in Microsoft's WDAPT sensors.

https://github.com/Dewera/Pluto - A manual system call library that supports functions from both ntdll.dll and win32u.dll

https://github.com/jackullrich/universal-syscall-64 - Resolve syscall numbers at runtime for all Windows versions.

https://github.com/br-sn/CheekyBlinder - Enumerating and removing kernel callbacks using signed vulnerable drivers

https://github.com/jthuraisamy/TelemetrySourcerer - Enumerate and disable common sources of telemetry used by AV/EDR.

https://github.com/TheWover/DInvoke - Dynamically invoke arbitrary unmanaged code from managed code without PInvoke.

https://github.com/fashionproof/CheckSafeBoot - I used this to see if an EDR is running in Safe Mode

https://github.com/asaurusrex/DoppelGate - DoppelGate relies on reading ntdll on disk to grab syscall stubs, and patches these syscall stubs into desired functions to bypass Userland Hooking.

# Useful Binary Modification tools

https://github.com/hasherezade/exe_to_dll

https://github.com/hasherezade/dll_to_exe

https://github.com/hasherezade/pe_to_shellcode

## Android
https://github.com/sensepost/kwetza

# External Penetration Testing

## Domain Finding / Subdomain Enumeration

https://github.com/aboul3la/Sublist3r

https://github.com/TheRook/subbrute

https://github.com/michenriksen/aquatone

https://github.com/darkoperator/dnsrecon

https://github.com/fwaeytens/dnsenum

https://github.com/s0md3v/Striker + Scanner

https://github.com/leebaird/discover

https://github.com/eldraco/domain_analyzer - more like an audit

https://github.com/caffix/amass - :heartpulse:

https://github.com/subfinder/subfinder

https://github.com/TypeError/domained

https://github.com/SilverPoision/Rock-ON

## File Search / Metadata extraction
https://github.com/dafthack/PowerMeta

https://github.com/ElevenPaths/FOCA

## Scanner

https://github.com/vesche/scanless

https://github.com/1N3/Sn1per

https://github.com/DanMcInerney/pentest-machine

https://github.com/jaeles-project/jaeles - The Swiss Army knife for automated Web Application Testing

## Email Gathering

https://github.com/leapsecurity/InSpy

https://github.com/dchrastil/ScrapedIn

https://github.com/SimplySecurity/SimplyEmail

https://github.com/clr2of8/GatherContacts

https://github.com/s0md3v/Zen - Find Emails of Github Users

https://github.com/m8r0wn/CrossLinked - super fast emails via google/bing linkedin dorks

https://github.com/m4ll0k/Infoga

https://github.com/navisecdelta/EmailGen - A simple email generator that uses dorks on Bing to generate emails from LinkedIn Profiles.

## Check Email Accounts

https://github.com/megadose/holehe - allows you to check if the mail is used on different sites like twitter, instagram and will retrieve information on sites with the forgotten password function.

## Domain Auth + Exploitation

https://github.com/nyxgeek/o365recon

https://github.com/gremwell/o365enum - Enumerate valid usernames from Office 365 using ActiveSync, Autodiscover v1, or office.com login page.

https://github.com/dafthack/MSOLSpray - A password spraying tool for Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.

https://github.com/sachinkamath/NTLMRecon - Tool to enumerate information from NTLM authentication enabled web endpoints

https://github.com/ustayready/fireprox - rotate IP Adresses over AWS - Combine with MSOLSpray

https://github.com/True-Demon/raindance - office 365 recon

https://github.com/dafthack/MailSniper

https://github.com/sensepost/ruler

https://github.com/Greenwolf/Spray - lockout Time integrated

https://github.com/nyxgeek/lyncsmash - Lync Credential Finder

https://github.com/byt3bl33d3r/SprayingToolkit - Scripts to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient

https://github.com/mdsecresearch/LyncSniper - Lync Credential Finder

https://github.com/3gstudent/easBrowseSharefile - Use to browse the share file by eas(Exchange Server ActiveSync)

https://github.com/FSecureLABS/peas - PEAS is a Python 2 library and command line application for running commands on an ActiveSync server e.g. Microsoft Exchange.

https://github.com/snovvcrash/peas - Modified version of PEAS client for offensive operations -  https://snovvcrash.rocks/2020/08/22/tuning-peas-for-fun-and-profit.html

https://github.com/RedLectroid/OutlookSend - A C# tool to send emails through Outlook from the command line or in memory

https://github.com/nccgroup/Carnivore - Tool for assessing on-premises Microsoft servers authentication such as ADFS, Skype, Exchange, and RDWeb

https://github.com/ricardojoserf/adfsbrute - A script to test credentials against Active Directory Federation Services (ADFS), allowing password spraying or bruteforce attacks.

https://github.com/nyxgeek/onedrive_user_enum - onedrive user enumeration - pentest tool to enumerate valid onedrive users

https://github.com/nyxgeek/AzureAD_Autologon_Brute - Brute force attack tool for Azure AD Autologon/Seamless SSO - Source: https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/

https://github.com/treebuilder/aad-sso-enum-brute-spray - POC of SecureWorks' recent Azure Active Directory password brute-forcing vuln

https://github.com/SecurityRiskAdvisors/msspray - Password attacks and MFA validation against various endpoints in Azure and Office 365

https://github.com/immunIT/TeamsUserEnum - User enumeration with Microsoft Teams API

https://github.com/knavesec/CredMaster - Refactored & improved CredKing password spraying tool, uses FireProx APIs to rotate IP addresses, stay anonymous, and beat throttling

## Exchange RCE-exploits

https://github.com/Airboi/CVE-2020-17144-EXP - Exchange2010 authorized RCE

https://github.com/Ridter/cve-2020-0688 - OWA Deserialisation RCE

## MobileIron RCE

https://github.com/httpvoid/CVE-Reverse/tree/master/CVE-2020-15505

# Specific Service Scanning / Exploitation

## Login Brute Force + Wordlist attacks

https://github.com/galkan/crowbar - Brute force non hydra compliant services - RDP, VNC, OpenVPN

https://github.com/1N3/BruteX - Brute Force various services

https://github.com/x90skysn3k/brutespray - :sunglasses:

https://github.com/DarkCoderSc/win-brute-logon - Crack any Microsoft Windows users password without any privilege (Guest account included)

https://github.com/lanjelot/patator

https://github.com/dafthack/RDPSpray - RDP Password Spray - No Event Logs

https://github.com/xFreed0m/RDPassSpray - Python3 tool to perform password spraying using RDP

## SNMP
https://github.com/hatlord/snmpwn

## Open X11
https://github.com/sensepost/xrdp

## Printers
https://github.com/RUB-NDS/PRET

https://github.com/BusesCanFly/PRETty - Automation for PRET

## MSSQL
https://github.com/quentinhardy/msdat

## Oracle
https://github.com/quentinhardy/odat

## IKE
https://github.com/SpiderLabs/ikeforce

## SMB Null Session Exploitation
https://github.com/m8r0wn/nullinux

## iLO Exploitation

https://github.com/airbus-seclab/ilo4_toolbox
https://www.exploit-db.com/exploits/44005

## vmware vCenter Exploits

https://github.com/guardicore/vmware_vcenter_cve_2020_3952 - Exploit for CVE-2020-3952 in vCenter 6.7

## Intel AMT Exploitation
https://github.com/Coalfire-Research/DeathMetal

## SAP Exploitation
https://github.com/comaeio/OPCDE

https://github.com/gelim/sap_ms

https://github.com/chipik/SAP_GW_RCE_exploit

## FPM port

Found Port 9001 open? Try that: 

https://github.com/hannob/fpmvuln - bash poc scripts to exploit open fpm ports

## Weblogic Exploitation

https://github.com/0xn0ne/weblogicScanner - scan/test for nearly all weblogic vulns

https://github.com/quentinhardy/jndiat - WEblogic Server Tests

https://github.com/kingkaki/weblogic-scan

https://github.com/FlyfishSec/weblogic_rce - cve-2019-2725

https://github.com/SukaraLin/CVE-2019-2890

https://github.com/1337g/CVE-2017-10271 

https://github.com/LandGrey/CVE-2018-2894

https://github.com/Y4er/CVE-2020-2551

## Sharepoint exploitation

https://github.com/sensepost/SPartan - Sharepoint Fingerprint + Exploitation

https://github.com/Voulnet/desharialize

## JIRA

https://github.com/0x48piraj/Jiraffe - One stop place for exploiting Jira instances in your proximity

## Sonicwall VPN

https://github.com/darrenmartyn/VisualDoor

## VSphere VCenter

https://github.com/JamesCooteUK/SharpSphere - .NET Project for Attacking vCenter

## Dameware

https://github.com/warferik/CVE-2019-3980

## Confluence Exploit

https://github.com/h3v0x/CVE-2021-26084_Confluence - Confluence Server Webwork OGNL injection

## Telerik UI for ASP.NET AJAX Exploit

https://github.com/noperator/CVE-2019-18935

## General Recon

https://github.com/FortyNorthSecurity/EyeWitness

## Solarwinds

https://github.com/mubix/solarflare - SolarWinds Orion Account Audit / Password Dumping Utility

# Command & Control Frameworks

https://github.com/n1nj4sec/pupy

https://github.com/nettitude/PoshC2

https://github.com/FortyNorthSecurity/WMImplant

https://github.com/quasar/QuasarRAT

https://github.com/EmpireProject/Empire

https://github.com/zerosum0x0/koadic

https://github.com/Mr-Un1k0d3r/ThunderShell

https://github.com/Ne0nd0g/merlin

https://github.com/Arno0x/WebDavC2

https://github.com/malwaredllc/byob

https://github.com/byt3bl33d3r/SILENTTRINITY

https://github.com/SharpC2/SharpC2 - Command and Control Framework written in C#.

https://github.com/Arno0x/WSC2

https://github.com/BC-SECURITY/Empire - Empire with embedded AMSI-Bypass

https://github.com/cobbr/Covenant

https://github.com/cobbr/C2Bridge - C2Bridges allow developers to create new custom communication protocols and quickly utilize them within Covenant.

https://github.com/py7hagoras/CovenantTasks - Source for tasks I have used with Covenant

https://github.com/BishopFox/sliver - Implant framework

https://github.com/bats3c/shad0w - A post exploitation framework designed to operate covertly on heavily monitored environments

https://github.com/FSecureLABS/C3 - Custom Command and Control (C3). A framework for rapid prototyping of custom C2 channels, while still providing integration with existing offensive toolkits.

https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp - Open-Source Remote Administration Tool For Windows C# (RAT)

https://github.com/its-a-feature/Mythic

https://github.com/Cr4sh/MicroBackdoor - Small and convenient C2 tool for Windows targets

https://github.com/cyberark/kubesploit - Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang, focused on containerized environments.

## Mythic Agents

https://github.com/MythicAgents/Apollo

https://github.com/MythicAgents/Nimplant

# VBA

https://github.com/JohnWoodman/VBA-Macro-Projects - This repository is a collection of my malicious VBA projects.

https://github.com/karttoon/trigen - Trigen is a Python script which uses different combinations of Win32 function calls in generated VBA to execute shellcode.

https://github.com/rmdavy/HeapsOfFun - AMSI Bypass Via the Heap

https://github.com/S3cur3Th1sSh1t/OffensiveVBA - This repo covers some code execution and AV Evasion methods for Macros in Office documents

# Rust

https://github.com/Kudaes/DInvoke_rs - Dynamically invoke arbitrary unmanaged code.

https://github.com/trickster0/OffensiveRust - Rust Weaponization for Red Team Engagements.

# Go

https://github.com/malware-unicorn/GoPEInjection - Golang PE injection on windows

# Cobalt Strike Stuff

https://github.com/DeEpinGh0st/Erebus

https://github.com/aleenzz/Cobalt_Strike_wiki

https://github.com/FortyNorthSecurity/C2concealer

https://github.com/invokethreatguy/AggressorCollection

https://github.com/harleyQu1nn/AggressorScripts

https://github.com/mgeeky/cobalt-arsenal - My collection of battle-tested Aggressor Scripts for Cobalt Strike 4.0+

https://github.com/xforcered/CredBandit - Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel

https://github.com/EncodeGroup/BOF-RegSave - Dumping SAM / SECURITY / SYSTEM registry hives with a Beacon Object File

https://github.com/EncodeGroup/AggressiveGadgetToJScript - A Cobalt Strike Aggressor script to generate GadgetToJScript payloads

https://github.com/rvrsh3ll/BOF_Collection - Various Cobalt Strike BOFs

https://github.com/EspressoCake/HandleKatz_BOF - A BOF port of the research of @thefLinkk and @codewhitesec

https://github.com/trustedsec/CS-Situational-Awareness-BOF - Situational Awareness commands implemented using Beacon Object Files

https://github.com/anthemtotheego/InlineExecute-Assembly - InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module

https://github.com/EspressoCake/Self_Deletion_BOF - BOF implementation of the research by @jonaslyk and the drafted PoC from @LloydLabs

https://github.com/EspressoCake/PPLDump_BOF - A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.

https://github.com/boku7/CobaltStrikeReflectiveLoader - Cobalt Strike User-Defined Reflective Loader written in Assembly & C for advanced evasion capabilities.

https://github.com/optiv/Registry-Recon - Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon

https://github.com/Tylous/SourcePoint - SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.

https://github.com/boku7/spawn - Cobalt Strike BOF that spawns a sacrificial process, injects it with shellcode, and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG), BlockDll, and PPID spoofing.

https://github.com/OG-Sadpanda/SharpExcelibur - Read Excel Spreadsheets (XLS/XLSX) using Cobalt Strike's Execute-Assembly

https://github.com/OG-Sadpanda/SharpSword - Read the contents of DOCX files using Cobalt Strike's Execute-Assembly

https://github.com/EncodeGroup/AggressiveProxy - Project to enumerate proxy configurations and generate shellcode from CobaltStrike

https://github.com/mgeeky/RedWarden - Cobalt Strike C2 Reverse proxy that fends off Blue Teams, AVs, EDRs, scanners through packet inspection and malleable profile correlation

https://github.com/rsmudge/unhook-bof - Remove API hooks from a Beacon process.

https://github.com/ajpc500/BOFs - Collection of Beacon Object Files

https://github.com/outflanknl/InlineWhispers - Tool for working with Direct System Calls in Cobalt Strike's Beacon Object Files (BOF)

# Android
https://github.com/AhMyth/AhMyth-Android-RAT

# Linux MacOSX Specific
https://github.com/neoneggplant/EggShell


# Wifi Tools

https://github.com/wifiphisher/wifiphisher

https://github.com/P0cL4bs/WiFi-Pumpkin

https://github.com/s0lst1c3/eaphammer

https://github.com/h0nus/RogueSploit

https://github.com/Tylous/SniffAir

https://github.com/FluxionNetwork/fluxion

https://github.com/derv82/wifite2

https://github.com/ICSec/airpwn-ng

https://github.com/xdavidhu/mitmAP

https://github.com/ZerBea/hcxdumptool

https://github.com/P0cL4bs/wifipumpkin3 - Powerful framework for rogue access point attack.

# Android / Nethunter
https://github.com/faizann24/wifi-bruteforcer-fsecurify

https://github.com/chrisk44/Hijacker

# NAT Slipstreaming

https://github.com/samyk/slipstream - NAT Slipstreaming allows an attacker to remotely access any TCP/UDP services bound to a victim machine, bypassing the victim’s NAT/firewall, just by the victim visiting a website

# Raspberri PI Exploitation

https://github.com/secgroundzero/warberry

https://github.com/samyk/poisontap

https://github.com/mame82/P4wnP1

https://github.com/mame82/P4wnP1_aloa

https://github.com/pi-hole/pi-hole

# Physical Security / HID/ETH Emulator

https://github.com/carmaa/inception - PCI-based DMA

https://github.com/samratashok/Kautilya

https://github.com/ufrisk/pcileech - PCI based DMA

https://github.com/Screetsec/Brutal - Teensy Payloads

https://github.com/insecurityofthings/jackit

https://github.com/BastilleResearch/mousejack

# Social Engeneering

https://github.com/kgretzky/evilginx

https://github.com/threatexpress/domainhunter

https://github.com/netevert/dnsmorph - lookup valid phishing-Domains

https://github.com/elceef/dnstwist - lookup valid phishing-Domains

https://github.com/quickbreach/SMBetray - Change SMB Files on the fly

https://github.com/SteveLTN/https-portal

https://github.com/ryhanson/phishery

https://github.com/curtbraz/Phishing-API - Comprehensive Web Based Phishing Suite of Tools for Rapid Deployment and Real-Time Alerting!

# Defender Guides / Tools / Incident Response / Blue Team

https://github.com/CCob/BeaconEye - Hunts out CobaltStrike beacons and logs operator command output

https://github.com/3lp4tr0n/BeaconHunter - Detect and respond to Cobalt Strike beacons using ETW.

https://github.com/IonizeCbr/AmsiPatchDetection - Detect AMSI.dll in memory patch

https://github.com/cisagov/Sparrow - Sparrow.ps1 was created by CISA's Cloud Forensics team to help detect possible compromised accounts and applications in the Azure/m365 environment.

https://github.com/meirwah/awesome-incident-response

https://github.com/CredDefense/CredDefense - Credential and Red Teaming Defense for Windows Environments

https://github.com/PaulSec/awesome-windows-domain-hardening

https://github.com/ernw/hardening

https://github.com/Invoke-IR/Uproot

https://github.com/danielbohannon/Revoke-Obfuscation - powershell obfuscation detection

https://github.com/NotPrab/.NET-Deobfuscator - Lists of .NET Deobfuscator and Unpacker (Open Source)

https://github.com/countercept/python-exe-unpacker - python exe decompile

https://github.com/0xd4d/de4dot - .NET Revoke-Obfuscation

https://github.com/securitywithoutborders/hardentools

https://github.com/x0rz/phishing_catcher

https://github.com/Ben0xA/PowerShellDefense

https://github.com/emposha/PHP-Shell-Detector

https://github.com/LordNoteworthy/al-khaser

https://github.com/Security-Onion-Solutions/security-onion - ids

https://github.com/ptresearch/AttackDetection

https://github.com/MHaggis/hunt-detect-prevent

https://github.com/JPCERTCC/LogonTracer - Investigate malicious Windows logon by visualizing and analyzing Windows event log 

https://github.com/lithnet/ad-password-protection - AD Passwort Blacklisting

https://github.com/R3MRUM/PSDecode - Powershell DE-Obfuscation

https://github.com/denisugarte/PowerDrive - A tool for de-obfuscating PowerShell scripts

https://github.com/matterpreter/DefenderCheck - Identifies the bytes that Microsoft Defender flags on.

https://github.com/rasta-mouse/ThreatCheck - Identifies the bytes that Microsoft Defender / AMSI Consumer flags on.

https://github.com/hegusung/AVSignSeek - Tool written in python3 to determine where the AV signature is located in a binary/payload

https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

https://github.com/ION28/BLUESPAWN - An Active Defense and EDR software to empower Blue Teams

https://github.com/hasherezade/hollows_hunter - Scans all running processes. Recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches).

https://github.com/hasherezade/pe-sieve - Scans a given process. Recognizes and dumps a variety of potentially malicious implants (replaced/injected PEs, shellcodes, hooks, in-memory patches).

https://github.com/0Kee-Team/WatchAD - AD Security Intrusion Detection System

https://github.com/nsacyber/Mitigating-Web-Shells

https://github.com/redcanaryco/atomic-red-team - Small and highly portable detection tests based on MITRE's ATT&CK.

https://github.com/DamonMohammadbagher/ETWProcessMon2 - ETWProcessMon2 is for Monitoring Process/Thread/Memory/Imageloads/TCPIP via ETW + Detection for Remote-Thread-Injection & Payload Detection by VirtualMemAlloc Events (in-memory) etc.

https://github.com/p0dalirius/LDAPmonitor - Monitor creation, deletion and changes to LDAP objects live during your pentest or system administration!

https://github.com/PSGumshoe/PSGumshoe - PSGumshoe is a Windows PowerShell module for the collection of OS and domain artifacts for the purposes of performing live response, hunt, and forensics.

https://github.com/rajiv2790/FalconEye - FalconEye is a windows endpoint detection software for real-time process injections. It is a kernel-mode driver that aims to catch process injections as they are happening (real-time). Since FalconEye runs in kernel mode, it provides a stronger and reliable defense against process injection techniques that try to evade various user-mode hooks.

# Wordlists / Wordlist generators

https://github.com/danielmiessler/SecLists

https://github.com/berzerk0/Probable-Wordlists

https://github.com/govolution/betterdefaultpasslist

https://github.com/insidetrust/statistically-likely-usernames

https://github.com/LandGrey/pydictor

https://github.com/sc0tfree/mentalist

https://github.com/skahwah/wordsmith

https://github.com/1N3/IntruderPayloads

https://github.com/fuzzdb-project/fuzzdb

https://github.com/Bo0oM/fuzz.txt

https://github.com/laconicwolf/Password-Scripts

https://github.com/FlameOfIgnis/Pwdb-Public - A collection of all the data i could extract from 1 billion leaked credentials from internet.

# AD Lab Environment

https://github.com/davidprowe/BadBlood

https://github.com/WazeHell/vulnerable-AD - Create a vulnerable active directory that's allowing you to test most of the active directory attacks in a local lab

https://github.com/clong/DetectionLab - Automate the creation of a lab environment complete with security tooling and logging best practices

# Obfuscation

https://github.com/xoreaxeaxeax/movfuscator

https://github.com/danielbohannon/Invoke-DOSfuscation

https://github.com/unixpickle/gobfuscate - GO Obfuscator

https://github.com/NotPrab/.NET-Obfuscator - Lists of .NET Obfuscator (Free, Trial, Paid and Open Source )

https://github.com/javascript-obfuscator/javascript-obfuscator - Javascript Obfuscator

https://github.com/danielbohannon/Invoke-Obfuscation - Powershell Obfuscator

https://github.com/BinaryScary/NET-Obfuscate - .NET IL Obfuscator

https://github.com/scrt/avcleaner - C/C++ source obfuscator for antivirus bypass

https://github.com/meme/hellscape - GIMPLE obfuscator for C, C++, Go, ... all supported GCC targets and front-ends that use GIMPLE.

https://github.com/mgeeky/VisualBasicObfuscator - VBS Obfuscator

https://github.com/3xpl01tc0d3r/Obfuscator - Shellcode Obfuscator

https://github.com/EgeBalci/sgn - Shellcode Encoder

https://github.com/burrowers/garble - Obfuscate Go builds

https://github.com/JustasMasiulis/xorstr - heavily vectorized c++17 compile time string encryption.

https://github.com/AnErrupTion/LoGiC.NET - A more advanced free and open .NET obfuscator using dnlib.

https://github.com/klezVirus/chameleon - PowerShell Script Obfuscator

https://github.com/xforcered/InvisibilityCloak - Proof-of-concept obfuscation toolkit for C# post-exploitation tools

https://github.com/Flangvik/RosFuscator - YouTube/Livestream project for obfuscating C# source code using Roslyn

https://github.com/JoelGMSec/Invoke-Stealth - Simple & Powerful PowerShell Script Obfuscator

https://github.com/GetRektBoy724/BetterXencrypt - A better version of Xencrypt.Xencrypt it self is a Powershell runtime crypter designed to evade AVs.

https://github.com/obfuscator-llvm/obfuscator - C obfuscator

https://github.com/moloch--/denim - NIM llvm obfuscator

# Hash Crack / Decryption

https://hashcat.net/hashcat/

https://github.com/Ciphey/Ciphey - Ciphey is an automated decryption tool. Input encrypted text, get the decrypted text back.

https://github.com/Coalfire-Research/npk - A mostly-serverless distributed hash cracking platform

https://github.com/JoelGMSec/Cloudtopolis - Cracking hashes in the Cloud (for free!)

https://github.com/f0cker/crackq - CrackQ: A Python Hashcat cracking queue system

# Source Code / Binary Analysis

## Binary Analysis

https://github.com/avast/retdec

https://github.com/MobSF/Mobile-Security-Framework-MobSF

## Source Code Analysis

https://github.com/mre/awesome-static-analysis

https://github.com/eslint/eslint - Javascript

https://github.com/dpnishant/jsprime - Javascript

https://github.com/phpstan/phpstan - PHP

https://github.com/ecriminal/phpvuln - Audit tool to find common vulnerabilities in PHP source code

# Nim

https://github.com/snovvcrash/NimHollow - Nim implementation of Process Hollowing using syscalls (PoC)

https://github.com/jonaslejon/malicious-pdf - Malicious PDF Generator

https://github.com/byt3bl33d3r/OffensiveNim

https://github.com/Yardanico/nim-strenc - A tiny library to automatically encrypt string literals in Nim code

https://github.com/ChaitanyaHaritash/NIM-Scripts

https://github.com/Moriarty2016/NimRDI - RDI implementation in Nim

https://github.com/ajpc500/NimExamples - A collection of offensive Nim example code

https://github.com/elddy/Nim-SMBExec - SMBExec implementation in Nim - SMBv2 using NTLM Authentication with Pass-The-Hash technique

https://github.com/FedericoCeratto/nim-socks5 - Nim Socks5 library

# MISC

https://github.com/rvrsh3ll/TokenTactics - Azure JWT Token Manipulation Toolset

https://github.com/zer1t0/ticket_converter - A little tool to convert ccache tickets into kirbi (KRB-CRED) and vice versa based on impacket.

https://github.com/pentestmonkey/gateway-finder

https://github.com/Cybellum/DoubleAgent

https://github.com/ytisf/theZoo

https://github.com/kbandla/APTnotes

https://github.com/WindowsLies/BlockWindows

https://github.com/secrary/InjectProc

https://github.com/AlsidOfficial/WSUSpendu

https://github.com/SigPloiter/SigPloit

https://github.com/virajkulkarni14/WebDeveloperSecurityChecklist

https://github.com/PowerShell/PowerShell

https://github.com/landhb/HideProcess

https://github.com/meliht/Mr.SIP

https://github.com/XiphosResearch/exploits

https://github.com/jas502n/CVE-2019-13272

https://github.com/fox-it/cve-2019-1040-scanner

https://github.com/worawit/MS17-010

https://github.com/DiabloHorn/yara4pentesters

https://github.com/D4Vinci/Cr3dOv3r

https://github.com/a2u/CVE-2018-7600 - Drupal Exploit

https://github.com/joxeankoret/CVE-2017-7494 - SAMBA Exploit

https://github.com/D4Vinci/One-Lin3r - Reverse Shell Oneliner / Payload Generation

https://github.com/0x00-0x00/ShellPop - Reverse/Bind Shell Generator

https://github.com/Acceis/crypto_identifier

https://github.com/sensepost/UserEnum - check if a user is valid in a domain

https://github.com/LOLBAS-Project/LOLBAS - Living of the Land Binaries

https://github.com/peewpw/Invoke-BSOD - Windows Denial of Service Exploit

https://github.com/mtivadar/windows10_ntfs_crash_dos - Windows Denial of Service Exploit

https://github.com/deepzec/Bad-Pdf PDF Steal NTLMv2 Hash Exploit - CVE-2018-4993

https://github.com/SecureAuthCorp/impacket - :boom: :fire: :boom:

https://github.com/blacknbunny/libSSH-Authentication-Bypass - LibSSH Authentication Bypass vuln.

https://github.com/OneLogicalMyth/zeroday-powershell - windows Privesc Exploit

https://github.com/smicallef/spiderfoot - OSINT

https://github.com/ShawnDEvans/smbmap

https://github.com/Coalfire-Research/java-deserialization-exploits - Deserialisation Exploits

https://github.com/RhinoSecurityLabs/GCPBucketBrute - S3 bucket tester

https://github.com/khast3x/h8mail

https://github.com/dirkjanm/adidnsdump - Zone transfer like for internal assessment

https://github.com/gquere/pwn_jenkins

https://github.com/JavelinNetworks/IR-Tools - Get-ShellContent.ps1 get the typed content for all open shells

https://github.com/taviso/ctftool - windows CTF Exploitation

https://github.com/jedisct1/dsvpn

https://github.com/GoSecure/dtd-finder

https://github.com/tyranid/DotNetToJScript

https://github.com/cfreal/exploits - Apache Privilege Escalation

https://github.com/Al1ex/WindowsElevation - Windows Elevation(持续更新)

https://github.com/adamdriscoll/snek - Execute python from powershell

https://github.com/g0tmi1k/exe2hex

https://github.com/beurtschipper/Depix - Recovers passwords from pixelized screenshots

https://github.com/slaeryan/AQUARMOURY - This is a tool suite consisting of miscellaneous offensive tooling aimed at red teamers/penetration testers to primarily aid in Defense Evasion TA0005

https://github.com/mmozeiko/aes-finder - Utility to find AES keys in running processes

https://github.com/Flangvik/SharpCollection - Nightly builds of common C# offensive tools, fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.

https://github.com/CCob/MinHook.NET - A C# port of the MinHook API hooking library

https://github.com/Mr-Un1k0d3r/EDRs - This repo contains information about EDRs that can be useful during red team exercise.

# Big-IP Exploitation

https://github.com/jas502n/CVE-2020-5902

# Azure Cloud Tools

https://github.com/hausec/PowerZure

https://github.com/NetSPI/MicroBurst

https://github.com/dirkjanm/ROADtools - The Azure AD exploration framework.

https://github.com/dafthack/CloudPentestCheatsheets

https://github.com/cyberark/BlobHunter - Find exposed data in Azure with this public blob scanner

# Anonymous / Tor Projects
https://github.com/realgam3/pymultitor

https://github.com/Und3rf10w/kali-anonsurf

https://github.com/GouveaHeitor/nipe

https://github.com/cryptolok/GhostInTheNet

https://github.com/DanMcInerney/elite-proxy-finder

# Exploit Search
https://github.com/vulnersCom/getsploit

https://github.com/1N3/Findsploit

# Industrial Control Systems

https://github.com/dark-lbp/isf

https://github.com/klsecservices/s7scan

https://github.com/w3h/isf

https://github.com/atimorin/scada-tools - 

# Network access control bypass

https://github.com/scipag/nac_bypass

# Jenkins 

https://github.com/cedowens/Jenkins_Hunter_CSharp

https://github.com/petercunha/jenkins-rce

https://github.com/gquere/pwn_jenkins

https://medium.com/@adamyordan/a-case-study-on-jenkins-rce-c2558654f2ce

https://github.com/Accenture/jenkins-attack-framework

# JMX Exploitation

https://github.com/mogwailabs/mjet

https://github.com/siberas/sjet

https://github.com/qtc-de/beanshooter - JMX enumeration and attacking tool.

https://github.com/mogwaisec/mjet - Mogwai Java Management Extensions (JMX) Exploitation Toolkit

# Citrix Netscaler Pwn

https://github.com/trustedsec/cve-2019-19781

# mikrotik pwn

https://github.com/vulnersCom/mikrot8over - Fast exploitation tool for Mikrotik RouterOS up to 6.38.4

# Red Team infrastructure setup

https://github.com/obscuritylabs/RAI

https://github.com/Coalfire-Research/Red-Baron - terraform cloud c2 redirector setup

https://github.com/qsecure-labs/overlord - Red Teaming Infrastructure Automation based on Red-Baron

https://github.com/rmikehodges/hideNsneak - This application assists in managing attack infrastructure for penetration testers by providing an interface to rapidly deploy, manage, and take down various cloud services. These include VMs, domain fronting, Cobalt Strike servers, API gateways, and firewalls.

https://github.com/shr3ddersec/Shr3dKit

https://github.com/t94j0/satellite

https://github.com/Cerbersec/DomainBorrowingC2 - Domain Borrowing is a new method to hide C2 traffic using CDN. It was first presented at Blackhat Asia 2021 by Junyu Zhou and Tianze Ding. 

https://github.com/Dliv3/DomainBorrowing - Domain Borrowing PoC

# Bypass SPF/DKIM/DMARC

https://github.com/chenjj/espoofer

# Redis Exploitation

https://github.com/n0b0dyCN/redis-rogue-server

https://github.com/Ridter/redis-rce

MSF:

* scanner/redis/file_upload

* exploit/linux/redis/redis_replication_cmd_exec

Windows Targets - Webshell upload
```
redis-cli -h targethost -p targetport
config set dir C:\inetpub\wwwroot\
config set dbfilename shell.aspx
set test "Webshell content"
save
```

# Apache Tomcat Exploitation

https://github.com/mgeeky/tomcatWarDeployer - Apache Tomcat auto WAR deployment & pwning penetration testing tool.

https://github.com/00theway/Ghostcat-CNVD-2020-10487 - AJP Exploit CVE-2020-1938

https://github.com/Ridter/redis-rce

# SSRF Exploitation

https://github.com/swisskyrepo/SSRFmap

# LFI exploitation

https://github.com/mzfr/liffy

# MondoDB Redis Couchdb Exploitation

https://github.com/torque59/Nosql-Exploitation-Framework

https://github.com/Charlie-belmer/nosqli - NoSql Injection CLI tool, for finding vulnerable websites using MongoDB.

# XXE 

https://github.com/luisfontes19/xxexploiter

# Elasticsearch / Kibana Exploitation

https://github.com/0xbug/Biu-framework

# RMI attacks

https://github.com/NickstaDB/BaRMIe

https://github.com/BishopFox/rmiscout - RMIScout uses wordlist and bruteforce strategies to enumerate Java RMI functions and exploit RMI parameter unmarshalling vulnerabilities

# JSON Web Token Analysis / Exploitation

https://github.com/ticarpi/jwt_tool

# Docker Exploitation

https://github.com/AbsoZed/DockerPwn.py - automation of Docker TCP socket abuse

https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CVE%20Exploits/Docker%20API%20RCE.py - Docker API exposed RCE

# PHP exploits

https://github.com/neex/phuip-fpizdam - nginx + php misconfiguration

# Cloud attack tools

https://github.com/mdsecactivebreach/o365-attack-toolkit

# Bluetooth / low energy

https://github.com/ojasookert/CVE-2017-0785

https://github.com/evilsocket/bleah

https://github.com/virtualabs/btlejack

# Wireless / Radio Exploitation

https://github.com/mame82/LOGITacker

# APT / Malware Emulation / Defense Check
https://github.com/TryCatchHCF/DumpsterFire

https://github.com/NextronSystems/APTSimulator

https://github.com/redhuntlabs/RedHunt-OS

https://github.com/guardicore/monkey

# Hash Crack / Lookup
https://github.com/k4m4/dcipher-cli

https://github.com/s0md3v/Hash-Buster

https://github.com/initstring/passphrase-wordlist

# OSCP Lists / tools / help

https://github.com/sailay1996/expl-bin

https://github.com/CyDefUnicorn/OSCP-Archives

# ASPX Webshells

https://github.com/antonioCoco/SharPyShell

# PHP Webshells

https://github.com/flozz/p0wny-shell

https://github.com/nil0x42/phpsploit - Full-featured C2 framework which silently persists on webserver via evil PHP oneliner

https://github.com/gellin/bantam - A PHP backdoor management and generation tool/C2 featuring end to end encrypted payload streaming designed to bypass WAF, IDS, SIEM systems.

# JSP WebShells

https://github.com/SecurityRiskAdvisors/cmd.jsp

# Other Tool-Lists / Cheat Sheets

https://github.com/D3VI5H4/Antivirus-Artifacts - List of Hooking DLLs for different AV vendors

https://github.com/PwnDexter/SharpEDRChecker - Checks running processes, process metadata, Dlls loaded into your current process and the each DLLs metadata, common install directories, installed services and each service binaries metadata, installed drivers and each drivers metadata, all for the presence of known defensive products such as AV's, EDR's and logging tools.

https://github.com/Hack-with-Github/Awesome-Hacking

https://github.com/enaqx/awesome-pentest

https://github.com/HarmJ0y/CheatSheets

https://github.com/zhzyker/exphub

https://github.com/vysecurity/RedTips

https://github.com/toolswatch/blackhat-arsenal-tools

https://github.com/jivoi/awesome-osint

https://github.com/qazbnm456/awesome-cve-poc

https://github.com/swisskyrepo/PayloadsAllTheThings

https://github.com/dsasmblr/hacking-online-games

https://github.com/carpedm20/awesome-hacking

https://github.com/rshipp/awesome-malware-analysis

https://github.com/thibmaek/awesome-raspberry-pi

https://github.com/bigb0sss/RedTeam-OffensiveSecurity

https://github.com/vitalysim/Awesome-Hacking-Resources

https://github.com/mre/awesome-static-analysis

https://github.com/coreb1t/awesome-pentest-cheat-sheets

https://github.com/infosecn1nja/Red-Teaming-Toolkit

https://github.com/rmusser01/Infosec_Reference

https://github.com/trimstray/the-book-of-secret-knowledge

https://github.com/N7WEra/SharpAllTheThings

https://github.com/3gstudent/Pentest-and-Development-Tips

https://github.com/qazbnm456/awesome-web-security

https://github.com/chryzsh/awesome-windows-security

https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE

https://github.com/We5ter/Scanners-Box

https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet

https://github.com/smgorelik/Windows-RCE-exploits

https://github.com/trustedsec/physical-docs

https://github.com/matterpreter/OffensiveCSharp

https://github.com/mgeeky/Penetration-Testing-Tools

https://github.com/nomi-sec/PoC-in-GitHub

https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques

https://github.com/netbiosX/Checklists

https://github.com/Mr-Un1k0d3r/RedTeamCSharpScripts

https://github.com/adon90/pentest_compilation

https://github.com/sailay1996/awesome_windows_logical_bugs

https://github.com/EnableSecurity/awesome-rtc-hacking

https://github.com/api0cradle/UltimateAppLockerByPassList

https://github.com/hahwul/WebHackersWeapons

https://github.com/d0nkeys/redteam

https://github.com/d1pakda5/PowerShell-for-Pentesters

https://github.com/Mr-Un1k0d3r/RedTeamCSharpScripts

https://github.com/google/tsunami-security-scanner
