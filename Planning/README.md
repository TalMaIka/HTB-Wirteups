

![[logo.png]]

nmap scan showed the following opened ports:
![[nmap.png]]

Port 80:
![[main-site.png]]

Fuzzing for logging yielded nothing.

Fuzzing subdomains:
![[ffuf-subdomains.png]]

Here we go!

![[grafana.png]]

![[version.png]]

Quick search got us with CVE-2024-9264-RCE-Exploit

And we are in (Rev-shell):
![[revshell.png]]

This is a Docker container !.

![[linpeas.png]]

Running linpeas got us with the creds for enzo.

SSH to the main box:

![[ss.png]]

Local port forwarding:

ssh -L 8000:localhost:8000 enzo@10.10.11.68

![[login.png]]

Running linpeas on the main machine:
![[main-linpeas.png]]

Logging in using credentianls from crontab.db

![[root-cron.png]]

Executing the malicious cron:

![[pwnd.png]]

