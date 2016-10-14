# ossecKibanaElkonWindows-475-2161_bornholm
This tool will setup OSSEC(windows variant) on Windows and perform log analysis with Kibana/ELK.  Powershell scripts will configure OSSEC clients and send output to Kibana. Data in Kibana will feed dashboards and e-mail alerts for user-specified events/incidents.  Documentation will allow users to configure these tools easily. 



1. Setup an ELK stack
	a. Create automation script to install ELK stack
	b. Secure kibana login
	c. Nginx web proxy front end
2. Setup an ELK stack with SSL transmission
	a. Script work with Let's encrypt
3. Setup an OSSEC management server with ELK stack
	a. Setup automatic to accept new clients without sys admin intereaction.
4. Create grok parser for OSSEC logs
	a. How to sanitize data for elasticsearch when it comes in
5. Create powershell script to install ossec on Windows and forward all data to OSSEC management node
	a. powershell script that can be deployed by Domain Controllers via Group policy
	b. Script pulls down cert file to send data securely.
6. Watch various alerts coming from OSSEC and tweak what is logged
	a. Does it log everything in windows event manager? Does it log on a limited set?
7. Create Kibana Dashboards on the data coming in
	a. Incorrect login attempts, spike in DNS traffic, etc
8. Setup what we want to alert on.
	a. 10 incorrect logins within 10min time frame.
	b. New domain admin users created
	c. When a user obtain admin privs 
9. Use a service like elastalert to send e-mail alerts on predefined alerts.
10. Create public documentation for others to follow my work. 
	a. Documentation will be posted on my blog: HoldMyBeer.xyz
	b. Documentation will be posted here in this readme on github.
