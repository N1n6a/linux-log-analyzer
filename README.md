# Linux Log Analyzer

A Flask-based web dashboard for analyzing Linux authentication logs (/var/log/auth.log or secure), built to surface the kind of activity a SOC Tier 1 Analyst would triage : brute-force attempts, privilege escalation abuse, and multi-stage attack chains; All ranked by severity.


### Known Limitations 

While stress-testing with a synthetic enterprise-scale auth log generator, a false-positive bug was found : The attack-chain correlation logic was flagging an unrealistic number of chains on high-volume logs. 
Fixing it was a good lesson in how detection rules that look correct on small test data can break down at scale.