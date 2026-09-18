# securestack-detection-range

This project serves as the guide for Detection and Response Engineering. The prjoect employs MITRE ATT&CK vectors by associating observed intrusions tagging it to a Technique ID. The project is implemented on AWS and the brain for this project is the SIEM (ElasticStack) with elastic agents configured on a Windows and Ubuntu hosts.

Windows and Linux stores log events but they are not granular. Sysmon and authd writes rich, detection ready events in to its own channel. They are then forwarded to the SIEM where detections are fired based on the rules configured for alerting. 

The communication b/w elastic agent and SIEM happens on two channels 
1. control channel - used for policy updates and connection
2. Data channel - forward logs.

Here is an example of a windows event and a Linux event as seen on the SIEM 

