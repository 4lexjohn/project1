# project1
What is Suricata:
Suricata is a free tool that helps protect computer networks from threats. It watches network traffic in real time and performs important security tasks to detect and prevent malicious activity.
Functions of Suricata:
• Intrusion Detection System (IDS):
It looks at network traffic and checks for anything suspicious or known to be harmful, based on a set of rules.
• Intrusion Prevention System (IPS):
In this mode, Suricata doesn't just detect threats - it can stop them right away by blocking the bad traffic.
• Network Security Monitoring (NSM):
It keeps track of all network activity so that security teams can review it later if something goes wrong. It also creates logs of things like website visits or DNS lookups.
• Packet Capture (PCAP):
Like tools such as Wireshark, it can save a copy of all the network data for later analysis.


Installing Suricata:
Step1) Install the dependencies using,Install the dependencies using:
sudo apt-get install software-properties-common

Step2) Now add suricata repository and update the machine
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update

Step3)  Install Suricata using
sudo apt-get install suricata

Step4)  Now check the interface of the network in the machine, using ifconfig command.

Step5) Use that information to configure Suricata:
nano /etc/suricata/suricata.yaml
 the interface name is ens33 so the interface name in the af-packet section needs to match. 
Check for this menu 
af-packet:
- interface: enp1s0
cluster-id: 99
cluster-type: cluster_flow
defrag: yes
use-mmap: yes
tpacket-v3: yes
And change the enpls0 to your interface name 

Step6) Now update Suricata
sudo suricata-update

Step7) Now restart Suricata
sudo systemctl restart suricata

Step8) Let us check the working of suricata
curl http://testmynids.org/uid/index.html

Step9) check fast.log
sudo tail -f /var/log/suricata/fast.log

Integrating Suricata Logs to Wazuh

Step1) Using the Wazuh Dashboard, deploy agent give the wazuh machine IP in the Server address and name the agent and run the generated command in the Suricata machine.
Integrating Suricata Logs to Wazuh

Step2) Copy the generated commands and run the command in the suricata machine

Step3) Once the agent starts we can view the agent information in the wazuh dashboard.

Step4) Once the agent is successfully deployed, change the directory to /var/ossec/etc and edit ossec.conf
Add the suricata eve.json file path as shown below.

![image](https://github.com/user-attachments/assets/9b29f441-2fd0-42d8-978c-f1f26cdb3f19)

Step5) you can modify Suricata settings in the /etc/suricata/suricata.yaml to add custom rules file

Step6)  now restart the machine using
systemctl restart suricata
systemctl restart wazuh-agent
Wazuh automatically parses data from /var/log/suricata/eve.json and generates related alerts on the Wazuh dashboard.
We can check the alert using wazuh
![image](https://github.com/user-attachments/assets/584d1615-203a-447e-8ebc-870fe11d89fc)






