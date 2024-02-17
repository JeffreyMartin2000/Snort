# Snort
As I am going through my studies I came across IDS/IPS technology and how to read and make rules. I wanted to dive deeper in this technology on my own machines. So with that said I decided to use Snort. Snort is a free and open-source network intrusion detection and prevention system (IDS/IPS) that employs a rule-based language, incorporating anomaly, protocol, and signature inspection methods to monitor network traffic and identify potential malicious activity on IP networks.
-
Lets start with what machines I will be using. I decided to use a hypervisor(Virtualbox). Using an Ubuntu as my defending machine, and my Kali Lunux machine as my attacking. Using a bridged network configuration as well.
-
After the installation of snort on my Ubuntu machine, I need to configure it for the address range of my network.

<img width="909" alt="Making sure local network add is good" src="https://github.com/JeffreyMartin2000/Snort/assets/129632324/27025678-6aa7-41b9-9e8c-34122005cec2">


Setting the NIC on promiscuous mode for Snort is essential because it enables the NIC to capture and analyze all network traffic passing through the network interface, regardless of the destination MAC address.
With the command "sudo ip link set enp0s3 promisc on" I can do this.

<img width="605" alt="setting prmisc on for nic" src="https://github.com/JeffreyMartin2000/Snort/assets/129632324/e9b9827e-f234-4841-8b30-a9a8e429ef1b">



I needed to use a text editor to set and configure rules, as well as setup the network addresses I am protecting. I decided to use vim.

<img width="534" alt="use vim as our text editor" src="https://github.com/JeffreyMartin2000/Snort/assets/129632324/6a59825e-24a5-429a-9334-2dd3c727ee2b">

Lets identify the network address we are protecting using vim. My Ubuntu machine has an IP address of 192.168.5.10 with subnet mask of 255.255.255.0, or CIDR notation of /24.


<img width="398" alt="setup the network address you are protecting" src="https://github.com/JeffreyMartin2000/Snort/assets/129632324/d6f18722-dde2-495b-b1b0-3da5603c53ac">

Lets start with the most important activity in this lab. The Snort rules. The command "sudo vim /etc/snort/rules/local.rules" is used to edit the local rules file for the Snort intrusion detection and prevention system using the Vim text editor. 

<img width="406" alt="creating a snort rule for any pings" src="https://github.com/JeffreyMartin2000/Snort/assets/129632324/2505c4c8-d976-40dc-8806-3dc0eaa944f0">

Let's break down this Snort rule:

alert: This keyword indicates that Snort should generate an alert when the specified conditions are met.

icmp: This specifies the protocol to be matched, in this case, Internet Control Message Protocol (ICMP), commonly used for ping.

any any -> $HOME_NET any: This part defines the source and destination addresses and ports for the rule. It states that the rule should match traffic from any source IP and any source port to any destination IP within the home network ($HOME_NET) on any destination port.

(msg:"Ping Detected!";): This is the message to be logged if the rule is triggered. In this case, it's "Ping Detected!"

sid:100001: This is the Snort ID (SID), a unique identifier for the rule. It helps in referencing and managing rules.

rev:1: This is the revision number for the rule. It's used to track changes to the rule over time.

So, the rule can be read as: "Generate an alert for ICMP traffic from any source to any destination within the home network, and log a message saying 'Ping Detected!' with a unique ID of 100001 and revision 1."

Here is another rule: 

<img width="527" alt="added a snort rule to detect http port  traffic" src="https://github.com/JeffreyMartin2000/Snort/assets/129632324/a42e47f9-6d7b-4df1-b762-94b2213a9901">

This Snort rule can be broken down as follows:

alert: This keyword indicates that Snort should generate an alert when the specified conditions are met.

tcp: Specifies the protocol to be matched, in this case, Transmission Control Protocol (TCP).

any any -> $HOME_NET 80: Defines the source and destination addresses and ports for the rule. It matches TCP traffic from any source IP and any source port to the home network ($HOME_NET) on port 80 (HTTP).

(msg:"Possible HTTP Attack";): This is the message to be logged if the rule is triggered. In this case, it's "Possible HTTP Attack!"

content:"GET"; nocase;: Specifies a content match. The rule triggers if the payload of the TCP packet contains the case-insensitive string "GET". It's commonly used to detect HTTP GET requests.

sid:100002: This is the Snort ID (SID), a unique identifier for the rule.

rev:1: This is the revision number for the rule. It helps track changes to the rule over time.

So, the rule can be interpreted as: "Generate an alert for TCP traffic to port 80 within the home network where the payload contains 'GET', and log a message saying 'Possible HTTP Attack!' with a unique ID of 100002 and revision 1."

After using the 'ping' command to verify connectivity with my Kali machine, I decided to start Snort and see if I can get any alerts. I used the command:

sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf

On my Kali machine I ping the address of 192.168.5.10 to generate the alerts.

<img width="574" alt="results from ping and the command to start snort" src="https://github.com/JeffreyMartin2000/Snort/assets/129632324/0cbab008-79d9-4087-acfb-ffd5c7220397">

Looks like the rule was triggered. This was a success. In my exploration of Snort, I set up a virtual environment using VirtualBox with Ubuntu as my defending machine and Kali Linux as my attacking machine on a bridged network. After installing and configuring Snort on Ubuntu, including setting the NIC on promiscuous mode, I utilized the Vim text editor to customize rules for monitoring potential malicious activities on the network. The key focus was on understanding and implementing Snort rules, such as detecting ICMP traffic with a rule for ping and another for potential HTTP attacks. After verifying connectivity with the 'ping' command, I activated Snort and generated alerts by pinging the designated address from my Kali machine. This was a great learning experience using this widely used tool.
