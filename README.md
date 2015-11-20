# scapy-tools

## dhcp_starvation

Consume all the DHCP range of IPs if the server is not properly configured.
The script is really simple, and it allows you to set some special characteristics.

	usage: dhcp_starvation.py [-h] [--iface IFACE] [--spoof-mac] [--dtimer DTIMER]
				  [--dparal DPARAL] [--hostname HOSTNAME]

	DHCP Starvation as a service

	optional arguments:
	  -h, --help           show this help message and exit
	  --iface IFACE        output interface (default:eth0)
	  --spoof-mac          spoof ethernet mac address (default:false)
	  --dtimer DTIMER      discovery run interval in seconds (default:1)
	  --dparal DPARAL      discovery parallelism (default:1)
	  --hostname HOSTNAME  fake client hostname (default:android-)


* **iface:** the network interface of the LAN (where the DHCP server runs)
* **spoof-mac:** use a random MAC Address also in ethernet frame (don't use in WiFi WPA2 Network)
* **dtimer:** discovery run interval time in seconds
* **dparal:** the amount of discovery packages to send in each interval.
* **hostname:** all fake client hostnames on requests will be composed by this name followed by 16 random HEX chars

## arp_host_ids

Try to detect ARP spoofing attacks in a smart way. WIP
