# esp_sniffer
An ESP sniffer can be uniquely tailored to monitor a specific Wi-Fi router by using a
BSSID (Basic Service Set Identifier) filter. While standard ESP sniffers operate in promiscuous mode to capture all nearby wireless traffic indiscriminately, a targeted sniffer is programmed to accept only packets where the BSSID matches a pre-defined MAC address.
This specialized approach offers several advantages:

Highly focused analysis: 
                    By ignoring unrelated Wi-Fi noise from neighboring networks, the sniffer provides a clean, focused stream of data about the activities on one specific network.                               This  makes it easier to track and diagnose issues without being overwhelmed by unnecessary information.    
Enhanced security and privacy: 
                    Filtering by BSSID ensures that the sniffer doesn't process or store potentially sensitive information from networks it is not intended to monitor. This is a                                more privacy-conscious method of network analysis compared to a broad, unfiltered capture.
Resource efficiency: 
                    Processing a smaller, filtered subset of packets reduces the load on the ESP32's limited memory and processing power. This makes the sniffer more stable and efficient,                      especially in busy environments.
