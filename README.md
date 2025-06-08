
<p align="center">
  <img src="assets/small.png?text=HomelabIDS" alt="HomelabIDS Logo" />
</p>

# 🚀 **HomelabIDS** - Your Personal Intrusion Detection System for the Home Lab!  

---

## 🛡️ **What is HomelabIDS?**

**HomelabIDS** is a lightweight, customizable, and powerful **Intrusion Detection System (IDS)** designed specifically for home labs and small networks. Whether you're a hobbyist, a network enthusiast, or a cybersecurity professional, HomelabIDS helps you monitor, detect, and respond to suspicious activity in your network with ease.

---

## 🌟 **Features**

### 🔍 **Network Flow Monitoring**
- Detect **new hosts** joining your network.
- Monitor **local, router, and foreign flows**.
- Identify **new outbound connections** and **high-bandwidth flows**.

### 🌍 **Geolocation and Reputation**
- Detect traffic to **banned countries**.
- Integrate with **reputation lists** to detect malicious IPs.
- Detect traffic bypassing **local DNS** or **NTP servers**.

### 📊 **Real-Time Alerts**
- Get instant alerts via **Telegram** for critical events.
- Log all detections in a centralized database for easy analysis.

### 🛠️ **Customizable Configurations**
- Fine-tune detection thresholds and approved lists.
- Enable or disable specific detection mechanisms.
- Integrate with **Pi-hole** for DNS query monitoring.

### 📊 **Integrations**
- Works with Home Assistant and Homepage.dev dashboard and potentially more
- Works with Pihole and PfSense
- Works with various reputation and geolist providers like MaxMind, IPASN, Tor list, etc

### ⚡ **Lightweight and Efficient**
- Designed to run on minimal hardware.
- Perfect for Raspberry Pi, home servers, or virtual machines.

---

## 🎯 **Why Choose HomelabIDS?**

- **Simple Setup**: Easy to install and configure.
- **Customizable**: Tailor the system to your specific needs.
- **Open Source**: Fully transparent and community-driven.
- **Perfect for Home Labs**: Built with small networks in mind.

---

## 🚀 **Get Started Today!**

Take control of your home network with **HomelabIDS**. Start monitoring, detecting, and protecting your network today!


## 📦 **Installation**

Please see docker compose example files in the docker_config_examples folder. Below is a docker compose file for the collector.

```

version: "3"
services:
  homelabids:
    network_mode: host
    container_name: homelabids
    restart: "unless-stopped"
    image: mayberry4477/homelabids:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /docker/homelabids:/database
    environment: 
      - SITE=FARM  <-- your site name
      - TZ=Asia/Tokyo <-- your time zone

  
  ```

Below is a docker compose file for the dashboard. Both containers need to be installed. 

```

version: "3"
services:
  homelabids-website:
    network_mode: host
    container_name: homelabids-website
    restart: "unless-stopped"
    image: mayberry4477/homelabids-website:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /docker/homelabids-website:/database
    environment: 
      - TZ=Asia/Tokyo  <-- your time zone
      - HOMELABIDS_API_BASE_URL=http://192.168.230.236:8044  <-- location where you installed the collector. 8044 is default port. Change the IP address. 

```

After installation navigate get to http://YOUR_IP_REPLACE:3030 .

---

## 🛠️ **Initial Configuration**

After initial installation, only the collector is running. First, you'll want to configure Netflowv5 on your PfSense Firewall (or another platform where Netflowv5 is supported). Then you'll want to go to HomelabIDS Settings and turn on the detection engine and turn on specific detections. We suggest turning on the New Host Detection to start with to start building some awareness of your local topology. 

---

## 🛠️ **Configure Netflowv5 On Your PfSense Firewall**

Configuring Netflow on PfSense is a simple two step process.

First, install the softflowd package on PfSense by going to System -> Package Manager -> Available Packages and searching for "softflowd" and installing it. 

Second, after softflowd installation go to Services -> softflowd and configure softflowd. We recommend these configuration settings:

* Enable softflowd: Enabled
* Interface: LAN
* Host: <IP address of your collector container named homelabids>
* Port: 2055 (the default collector listen port)
* Sample: 0 (setting this above 0 is only necessary for high volume sites. This will configure the firewall to only look at some packets)
* Max Flow: 8192
* Hop Limit: Unset
* Netflow nersion: 5
* Bidirectional Flow: Unchecked
* Flow Tracking Level: Full
* Flow Timestamp Precision: Seconds
* Timeout General: 60 (or the speed at which you want in detection latency. Change this only if you know what you're doing)
* Timeout other settings: Keep defaults

After this, save your settings. 

## 🛠️ **Configuration Settings**

HomelabIDS is highly configurable! Check out the Configuration Documentation for a detailed guide on how to customize the system to your needs.

## 📸 **Screenshots**

### **Dashboard**
![Landing page]({BCC535B4-5F5E-4023-B5D7-CE7DE7AEE540}.png)

### **Host View**
![Host View]({C547E506-22B3-4DB3-87A6-C175C23C660F}.png)

### **Alerts**
![Alert Listing]({821572B7-8FAC-4FC2-945C-3818026092DE}.png)

### **Flow Explorer**
![Flow Explorer]({E80E5B2B-336D-4098-9203-3E89D35667BB}.png)

### **Settings Page**
![Settings]({77E0E130-E8A7-4BEF-A63A-B711C69BA261}.png)

---

## 🤝 **Contributing**

We welcome contributions from the community! Whether it's fixing bugs, adding new features, or improving documentation, your help is appreciated. 

---

## 📜 **License**

HomelabIDS is licensed under the MIT License. Feel free to use, modify, and distribute it as you see fit.

---

## 💬 **Join the Community**

- **Reddit**: (https://www.reddit.com/r/homelabids/([r/homelabids]

---

## ⭐ **Support the Project**

If you find HomelabIDS useful, please consider giving us a ⭐ on GitHub! It helps others discover the project and motivates us to keep improving.

---



# **HomelabIDS Configuration Documentation**

## **Overview**
This document provides an overview of the configuration settings used in HomelabIDS. These settings control various detection mechanisms, integrations, and system processes. The configurations are stored in the `configuration` table of the database and can be modified to customize the behavior of the system.

---

## **Configuration Settings**

### **1. Detection Settings**
These settings enable or disable specific detection mechanisms.

| **Key**                          | **Description**                                                                                     | **Default Value** |
|-----------------------------------|-----------------------------------------------------------------------------------------------------|-------------------|
| `NewHostsDetection`               | Enables detection of new hosts on the network.                                                     | `0`               |
| `LocalFlowsDetection`             | Enables detection of local network flows.                                                          | `0`               |
| `RouterFlowsDetection`            | Enables detection of flows originating from or destined to the router.                             | `0`               |
| `ForeignFlowsDetection`           | Enables detection of foreign (non-local) network flows.                                            | `0`               |
| `NewOutboundDetection`            | Enables detection of new outbound connections.                                                     | `0`               |
| `GeolocationFlowsDetection`       | Enables detection of flows based on geolocation data.                                              | `0`               |
| `BypassLocalDnsDetection`         | Detects flows bypassing local DNS servers.                                                         | `0`               |
| `IncorrectAuthoritativeDnsDetection` | Detects incorrect authoritative DNS servers.                                                     | `0`               |
| `BypassLocalNtpDetection`         | Detects flows bypassing local NTP servers.                                                         | `0`               |
| `IncorrectNtpStratrumDetection`   | Detects incorrect NTP stratum levels.                                                              | `0`               |

---

### **2. Approved Lists**
These settings define approved servers or networks for specific purposes.

| **Key**                              | **Description**                                                                 | **Default Value** |
|--------------------------------------|---------------------------------------------------------------------------------|-------------------|
| `ApprovedLocalNtpServersList`        | List of approved local NTP servers.                                             | `''`              |
| `ApprovedLocalDnsServersList`        | List of approved local DNS servers.                                             | `''`              |
| `ApprovedAuthoritativeDnsServersList`| List of approved authoritative DNS servers.                                     | `''`              |
| `ApprovedNtpStratumServersList`      | List of approved NTP stratum servers.                                           | `''`              |
| `ApprovedVpnServersList`             | List of approved VPN servers.                                                   | `''`              |
| `ApprovedHighRiskDestinations`       | List of approved high-risk destinations.                                        | `''`              |

---

### **3. Geolocation and Reputation**
These settings control geolocation and reputation-based detections.

| **Key**                  | **Description**                                                                 | **Default Value** |
|---------------------------|---------------------------------------------------------------------------------|-------------------|
| `BannedCountryList`       | List of countries to ban traffic from.                                          | `China,North Korea,Iran,Russia,Ukraine,...` |
| `ReputationUrl`           | URL to fetch reputation lists.                                                  | `https://iplists.firehol.org/files/firehol_level1.netset` |
| `ReputationListRemove`    | List of networks to exclude from reputation lists.                              | `192.168.0.0/16,0.0.0.0/8,224.0.0.0/3`    |
| `ReputationListDetection` | Enables detection based on reputation lists.                                    | `0`               |

---

### **4. Network and Flow Settings**
These settings control network-related configurations and flow processing.

| **Key**                  | **Description**                                                                 | **Default Value** |
|---------------------------|---------------------------------------------------------------------------------|-------------------|
| `LocalNetworks`           | List of local networks.                                                         | `''`              |
| `RouterIpAddresses`       | List of router IP addresses.                                                    | `''`              |
| `ProcessingInterval`      | Interval (in seconds) for processing flows.                                     | `60`              |
| `RemoveBroadcastFlows`    | Removes broadcast flows from processing.                                        | `1`               |
| `RemoveMulticastFlows`    | Removes multicast flows from processing.                                        | `1`               |
| `MaxUniqueDestinations`   | Maximum number of unique destinations allowed per source.                       | `30`              |
| `MaxPortsPerDestination`  | Maximum number of ports allowed per destination.                                | `15`              |
| `HighRiskPorts`           | List of high-risk ports to monitor.                                             | `135,137,138,139,445,25,587,22,23,3389`   |

---

### **5. Telegram Integration**
These settings configure Telegram bot integration for sending alerts.

| **Key**                  | **Description**                                                                 | **Default Value** |
|---------------------------|---------------------------------------------------------------------------------|-------------------|
| `TelegramBotToken`        | Token for the Telegram bot.                                                     | `''`              |
| `TelegramChatId`          | Chat ID for sending Telegram messages.                                          | `''`              |

---

### **6. Pi-hole Integration**
These settings configure integration with Pi-hole for DNS query monitoring.

| **Key**                  | **Description**                                                                 | **Default Value** |
|---------------------------|---------------------------------------------------------------------------------|-------------------|
| `PiholeUrl`               | URL of the Pi-hole API.                                                         | `http://192.168.49.80/api` |
| `PiholeApiKey`            | API key for accessing the Pi-hole API.                                          | `''`              |
| `StorePiHoleDnsQueryHistory` | Enables storing Pi-hole DNS query history.                                   | `0`               |

---

### **7. Tor Node Detection**
These settings configure detection of Tor node traffic.

| **Key**                  | **Description**                                                                 | **Default Value** |
|---------------------------|---------------------------------------------------------------------------------|-------------------|
| `TorFlowDetection`        | Enables detection of Tor node traffic.                                          | `0`               |
| `TorNodesUrl`             | URL to fetch the list of Tor nodes.                                             | `https://www.dan.me.uk/torlist/?full` |

---

### **8. High Bandwidth Flow Detection**
These settings configure detection of high-bandwidth flows.

| **Key**                  | **Description**                                                                 | **Default Value** |
|---------------------------|---------------------------------------------------------------------------------|-------------------|
| `HighBandwidthFlowDetection` | Enables detection of high-bandwidth flows.                                  | `0`               |
| `MaxPackets`              | Maximum number of packets allowed per flow.                                     | `30000`           |
| `MaxBytes`                | Maximum number of bytes allowed per flow.                                       | `3000000`         |

---

### **9. Error Reporting**
These settings control error reporting and logging.

| **Key**                  | **Description**                                                                 | **Default Value** |
|---------------------------|---------------------------------------------------------------------------------|-------------------|
| `SendErrorsToCloudApi`    | Enables sending error reports to the cloud API.                                 | `0`               |

---

### **10. Miscellaneous Settings**
These settings control various other aspects of the system.

| **Key**                  | **Description**                                                                 | **Default Value** |
|---------------------------|---------------------------------------------------------------------------------|-------------------|
| `ScheduleProcessor`       | Enables scheduling of the processor.                                            | `0`               |
| `StartCollector`          | Enables starting the collector process.                                         | `1`               |
| `CleanNewFlows`           | Enables cleaning of new flows.                                                  | `0`               |
| `IntegrationFetchInterval`| Interval (in seconds) for fetching integrations.                                | `3660`            |
| `DiscoveryReverseDns`     | Enables reverse DNS discovery.                                                  | `0`               |
| `DiscoveryPiholeDhcp`     | Enables Pi-hole DHCP discovery.                                                 | `0`               |
| `EnableLocalDiscoveryProcess` | Enables the local discovery process.                                        | `0`               |
| `DiscoveryProcessRunInterval` | Interval (in seconds) for running the discovery process.                    | `60`              |

---

