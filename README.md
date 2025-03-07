# SOC Automation Integration with Wazuh, TheHive, and Shuffle

This project demonstrates the integration of **Wazuh**, **TheHive**, and **Shuffle** to automate incident detection, response, and case management within a Security Operations Center (SOC). By leveraging Wazuh for log management and detection, TheHive for case management, and Shuffle for automating workflows, this solution reduces manual intervention and improves incident response times. The goal is to streamline threat detection and response, enabling security teams to respond faster and more effectively to potential security breaches.

## Key Features

- **Wazuh**: Provides security monitoring by collecting and analyzing telemetry data from endpoints and network devices. It uses rules to detect suspicious activities, such as malicious tool executions and network anomalies.
- **TheHive**: Manages alerts from Wazuh and organizes them into cases for further investigation. TheHive helps prioritize and assign incidents to security analysts, improving incident management efficiency.
- **Shuffle**: Orchestrates the automated response by handling alerts, triggering actions (such as sending email notifications and blocking malicious IPs), and integrating with external services like VirusTotal for malware analysis.
- **Automated Email Notifications**: Sends email alerts to security analysts whenever a high-priority alert is triggered, ensuring timely awareness of security incidents.
- **IP Blocking**: Automatically blocks malicious IPs identified by Wazuh, preventing further network access and mitigating the risk of compromise.

## Technologies Used:
- **Wazuh**: For security monitoring, threat detection, and log analysis.
- **TheHive**: For case management and alert tracking.
- **Shuffle**: For automating workflows and responses to security events.
- **VirusTotal**: For analyzing suspicious files and determining their risk level.
- **Email**: For alerting security teams via email.
- **Webhooks**: For integrating and automating the flow of data between the different platforms.

## Project Walkthrough

### 1. **Project Overview Diagram**

This diagram illustrates the entire end-to-end workflow of the SOC automation project, showcasing how Wazuh, TheHive, and Shuffle work together to automate detection and response.

![Project Overview Diagram](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/SOC%20Automation%20Project.drawio.png?raw=true)

---

### 2. **Deploying Servers on Vultr**

The **Wazuh Server** and **TheHive Server** are deployed on Vultr to handle detection, event analysis, and case management.

![Vultr Server Deployment](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/VultrServers.jpeg?raw=true)

---

### 3. **Installing and Configuring Wazuh**

The Wazuh manager is installed and configured to ingest telemetry data, including logs from endpoints like Windows and Linux machines. The configuration enables real-time detection and analysis of suspicious activities.

![Wazuh Install](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/WazuhInstall.jpeg?raw=true)

---

### 4. **Monitoring Endpoint Activity with Wazuh**

Once the agents are connected to Wazuh, they begin monitoring system activities. Wazuh processes logs and detects suspicious events, such as the execution of malicious tools like Mimikatz.

![Mimikatz Logs](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/MimikatzLogs.jpeg?raw=true)  
![Mimikatz Wazuh](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/MimikatzWazuh.jpeg?raw=true)  
![Wazuh Endpoint](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/WazuhEndpoint.jpeg?raw=true)

---

### 5. **Creating a Custom Detection Rule in Wazuh**

A custom detection rule is created in Wazuh to identify Mimikatz execution, a tool often used for credential dumping by attackers. This rule enhances the system's ability to detect specific security threats in real time.

![Custom Rule](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/CustomRule.jpeg?raw=true)

---

### 6. **Detecting Mimikatz Usage**

Once the Mimikatz rule is set up, Wazuh detects Mimikatz activity on monitored endpoints. The alert is triggered based on the execution of the Mimikatz tool.

![Mimikatz Detection](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/MimikatzDetection.jpeg?raw=true)

---

### 7. **Integrating Wazuh with Shuffle via Webhooks**

Wazuh alerts are sent to **Shuffle** using webhooks, based on specific **rule IDs**. This integration triggers automated workflows in Shuffle, enabling actions like IP blocking and email notifications.

![Windows Integration](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/WindowsIntegration.jpeg?raw=true)

---

### 8. **Hash Detection with VirusTotal Integration**

Wazuh sends suspicious file hashes to VirusTotal for reputation checks, cross-referencing the hash with VirusTotal's database of known threats.

![SHA256 Hash](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/SHA256.jpeg?raw=true)  
![VirusTotal Analysis](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/SHAtoVirustotal.jpeg?raw=true)  
![VirusTotal Results](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/VirusTotalResults.jpeg?raw=true)

---

### 9. **Investigating Alerts in TheHive**

The alerts from Wazuh are now available in TheHive, where security analysts can investigate these alerts, view their details, and assess the severity. TheHive streamlines case management and tracking.

![Hive Mimikatz Detected](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/HiveMimikatzDetected.jpeg?raw=true)  
![Hive Results](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/HiveResults.jpeg?raw=true)

---

### 10. **Email Notifications for SOC Analysts**

Email alerts are automatically sent to the SOC analyst whenever a high-priority event is detected. These emails provide the analyst with all the necessary details to investigate and respond to the threat.

![Email Setup](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/EmailSetup.jpeg?raw=true)  
![Email Sent](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/EmailSent.jpeg?raw=true)  
![Email Received](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/EmailRecieved.jpeg?raw=true)

---

### 11. **Linux Endpoint Integration**

Linux endpoints are integrated into the system to provide comprehensive monitoring across all devices in the environment.

![Linux Endpoint Added](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/LinuxEndpointadded.jpeg?raw=true)  
![Linux Rule Integrations](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/LinuxRuleIntegrations.jpeg?raw=true)  
![Linux Alert](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/LinuxAlert.jpeg?raw=true)

---

### 12. **Automating Responses with Shuffle**

After Wazuh detects an alert, **Shuffle** automates the response process. The SOC analyst receives an email notification with a link to approve or deny actions.

![User Input Email](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/UserInputEmail.jpeg?raw=true)  
![User Input](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/UserInput.jpeg?raw=true)

---

### 13. **Blocking IP Addresses Automatically**

When the analyst approves the blocking action, **Shuffle** automatically blocks the malicious IP, preventing further malicious traffic.

![IP Blocked](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/IPblocked.jpeg?raw=true)

---

### 14. **Full Workflow Execution**

The entire automated workflow executes seamlessly, from detection to investigation, alerting, and response actions such as IP blocking and email notifications. Shuffle orchestrates the entire process, ensuring rapid incident response.

![Full Workflow](https://github.com/sufani/Security-Operations-Automation-with-Wazuh-TheHive-and-Shuffle/blob/main/images/FinalWorkflow.jpeg?raw=true)
