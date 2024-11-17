![forensic-insight-logo](./forensic-insight.jpg)

# Forensic Insight Script

## Overview  
**Forensic Insight** is a modular, interactive script designed for system administrators, incident responders, and forensic analysts. It facilitates the collection of volatile and non-volatile data from Linux systems suspected of compromise. The script features an intuitive menu-driven interface, enabling users to generate specific reports based on their investigative needs.  

---

## Table of Contents  
- [Features](#features)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Menu Options](#menu-options)  
- [Output Structure](#output-structure)  
- [Contributing](#contributing)  
- [License](#license)  

---

## Features  
- **Interactive Menu:** Navigate a simple interface to select specific categories of information for reporting.  
- **Customizable Reports:** Generate reports only for the areas relevant to your investigation.  
- **Organized Output:** All results are saved in a structured directory, with summary and detailed sub-reports.  
- **Extendable Script:** Modular design allows for easy additions to functionality.  

### Data Categories Collected  
The script provides insights into the following areas:  
- **System Information Overview:** General system details, uptime, memory, and storage usage.  
- **Network Usage:** Active connections, open ports, DNS resolver settings, and ARP table.  
- **Processes:** Details on running processes, network activity per process, and deleted binaries.  
- **Directories:** Hidden files, world-writable directories, and recent file changes.  
- **Files and Installed Software:** Large binaries, SUID/SGID files, orphaned files, and package integrity.  
- **Users and Authentication Activity:** Login histories, password hashes, SSH keys, and cron jobs.  
- **Logs:** System logs, user activity, and application logs.  
- **Persistence Mechanisms:** Detection of scheduled tasks, modified scripts, SSH backdoors, and systemd services.  
- **Containers and Virtual Machines:** Information on Docker containers and virtual environments.  

---

## Installation  

### Prerequisites  
- A Linux-based system (Ubuntu or similar).  
- `sudo` privileges for elevated commands.  

### Steps  
1. Clone the repository:

```bash
git clone https://github.com/duarte-ferreira-santos/forensic-insight.git
cd forensic-insight
```   

2. Make the script executable:  
   ```bash
   chmod +x forensic_insight.sh
   ```  

---

## Usage  
Run the script from the command line with `sudo`:  

```bash
sudo ./forensic_insight.sh
```  

Upon execution, the script presents a menu interface to guide the user through available options. Select a category to generate a specific report or exit the tool.

---

## Menu Options  

The script presents the following menu upon execution:

```
=========================================
         Linux Forensic Toolkit          
=========================================
Choose an option by entering a number:
1. System Information
2. Network Usage
3. Processes
4. Directories
5. Files and Installed Software
6. Users and Authentication Activity
7. Logs
8. Persistence Mechanisms
9. Containers and VM Information
0. Exit
=========================================
```

### How to Use the Menu  
1. Enter the number corresponding to your desired category.  
2. The script will generate the requested report and save it in the output directory.  
3. After completing the report, you’ll be returned to the main menu.  

### Example of Execution  
1. Run the script:  
   ```bash
   sudo ./forensic_insight.sh
   ```  
2. Choose an option (e.g., `1` for "System Information").  
3. Review the report saved in the output directory.  
4. Repeat for additional reports or choose `0` to exit.  

---

## Output Structure  

The generated reports are organized as follows:  

```
├── 1_System_Info_Overview
│   ├── System-Information-Overview.txt
│   └── Sections
│       ├── Disk_Usage_and_Mounts.txt
│       ├── Hostname_Information.txt
│       └── ...
├── 2_Network_Usage
│   ├── Network-Usage-Overview.txt
│   └── Sections
│       ├── Active_Connections_and_Associated_Processes.txt
│       ├── Open_Ports_and_Listening_Services.txt
│       └── ...
...
```

---

### ⚠️ Warning  
**Sensitive Information:** The generated reports will contain system-sensitive data, including password hashes, user login details, SSH keys, and other confidential information. These outputs are saved in plain-text files, making them vulnerable to unauthorized access if not handled properly.  

**Recommendations:**  
- Store the output files in a secure, restricted-access location.  
- Delete the reports after completing your analysis if they are no longer required.  
- Use encryption or secure storage methods to protect the data if it needs to be retained.  

---
## Contributing  

We welcome contributions to improve the script!  

1. **Fork the repository** and create a new branch (`git checkout -b feature/your-feature`).  
2. **Make changes** and commit them (`git commit -am 'Add new feature'`).  
3. **Push to your branch** (`git push origin feature/your-feature`).  
4. Create a **pull request** with a description of your changes.  

---

## License  
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.  



