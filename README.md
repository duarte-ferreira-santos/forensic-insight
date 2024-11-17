![forensic-insight-logo](./forensic-insight.jpg)

# Forensic Insight Script

## Overview  
**Forensic Insight** is a comprehensive, modular script designed for system administrators, incident responders, and forensic analysts. It automates the collection of both volatile and non-volatile data from Linux systems suspected of compromise, providing thorough analysis with minimal manual effort. The script outputs organized reports, including both high-level summaries and detailed data, facilitating rapid decision-making during security investigations.

---

## Table of Contents  
- [Features](#features)  
- [Installation](#installation)  
- [Usage](#usage)  
- [How It Works](#how-it-works)  
- [Output Structure](#output-structure)  
- [Contributing](#contributing)  
- [License](#license)  

---

## Features  
The **Forensic Insight** script provides an automated means of gathering critical system information, organized into the following categories:

- **System Information Overview:** System details (OS, kernel, uptime, etc.), logged-in users, disk usage, routing table, and password hashes.
- **Network Usage:** Active network connections, open ports, ARP table, DNS settings, and interfaces.
- **Process Information:** Running processes, network activity, deleted binaries, and suspicious directories.
- **Directory Information:** Commonly targeted directories, world-writable paths, hidden directories, and recently modified files.
- **Files and Programs:** Scans for large binaries, orphaned files, SUID/SGID files, and checks package integrity.
- **Users and Authentication Activity:** Password hashes, authentication logs, SSH keys, scheduled tasks, and login histories.
- **Log Information:** System, network, and application logs, including metadata and user activity.
- **Persistence Mechanisms:** Detection of persistent malware, modified scripts, scheduled tasks, SSH persistence, and systemd services.
- **Containers and Virtual Machines:** Information about Docker containers, images, and virtual machines.

---

## Installation  

### Prerequisites  
Before using the script, ensure that you have the following installed:  
- A Linux-based system (Ubuntu or similar is recommended).  
- `sudo` access to run commands requiring elevated privileges.

### Steps  
1. **Clone the repository:**  
   Clone the repository to your local machine:
   ```bash
   git clone https://github.com/duarte-ferreira-santos/forensic-insight.git
   cd forensic-insight
   ```

2. **Make the script executable:**  
   Ensure the script has execute permissions:
   ```bash
   chmod +x forensic_insight.sh
   ```

---

## Usage  
Once installed, you can run the script by executing the following command with `sudo` privileges:

```bash
sudo ./forensic_insight.sh
```

The script will generate detailed reports on your system’s current state and save them in the output directory.

### Example of Execution:  
```bash
sudo ./forensic_insight.sh
```

After running the script, the data will be organized into a directory structure containing the main report and individual text files for each category.

---

## How It Works  

The **Forensic Insight** script executes a series of predefined Linux commands to collect data, perform checks, and generate reports. Here’s how it works in a nutshell:

1. **Gathering Data:** The script runs system commands to gather relevant data across multiple categories such as system information, network activity, and process data.
2. **Generating Reports:** Data is compiled into both an overview file (with summarized findings) and detailed sub-sections (with specific data points).
3. **Output:** The script creates organized directories and files, allowing for easy review and analysis of the collected data.

### Example:  
- **Persistence Mechanisms Module:**  
  - **Overview File:** Lists all persistence tactics detected.  
  - **Sub-sections:**  
    - **Webshell Detection:** Checks for modified files in `/var/www/html`.
    - **Cron Jobs:** Lists system and user-specific cron tasks.
    - **Systemd Services:** Identifies enabled and custom systemd services.
    - **SSH Configuration:** Inspects SSH daemon settings and user files.

---

## Output Structure  

The output is organized into the following structure:

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

Each section contains both an overview of the findings and detailed data files for in-depth analysis.

---

## Contributing  

We welcome contributions to improve the script! Here’s how you can help:  

1. **Fork the repository** and create your branch (`git checkout -b feature/your-feature`).
2. **Make changes** and commit them (`git commit -am 'Add new feature'`).
3. **Push to your branch** (`git push origin feature/your-feature`).
4. Create a **pull request** with a description of the changes.

Please make sure to write clear and concise commit messages, and document your changes thoroughly.

---

## License  
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.


