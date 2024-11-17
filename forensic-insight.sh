#!/bin/bash

# Ensure the script is run as root
check_root_permission() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] This script must be run as root."
        exit 1
    else
        echo "[INFO] Script running with root privileges."
    fi
}

# Configure paths and directories
config() {
    base_dir="$(pwd)"
    report_dir="${base_dir}/forensic_output"
    mkdir -p "${report_dir}"
    error_log="${report_dir}/error_log.txt"
    touch "$error_log"
    
    # Function directory names
    functions=("1_System_Info_Overview" "2_Network_Usage" "3_Process_Information" "4_Directory_Information" 
               "5_Files_and_Programs" "6_Users_And_Authentication_Activity" 
               "7_Log_Information" "8_Persistence_Signs" "9_Containers_And_VM_Info")
    for func in "${functions[@]}"; do
        func_dir="${report_dir}/${func}"
        mkdir -p "${func_dir}/Sections"
    done
}

# Logging functions
log_info() {
    local message="$1"
    printf "[INFO] %s\n" "${message}" | tee -a "${error_log}" >/dev/null
}

log_warning() {
    local message="$1"
    printf "[WARNING] %s\n" "${message}" | tee -a "${error_log}" >&2
}

log_error() {
    local message="$1"
    printf "[ERROR] %s\n" "${message}" | tee -a "${error_log}" >&2
}

# Cleanup functions to remove old reports
cleanup() {
    [[ -f "${error_log}" ]] && rm -f "${error_log}"
    for func in "${functions[@]}"; do
        local dir="${report_dir}/${func}"
        [[ -d "${dir}" ]] && rm -rf "${dir}"
    done
}
trap cleanup EXIT

# Finalize script
finish() {
    local result=$?
    if [[ $result -ne 0 ]]; then
        log_error "Script terminated with errors. Check error log for details."
    else
        log_info "Script completed successfully."
    fi
    exit "${result}"
}
trap finish EXIT ERR

# Show progress while collecting data
show_progress() {
    local spinner="|/-\\"
    local delay=0.1
    local pid="$1"
    while kill -0 "$pid" 2>/dev/null; do
        for i in $(seq 0 3); do
            printf "\r[%c] Collecting data..." "${spinner:$i:1}"
            sleep $delay
        done
    done
    printf "\r[✔] Data collection complete!         \n"
}

# Run a function in the background with progress indication
run_with_progress() {
    local func="$1"
    $func &  # Execute function in background
    local pid=$!
    show_progress "$pid"
    wait "$pid"
}

# Append section data to report files
append_section() {
    local section_name="$1"
    local section_desc="$2"
    local command="$3"
    local func_folder="$4"
    local main_func_report_file="$5"
    
    local clean_section_name="${section_name// /_}"
    clean_section_name="${clean_section_name//[^a-zA-Z0-9_]/}"
    
    local sections_folder="${func_folder}/Sections"
    mkdir -p "${sections_folder}"
    local section_file="${sections_folder}/${clean_section_name}.txt"
    
    # Append to main report and create section-specific file
    {
        echo "-----------------------------------------"
        echo "Section: ${section_name}"
        echo "Description: ${section_desc}"
        echo "-----------------------------------------"
    } >> "${main_func_report_file}"
    
    {
        echo "-----------------------------------------"
        echo "Section: ${section_name}"
        echo "Description: ${section_desc}"
        echo "-----------------------------------------"
    } > "${section_file}"
    
    if ! eval "${command}" 2>&1 | tee -a "${main_func_report_file}" >> "${section_file}"; then
        log_error "Error executing command: ${command}"
    fi
}

# Main execution starts here
check_root_permission
config

# Function 1: Collect system information and save it to structured output files
system_info() {    
    local func_folder="${report_dir}/1_System_Info_Overview"
    local main_func_report_file="${func_folder}/System-Information-Overview.txt"

    # Clear folder contents if it exists, or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi
    
    # Create the main report file with a header
    {
        echo "========================================="
        echo "           SYSTEM INFO OVERVIEW          "
        echo "           $(date)                      "
        echo "========================================="
        echo "Overview sections are listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # SYSTEM OVERVIEW

    # Append System Info sections
    append_section "Operating System and Kernel Information" \
                   "OS and Kernel details." \
                   "uname -a" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "OS Release Details" \
                   "Distribution version details." \
                   "cat /etc/*-release" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Hostname Information" \
                   "System hostname." \
                   "hostname; cat /etc/hostname" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Machine ID and OS Installation Date" \
                   "Unique machine ID and installation date." \
                   "cat /etc/machine-id; stat /etc/machine-id | grep 'Birth'; ls -ld /var/log/installer" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Timezone Information" \
                   "System timezone." \
                   "cat /etc/timezone" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "System Uptime and Load Average" \
                   "System uptime and load average." \
                   "uptime" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # NETWORK OVERVIEW
    append_section "Network Interfaces" \
                   "List of network interfaces." \
                   "$(command -v ip &>/dev/null && echo 'ip a' || echo 'ifconfig -a')" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Routing Table" \
                   "Network routing table." \
                   "netstat -rn; route" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # DISK AND MEMORY USAGE
    append_section "Disk Usage and Mounts" \
                   "Disk usage and mounted filesystems." \
                   "df; mount" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Memory and Swap Usage" \
                   "Memory and swap usage details." \
                   "free -h" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # USER AND AUTHENTICATION INFORMATION
    append_section "Logged-in Users" \
                   "List of logged-in users." \
                   "w" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Recent Logins" \
                   "Check login attempts." \
                   "last -Faiwx" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "User Accounts" \
                   "System user accounts." \
                   "cat /etc/passwd" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Password Hashes" \
                   "Password hashes for accounts." \
                   "cat /etc/shadow" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # SECURITY AND SYSTEM LOGS
    append_section "System Logs" \
                   "Recent system logs." \
                   "tail -n 50 /var/log/syslog" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Loaded Kernel Modules" \
                   "Lists loaded kernel modules." \
                   "lsmod" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # Summary for the main function report
    {
        echo "========================================="
        echo "  Summary of Collected Sections in System Info"
        echo "========================================="
        echo "All sections have been successfully collected and saved."
        echo ""
        echo "- **System Information Overview Report**: ${main_func_report_file}"
        echo "  Contains all system information sections for an overview."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path so it can be used in the menu
    echo "${main_func_report_file}"
        # Prints the report file
    cat ${main_func_report_file}
}


# Function 2: Collect Network Usage Information for Forensic Analysis
network_usage() {
    local func_folder="${report_dir}/2_Network_Usage"
    local main_func_report_file="${func_folder}/Network-Usage-Overview.txt"

    # Clear folder contents if it exists, or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi

    # Create the main report file with a header
    {
        echo "========================================="
        echo "          NETWORK USAGE OVERVIEW         "
        echo "          $(date)                        "
        echo "========================================="
        echo "Overview sections are listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # Collect network information and append it to the main report file, and print to terminal
    append_section "Network Interface Configuration" \
                   "Displays all network interfaces. Look for interfaces in promiscuous mode (PROMISC), which may indicate packet sniffing." \
                   "$(command -v ip &>/dev/null && echo 'ip link' || echo 'ifconfig -a')" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "IP Address Information and Routing Table" \
                   "Shows IP addresses and routing table. Look for unusual routes that might indicate data exfiltration." \
                   "ip addr; netstat -rn; route -n" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Open Ports and Listening Services" \
                   "Shows open ports and services listening on these ports. Unexpected services or high-numbered ports can indicate backdoors or rogue services." \
                   "netstat -tuln; ss -tuln" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Active Connections and Associated Processes" \
                   "Lists all active connections with details on associated processes. Helps in identifying suspicious or unexpected connections." \
                   "lsof -i" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "ARP Table Entries" \
                   "Shows ARP table entries, mapping IPs to MAC addresses. Look for unknown IP-MAC mappings which may indicate rogue devices on the network." \
                   "arp -a" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "DNS Resolver Configuration" \
                   "Checks DNS resolver configuration. Unexpected nameservers may indicate DNS hijacking." \
                   "systemctl is-active --quiet systemd-resolved && echo 'systemd-resolved is running.' || echo 'systemd-resolved is not running.'; resolvectl status; resolvectl dnssec" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    append_section "Content of /etc/resolv.conf" \
                   "Check the /etc/resolv.conf file for DNS configuration." \
                   "cat /etc/resolv.conf" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # Append the summary explicitly at the end of the data collection
    {
        echo "========================================="
        echo "  Summary of Collected Sections in Network Usage"
        echo "========================================="
        echo "All sections have been successfully collected and saved."
        echo ""
        echo "- **Network Usage Report**: ${main_func_report_file}"
        echo "  Contains all network-related information sections for an overview."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path so it can be used in the menu
    echo "${main_func_report_file}"
    # Prints the report file
    cat ${main_func_report_file}
}

# Function 3: Collect Process Information for Forensic Analysis
process_information() {
    local func_folder="${report_dir}/3_Process_Information"
    local main_func_report_file="${func_folder}/Process-Information-Overview.txt"

    # Clear folder contents if it exists, or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi

    # Create the main report file with header
    {
        echo "========================================="
        echo "        PROCESS INFORMATION OVERVIEW     "
        echo "          $(date)                        "
        echo "========================================="
        echo "Overview sections are listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # 1. Overview of Running Processes
    append_section "Overview of Running Processes" \
                   "Lists all running processes. Focus on processes with high CPU or memory usage, as well as unfamiliar or suspicious ones with root (UID 0) privileges." \
                   "ps aux --sort=-%cpu,-%mem" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 2. System Load and Resource Usage
    append_section "System Load and Resource Usage" \
                   "Displays system load averages and memory usage. High load averages can indicate heavy process activity." \
                   "uptime" \
                   "${func_folder}" \
                   "${main_func_report_file}"
    append_section "" \
                   "Displays system memory usage." \
                   "free -h" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 3. Process Tree Structure
    append_section "Process Tree Structure" \
                   "Displays a process tree. Look for processes with unusual parents or unexpected children." \
                   "ps auxwf" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 4. Active Network Connections for Each Process
    append_section "Active Network Connections for Each Process" \
                   "Lists active network connections with associated processes. Unexpected connections might indicate suspicious activity." \
                   "netstat -plant" \
                   "${func_folder}" \
                   "${main_func_report_file}"
    append_section "" \
                   "Displays listening network ports." \
                   "ss -tuln" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 5. Details of Deleted Binaries Still Running
    append_section "Deleted Binaries Still Running" \
                   "Shows any processes running deleted binaries. This can suggest malware trying to avoid detection." \
                   "ls -alR /proc/*/exe 2>/dev/null | grep deleted" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 6. Process Details by PID
    append_section "Process Details by PID" \
                   "Collects command name, environment, and working directory information for each process. Useful for deeper analysis of suspicious processes." \
                   "for pid in \$(ps -e -o pid | tail -n +2); do echo '### Process ID: \$pid'; strings /proc/\$pid/comm 2>/dev/null; strings /proc/\$pid/cmdline 2>/dev/null; ls -al /proc/\$pid/exe 2>/dev/null; ls -al /proc/\$pid/cwd 2>/dev/null; done" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 7. Check for Processes Running from Suspicious Directories
    append_section "Processes Running from Suspicious Directories (/tmp, /dev)" \
                   "Identifies any processes with working directories in /tmp or /dev, often used for hiding malicious processes." \
                   "ls -alR /proc/*/cwd 2>/dev/null | grep -E 'tmp|dev'" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # Append the summary explicitly at the end of the data collection
    {
        echo "========================================="
        echo "  Summary of Collected Sections in Process Information"
        echo "========================================="
        echo "All sections have been successfully collected and saved."
        echo ""
        echo "- **Process Information Report**: ${main_func_report_file}"
        echo "  Contains all process-related information sections for an overview."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path and print it to the terminal
    echo "${main_func_report_file}"
    cat "${main_func_report_file}"
}

# Function 4: Collect Directory Information for Forensic Analysis
directory_information() {
    local func_folder="${report_dir}/4_Directory_Information"
    local main_func_report_file="${func_folder}/Directory-Information-Overview.txt"

    # Clear folder contents if it exists, or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi

    # Create the main report file with header
    {
        echo "========================================="
        echo "        DIRECTORY INFORMATION OVERVIEW  "
        echo "          $(date)                        "
        echo "========================================="
        echo "Overview sections are listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # 1. Commonly Targeted Directories
    append_section "Commonly Targeted Directories" \
                   "Listing /tmp, /var/tmp, /dev/shm, /var/run, /var/spool, and User Home Directories. These are often targeted for malicious activity." \
                   "for dir in /tmp /var/tmp /dev/shm /var/run /var/spool /home/*; do echo 'Directory: \$dir'; ls -lap \"\$dir\"; done" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 2. Search for Hidden Directories
    append_section "Hidden Directories" \
                   "Finds all hidden directories (directories beginning with a dot). These may hide malicious files or scripts." \
                   "find / -type d -name \".*\"" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 3. Look for Recently Modified Files in Targeted Directories
    append_section "Recently Modified Files in Common Directories" \
                   "Shows files modified in the last 7 days in commonly targeted directories. Unexpected modifications may suggest tampering." \
                   "find /tmp /var/tmp /dev/shm /var/run /var/spool /home/* -type f -mtime -7" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 4. Check for World-Writable Directories
    append_section "World-Writable Directories" \
                   "Identifies world-writable directories, which can be exploited to store unauthorized files." \
                   "find / -type d -perm -0002 -exec ls -ld {} \;" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 5. Suspicious Executable Files in Temporary Directories
    append_section "Suspicious Executable Files in Temporary Directories" \
                   "Lists executable files in temporary directories like /tmp and /var/tmp, commonly used to hide malicious executables." \
                   "find /tmp /var/tmp /dev/shm -type f -executable" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 6. Configuration Files in /etc Directory
    append_section "Configuration Files in /etc Directory" \
                   "Lists key configuration files that are often targeted for manipulation by attackers." \
                   "ls -lap /etc/" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # Append the summary explicitly at the end of the data collection
    {
        echo "========================================="
        echo "  Summary of Collected Sections in Directory Information"
        echo "========================================="
        echo "All sections have been successfully collected and saved."
        echo ""
        echo "- **Directory Information Report**: ${main_func_report_file}"
        echo "  Contains all directory-related information sections for an overview."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path and print it to the terminal
    echo "${main_func_report_file}"
    cat "${main_func_report_file}"
}

# Function 5: Collect File and Installed Program Information for Forensic Analysis
files_and_installed_programs() {
    local func_folder="${report_dir}/5_Files_and_Programs"
    local main_func_report_file="${func_folder}/Files-and-Programs-Overview.txt"

    # Clear folder contents if it exists, or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi

    # Create the main report file with header
    {
        echo "========================================="
        echo "       FILES AND INSTALLED PROGRAM INFO  "
        echo "          $(date)                        "
        echo "========================================="
        echo "Overview sections are listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # 1. Search for Suspiciously Named Files (Dot/Space Obfuscation)
    append_section "Files with Dot and Space Obfuscation" \
                   "Finds files with names containing obfuscations like dots or spaces, often used to hide malicious files." \
                   "find / -type f \( -name \" \" -o -name \".. \" -o -name \". \" -o -name \"...\" \) -print" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 2. Suspicious Large Executable Files (>10MB)
    append_section "Large Executable Files (>10MB)" \
                   "Finds large executable files (greater than 10MB), which could potentially be suspicious programs." \
                   "find / -type f -executable -size +10000k -print" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 3. Files with SetUID/SetGID Permissions
    append_section "SUID/SGID Files Owned by Root" \
                   "Finds SetUID/SetGID files owned by root. These could be used to escalate privileges." \
                   "find / -user root -perm -4000 -print" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 4. Immutable Files and Directories
    append_section "Immutable Files" \
                   "Lists immutable files and directories that cannot be modified or deleted, potentially used to protect malicious files." \
                   "lsattr / -R 2>/dev/null | grep \"\\----i\"" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 5. Files with Missing User/Group Ownership
    append_section "Files with No User/Group" \
                   "Identifies files without valid user/group ownership. This might indicate tampering." \
                   "find / \( -nouser -o -nogroup \) -exec ls -lg {} \;" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 6. Executable Files in Temporary Directories
    append_section "Executable Files in Temporary Directories" \
                   "Lists executable files found in temporary directories like /tmp and /var/tmp, commonly used to hide malware." \
                   "find /tmp /var/tmp /dev/shm -type f -executable" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 7. Unlinked Files in Use (Orphaned)
    append_section "Unlinked Files in Use (Orphaned)" \
                   "Identifies unlinked files still in use by processes. These could be remnants of deleted malicious files." \
                   "lsof +L1" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 8. Package Verification (RPM and Debsums)
    append_section "Package Verification" \
                   "Checks the integrity of installed packages using RPM or Debsums verification." \
                   "if command -v rpm &> /dev/null; then rpm -Va | grep '^..5'; fi" \
                   "${func_folder}" \
                   "${main_func_report_file}"
    append_section "" \
                   "Debsums Verification" \
                   "if command -v debsums &> /dev/null; then debsums -c; fi" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 9. APT and DPKG Installation History
    append_section "APT Package Installation History" \
                   "Shows APT package installation history, including commandline usage." \
                   "cat /var/log/apt/history.log | grep \"Commandline\"" \
                   "${func_folder}" \
                   "${main_func_report_file}"
    append_section "DPKG Package Status" \
                   "Displays installed package status using DPKG logs." \
                   "cat /var/log/dpkg.log | grep installed" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # Append the summary explicitly at the end of the data collection
    {
        echo "========================================="
        echo "  Summary of Collected Sections in Files and Programs"
        echo "========================================="
        echo "All sections have been successfully collected and saved."
        echo ""
        echo "- **Files and Installed Programs Report**: ${main_func_report_file}"
        echo "  Contains all file and program-related information sections for an overview."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path and print it to the terminal
    echo "${main_func_report_file}"
    cat "${main_func_report_file}"
}

# Function 6: Gather and Format User and Authentication Information for Forensic Analysis
users_and_authentication_activity() {
    local func_folder="${report_dir}/6_Users_And_Authentication_Activity"
    local main_func_report_file="${func_folder}/User_and_Auth_Analysis.txt"

    # Clear folder contents if it exists, or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi

    # Create the main report file with header
    {
        echo "========================================="
        echo "      USER & AUTHENTICATION ANALYSIS     "
        echo "          $(date)                        "
        echo "========================================="
        echo "Overview sections are listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # 1. Identify Potentially Active User Accounts
    append_section "Potentially Active User Accounts" \
                   "Lists users with common shell access (bash, sh, dash) to identify interactive accounts." \
                   "grep -E '/(bash|sh|dash)$' /etc/passwd" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 2. Sort User Accounts by UID for Anomalies
    append_section "User Accounts Sorted by UID" \
                   "Sorting by UID can reveal unusual accounts, especially those with UID=0 (root-level privileges)." \
                   "sort -nk3 -t: /etc/passwd && grep ':0:' /etc/passwd" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 3. Find Files Owned by Non-Existent Users
    append_section "Orphaned Files (Non-Existent User Ownership)" \
                   "Finds files with no associated user, potentially indicating attacker-created accounts now removed." \
                   "find / -nouser -print 2>/dev/null" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 4. Extract Password Hashes (for further analysis)
    append_section "Extracted Password Hashes from /etc/shadow" \
                   "Extracts password hashes for hash analysis (requires root permissions)." \
                   "cat /etc/shadow 2>/dev/null" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 5. Analyze Group Information
    append_section "Group Information" \
                   "Lists groups and users, helping identify potential privilege escalation vectors." \
                   "cat /etc/group" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 6. Review Sudoers and Sudo Configuration Files
    append_section "Sudo Configuration Files" \
                   "Checks sudo configurations, identifying entries that might allow privilege escalation or backdoors." \
                   "cat /etc/sudoers && cat /etc/sudoers.d/* 2>/dev/null" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 7. SSH Authentication Keys and Known Hosts
    append_section "SSH Authentication Keys and Known Hosts" \
                   "Reviews SSH authorized_keys and known_hosts for each user to detect unauthorized access." \
                   "find / -name authorized_keys -exec cat {} \\; 2>/dev/null && find / -name known_hosts -exec cat {} \\; 2>/dev/null" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 8. Login Information and Last Login Analysis
    append_section "User Login History" \
                   "Summarizes recent login history, including successful and failed attempts, for anomaly detection." \
                   "lastlog && last -f /var/log/wtmp && last -f /var/log/btmp" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 9. Authentication Log Analysis
    append_section "Authentication Logs" \
                   "Searches auth.log (Debian/Ubuntu) or secure log (RHEL/CentOS) for login events and suspicious activity." \
                   "grep -Iv cron /var/log/auth.log* | grep -iE 'user|Accepted|failed|login:session' 2>/dev/null && cat /var/log/secure 2>/dev/null" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 10. Command History for Root and Users
    append_section "User Command Histories" \
                   "Checks history files across shells (bash, mysql, ftp, sftp) and editors (vim, less) for user actions." \
                   "find /home -type f \\( -name '.*history' -o -name '.viminfo' -o -name '.lesshst' \\) -exec cat {} \\; 2>/dev/null && cat /root/.bash_history 2>/dev/null" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 11. Scheduled Tasks (Cron Jobs, System Timers)
    append_section "Scheduled Tasks" \
                   "Lists user and system cron jobs and timers, which attackers may use for persistence." \
                   "crontab -l 2>/dev/null && systemctl list-timers --all 2>/dev/null" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # Append the summary explicitly at the end of the data collection
    {
        echo "========================================="
        echo "  Summary of Collected Sections in User and Authentication"
        echo "========================================="
        echo "All sections have been successfully collected and saved."
        echo ""
        echo "- **User and Authentication Report**: ${main_func_report_file}"
        echo "  Contains all user and authentication-related information sections for an overview."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path and print it to the terminal
    echo "${main_func_report_file}"
    cat "${main_func_report_file}"
}

# Function 7: Collect Log Information
collect_log_information() {
    local func_folder="forensic_output/7_Log_Information"
    local main_func_report_file="${func_folder}/Logs_Analysis.txt"

    # Ensure the folder exists or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi

    # Create the main report file with a header
    {
        echo "========================================="
        echo "            LOG INFORMATION              "
        echo "           $(date)                       "
        echo "========================================="
        echo "Overview sections are listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # 1. System Logs
    append_section "System Logs Summary" \
                   "Lists all log files in /var/log. Look for unusual timestamps or permissions that may indicate tampering." \
                   "ls -al --time-style=full-iso /var/log/*" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 2. Authentication Logs
    append_section "Authentication Logs" \
                   "Summarizes login history and failed attempts, and looks for patterns in authentication logs for anomalies." \
                   "last && lastb && grep -iE 'session opened for|accepted password|new session|not in sudoers' /var/log/auth.log" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 3. Kernel and System Event Logs
    append_section "Kernel and System Event Logs" \
                   "Captures kernel events from kern.log and dmesg logs to identify repeated errors or unusual timestamps." \
                   "cat /var/log/kern.log && cat /var/log/dmesg" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 4. User Activity Logs
    append_section "User Activity Logs" \
                   "Records user command history. Be cautious of commands like 'rm', 'chmod', or 'chown' used unexpectedly." \
                   "for user in \$(ls /home/); do cat /home/\$user/.bash_history; done" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 5. Scheduled Tasks
    append_section "Scheduled Tasks (Cron Jobs)" \
                   "Collects cron jobs for all users to detect unexpected tasks or unknown scripts." \
                   "crontab -u root -l && cat /etc/crontab && ls /etc/cron.*" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 6. Application and Service Logs
    append_section "Application and Service Logs" \
                   "Collects logs from critical services like Apache and MySQL. Unusual patterns may indicate compromises." \
                   "cat /var/log/apache2/access.log* && cat /var/log/mysql.log" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 7. Network and Firewall Logs
    append_section "Network and Firewall Logs" \
                   "Records active network connections, firewall settings, and DNS configurations to identify breaches." \
                   "netstat -antup && cat /etc/hosts && cat /etc/resolv.conf && cat /etc/hosts.allow && cat /etc/hosts.deny" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 8. Metadata Collection
    append_section "File Metadata" \
                   "Collects metadata (modification time, size) of log files. Unusual changes could indicate tampering." \
                   "find /var/log/ -type f -exec stat --format '%n %y %s' {} \\;" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # Append summary at the end of the report
    {
        echo "========================================="
        echo " Summary of Collected Log Information    "
        echo "========================================="
        echo "All log-related sections have been successfully collected and saved."
        echo ""
        echo "- **Log Analysis Report**: ${main_func_report_file}"
        echo "  Contains all sections related to log information for an overview."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path and display it
    echo "${main_func_report_file}"
    cat "${main_func_report_file}"
}

# Function 8: Collect Persistence Mechanisms Information
collect_persistence_signs() {
    local func_folder="forensic_output/8_Persistence_Signs"
    local main_func_report_file="${func_folder}/Persistence_Analysis.txt"

    # Ensure the folder exists or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi

    # Create the main report file with a header
    {
        echo "========================================="
        echo "      PERSISTENCE MECHANISMS ANALYSIS    "
        echo "           $(date)                       "
        echo "========================================="
        echo "Overview sections are listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # 1. Webshell Detection
    append_section "Webshell Detection" \
                   "Searches for modified PHP files in /var/www/html, as these may indicate the presence of webshells." \
                   "find /var/www/html -type f -name '*.php' -printf '%T@ %f\n' | sort -n | awk '{print strftime(\"%Y-%m-%d %H:%M:%S\", \$1), \$2}'" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 2. Cron Jobs - Scheduled Tasks
    append_section "Scheduled Tasks and Cron Jobs" \
                   "Checks system-wide and user-specific cron jobs for persistence mechanisms." \
                   "cat /etc/crontab && ls /etc/cron.*/* && ls /var/spool/cron/crontabs/* && for user in \$(cut -f1 -d: /etc/passwd); do crontab -u \$user -l; done" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 3. Systemd and Service Units
    append_section "Systemd Services and Units" \
                   "Lists enabled services and custom unit files to identify potential persistence services." \
                   "systemctl list-unit-files --type=service --state=enabled && ls /etc/systemd/system/" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 4. SSH Daemon Configurations
    append_section "SSH Configuration and Persistence" \
                   "Examines SSH daemon configuration and user-specific SSH files for persistence scripts." \
                   "cat /etc/ssh/sshd_config && ls ~/.ssh/rc && ls /etc/ssh/sshrc" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 5. Login Shell Modifications
    append_section "Login Shell Configuration" \
                   "Checks shell initialization files for scripts or commands used for persistence." \
                   "cat /etc/bash.bashrc && cat /etc/profile && for user in \$(ls /home); do cat /home/\$user/.bashrc /home/\$user/.profile; done" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 6. Potentially Infected Binaries
    append_section "Infected or Modified Binaries" \
                   "Finds binaries modified in the last 10 days in critical directories." \
                   "find /lib /usr/bin /usr/sbin -type f -newermt \$(date -d '10 days ago' +'%Y-%m-%d')" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 7. PAM Configuration Files
    append_section "PAM Configuration Files" \
                   "Checks PAM (Pluggable Authentication Modules) configurations for unusual or modified entries." \
                   "cat /etc/pam.conf && ls /etc/pam.d" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # 8. MOTD Scripts
    append_section "Message of the Day (MOTD) Scripts" \
                   "Reviews MOTD scripts for unauthorized modifications used for persistence." \
                   "cat /etc/update-motd.d/*" \
                   "${func_folder}" \
                   "${main_func_report_file}"

    # Append summary at the end of the report
    {
        echo "========================================="
        echo " Summary of Persistence Mechanisms       "
        echo "========================================="
        echo "All persistence-related sections have been successfully collected and saved."
        echo ""
        echo "- **Persistence Analysis Report**: ${main_func_report_file}"
        echo "  Contains all sections related to persistence mechanisms for an overview."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path and display it
    echo "${main_func_report_file}"
    cat "${main_func_report_file}"
}

# Function 9: Collect Container and VM Information
container_and_vm_info() {
    local func_folder="forensic_output/Containers_and_VMs"
    local main_func_report_file="${func_folder}/Container_VM_Info.txt"

    # Ensure the folder exists or create it
    if [[ -d "${func_folder}" ]]; then
        log_info "Folder exists. Clearing contents of: ${func_folder}"
        rm -rf "${func_folder:?}"/*
    else
        log_info "Creating folder: ${func_folder}"
        mkdir -p "${func_folder}"
    fi

    # Create the main report file with a header
    {
        echo "========================================="
        echo "   CONTAINERS AND VM INFORMATION         "
        echo "           $(date)                       "
        echo "========================================="
        echo "Overview of container and VM information is listed below."
        echo ""
    } > "${main_func_report_file}"

    if [[ -f "${main_func_report_file}" ]]; then
        log_info "Main report file successfully created at: ${main_func_report_file}"
    else
        log_error "Failed to create the report file at: ${main_func_report_file}"
        return 1
    fi

    # 1. Docker Information
    if command -v docker &>/dev/null; then
        append_section "Docker Containers (All)" \
                       "Lists all Docker containers and their statuses." \
                       "docker ps -a" \
                       "${func_folder}" \
                       "${main_func_report_file}"

        append_section "Docker Images" \
                       "Lists all Docker images available on the system." \
                       "docker images" \
                       "${func_folder}" \
                       "${main_func_report_file}"
    else
        {
            echo "Docker is not installed or not available in the PATH."
            echo "Skipping Docker-related information collection."
            echo ""
        } >> "${main_func_report_file}"
    fi

    # 2. Virtual Machines (using Virsh for libvirt)
    if command -v virsh &>/dev/null; then
        append_section "Virtual Machines (using virsh)" \
                       "Lists all virtual machines managed by libvirt." \
                       "virsh list --all" \
                       "${func_folder}" \
                       "${main_func_report_file}"
    else
        {
            echo "Virsh (libvirt) is not installed or not available in the PATH."
            echo "Skipping VM-related information collection."
            echo ""
        } >> "${main_func_report_file}"
    fi

    # Append summary at the end of the report
    {
        echo "========================================="
        echo " Summary of Container and VM Information "
        echo "========================================="
        echo "All container and VM-related information has been successfully collected."
        echo ""
        echo "- **Container and VM Report**: ${main_func_report_file}"
        echo "  Contains an overview of container and VM information."
        echo ""
        echo "- **Individual Section Reports**:"
        echo "  Each section has its own detailed report under the 'Sections' folder."
        echo "  Review specific sections for detailed insights."
        echo ""
        echo "========================================="
    } >> "${main_func_report_file}"

    # Return the report file path and display it
    echo "${main_func_report_file}"
    cat "${main_func_report_file}"
}


main_menu() {
    while true; do
        clear
        echo "========================================="
        echo "         Linux Forensic Toolkit          "
        echo "========================================="
        echo "Choose an option by entering a number:"
        echo "1. System Information"
        echo "2. Network Usage"
        echo "3. Processes"
        echo "4. Directories"
        echo "5. Files and Installed Software"
        echo "6. Users and Authentication Activity"
        echo "7. Logs"
        echo "8. Persistence Mechanisms"
        echo "9. Containers and VM Information"
        echo "0. Exit"
        echo "========================================="

        read -p "Enter your choice [0-9]: " choice

        if [[ ! "$choice" =~ ^[0-9]$ ]] || [[ "$choice" -lt 0 ]] || [[ "$choice" -gt 9 ]]; then
            echo "[ERROR] Invalid option. Please enter a number between 0 and 9."
            continue
        fi

        case $choice in
            1) run_with_progress "system_info" ;;
            2) run_with_progress "network_usage" ;;
            3) run_with_progress "process_information" ;;
            4) run_with_progress "directory_information" ;;
            5) run_with_progress "files_and_installed_programs" ;;
            6) run_with_progress "users_and_authentication_activity" ;;
            7) run_with_progress "collect_log_information" ;;
            8) run_with_progress "collect_persistence_signs" ;;
            9) run_with_progress "container_and_vm_info" ;;
            0)
                echo "Exiting script."
                exit 0
                ;;
            *) echo "[ERROR] Invalid option. Please try again." ;;
        esac

        echo
        read -p "Press Enter to return to the main menu..."
    done
}

# Main menu call
main_menu

