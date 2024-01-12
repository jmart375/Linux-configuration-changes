System Hardening and Compliance

## Summary
This report aims to identify 20-plus configuration changes that we can implement using the well-known standards for our flavor of Linux (Tested and Validated on Kali 2022.3) published by the Center for Internet security to help increase the computer's hardness score. It's essential to look at the computer's operating system and any application that lives on in which you're planning to market and try to use the recommended configurations that should be closed to avoid unexpected behavior and ideally reduce the attack surface for an attacker. Below will list the identified configurations, why we selected them, why we implemented them and how they helped improve what started as a hardness score of 59 and improved to a hardness score of 69 after our configuration changes. This is only the first step of many when it comes to continuous monitoring. We can tackle doing another 20 configurations in the next Sprint, increasing the hardness level even further. 


## Table of Contents
- [Executive Summary](#executive-summary)
- [Filesystem Configuration](#filesystem-configuration)
- [Removal of Unused Services](#removal-of-unused-services)
- [Network Configuration](#network-configuration)
- [Logging and Auditing](#logging-and-auditing)
- [References](#references)

Clean install of Kali v2022.3 (pictured below) 
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/19007a2a-ab56-4d4f-b0e1-57c1dd27b59c)
After the 20 configuration changes.  
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/297861ca-8c19-4482-876e-7ed742b7a679)

# Filesystem Configuration
A configuration file, with another name, config file, defines the parameters, options, settings, and preferences applied to operating systems, infrastructure devices, and applications in IT. Software and hardware devices can be profoundly complex, supporting many options and parameters. These configurations allow us to configure our environments based on our company’s needs. 

## 1.4 Filesystem Integrity Checking
- **1.4.1 Ensure AIDE is installed**
•	1.4 Filesystem Integrity Checking
AIDE is a file integrity-checking tool that is like Tripwire. AIDE cannot prevent intrusions, but it can detect unauthorized changes to configuration files alerting when they are changed. When setting up AIDE, we should decide internally what the site policy will be concerning integrity checking. Review the AIDE quick start guide and AIDE documentation before proceeding.
o	1.4.1 Ensure AIDE is installed
AIDE takes a snapshot of the filesystem state, including modification times, permissions, and file hashes. This can then be used to compare against the current state of the filesystem to detect modifications to the system.
To verify that AIDE is installed, we run the following commands:
dpkg -s aide | grep 'Status: install ok installed.'
And we should get ‘Status: install ok installed.’
Other than that, to remediation, we should install AIDE using the appropriate package manager or manual installation and use the following command: apt install aide aide-common 
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/e134613d-7585-4660-aa07-c4a4bbb42636)

- **1.5 Secure Boot Settings**
•	1.5 Secure Boot Settings
Secure Boot is a security standard developed by members of the PC industry to help ensure that a device boot uses only software trusted by the original equipment manufacturer. It mainly focuses on directly securing the bootloader and settings involved in the boot process. 
o	1.5.1 Ensure permissions on bootloader config are configured
Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them.
We run the following command:
stat /boot/grub/grub.cfg
And to set permissions on the grub configuration, we run the following command: 
chown root:root /boot/grub/grub.cfg
o	1.5.3 Ensure authentication is required for single-user mode
Requiring authentication in single-user mode prevents an unauthorized user from rebooting the system into a single user to gain root privileges without credentials. 
Perform the following to determine if a password is set for the root user:
grep ^root:[*\!]: /etc/shadow
And no result should show up.
To set a password for the root user, we should run the following command and follow the prompts:
passwd root
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/5277d8b7-1078-48ab-b5d9-9db669b98f40)

- **1.6 Additional Process Hardening**
•	1.6 Additional Process Hardening
o	1.6.2 Ensure address space layout randomization (ASLR) is enabled
Address space layout randomization (ASLR) is an exploit mitigation technique that randomly arranges the address space of key data areas of a process. Generically and on AMD processors, this ability is called No Execute (NX), while on Intel processors, it is called Execute Disable (XD). This ability can help prevent the exploitation of buffer overflow vulnerabilities and should be activated whenever possible. 
To enable any feature that can protect against buffer overflow attacks and enhance the system’s security, we run the following command and verify activated NX/XD protection.
# journalctl | grep 'protection: active' kernel: NX (Execute Disable) protection: active
And nothing should be returned;
Configure your bootloader to load the new kernel and reboot the system if necessary. You may need to enable NX or XD support in your bios.
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/505fd4f6-694a-4cc1-82b3-17172827542d)

•	1.7 Mandatory Access Control\
Mandatory Access Control (MAC) provides an additional layer of access restrictions to processes on top of the base Discretionary Access Controls. By restricting how processes can access files and resources on a system, the potential impact of vulnerabilities in the techniques can be reduced. Mandatory Access Control limits the capabilities of applications and demons on a system. While this can prevent unauthorized access, the configuration of MAC can be complex and challenging to implement correctly, preventing legitimate access. 
o	1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration
Configure AppArmor to be enabled at boot time and verify that the bootloader boot parameters have not been overwritten.
AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden.
We run the following commands to verify that all Linux lines have the apparmor=1 and security=apparmor parameters set:
grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1"
And nothing should be returned. 
To remediate we should follow the commands below; 
GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"
Or:
update-grub
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/c7c90d03-2fa8-4448-adf0-454b44eae2ee)

# Network Configuration
Section 3 provides a list of ways to secure the system’s network configuration through kernel parameters and access list control. Network configuration is a security measure needed when building and installing network devices. The reason being newly installed computers and network devices are often set to default configurations. As we will see below, the network configurations are centered on ICMP (Internet Control Message Protocol) and determine whether or not data is reaching its intended destination promptly. ICMP is an internet protocol that is used by network devices to send error messages and operational information (“What is an ICMP,” 2022). To combat this issue, patches, updates, and changes are typically required to adjust the system. A properly configured network will enhance security and improve network stability.
Section 3 provides a list of ways to secure the system’s network configuration through kernel parameters and access list control. Network configuration is a security measure needed when...

## 3.2.1 Ensure packet redirect sending is disabled
- This configuration describes the ICMP (Internet Control Message Protocol) packet redirect functionality and what can be done to lessen the negatively associated network conditions. In this case, there is no need to send redirects. Below we can see one of the steps taken; here, we added the necessary entries to ensure this service is disabled.
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/0620fc05-7283-4842-884f-b1299d75b033)

## 3.3.1 Ensure source-routed packets are not accepted
- In this case, we have non-source routed packets that travel a path determined by routers in the network but are not reachable in some instances. So, source-routed packets would need to be used. The illustration below shows the necessary changes that were made.
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/8316ba4f-30b8-4576-a757-e2d21e5b9082)

# Logging and Auditing
- Having detailed audit logs helps companies monitor data and keep track of potential security breaches or internal misuse of information. They help to ensure users follow all documented protocols and also assist in preventing and tracking down fraud. Any intrusion can be detected in real-time by examining audit records as they are created. Importantly, to maximize the security benefits of audit logging, the logs should be reviewed often enough to detect security incidents as early as possible. Below you'll find a list of the seven recommended configuration settings from the CIS benchmark that I made to our Kali VM to help improve the system’s security. In hindsight, I initially thought the changes I made below would drastically enhance the Kali VM's hardness score. As it turns out, it didn't change the hardness score at all, but it did enhance our visibility on what happened when it happened and why it happened. Without the configurations below made to our VM, we wouldn't have visibility on what was changed, making troubleshooting and remediating the issue that occurred very difficult.
•	4.1.1.1 Ensure auditd is installed.
o	This service allows “auditd” access to the user space component of the Linux Auditing System. It's responsible for writing audit records to the disk. 
o	Below, we can see the command to verify that the service has been installed. 
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/fb4fa2e3-0870-4af7-bd49-0b2c93628564)
•	4.1.1.2 Ensure the “auditd” service is enabled.
o	The capturing of system events provides system administrators with information to determine if unauthorized access to their system occurs.
o	Below, the picture illustrates that the audited services are enabled. 
![image](https://github.com/jmart375/Linux-configuration-changes/assets/91294710/84cf0cde-9b63-4d47-aae7-c541404c99b1)

