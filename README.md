🔧 Kernel-Level AV Evasion & Process Interception Framework
This project is a kernel-mode driver designed for fast-acting detection and neutralization of anti-tamper and security software. It leverages deep Windows internals — including PsOpenProcess, the Object Type Initializer Table, and low-level manipulation of process structures — to intercept, deny access, or terminate target processes without relying on user-mode APIs or standard kernel routines that are easily hooked or monitored.

🧠 Key Features
Direct Object Type Table Hooks: Intercepts access to PROCESS and DEVICE object types at the kernel level by modifying the Object Type Initializer Table.

Process Filtering by Executable Name: Uses SeLocateProcessImageName to filter targets by full process path and apply enforcement policies.

Termination Without API: Kills or neuters protected processes (e.g., Malwarebytes.exe, MsMpEng.exe) without calling ZwTerminateProcess or other monitored APIs.

Audit-Proof Enforcement: Uses low-level mechanisms to avoid triggering ETW, audit logs, or user-mode AV hooks.

IDT-Based Kernel Locating: Utilizes the Interrupt Descriptor Table (IDT) page to locate the base address of ntoskrnl.exe, allowing full relocation-free operation even in ASLR-hardened environments.

🕳️ Use Cases
Red-teaming & security research.

AV/EDR evasion simulation.

Custom hypervisor or stealth kernel tool foundations.

Teaching tool for Windows kernel internals.

⚠️ Disclaimer
This tool is for educational and research purposes only. Unauthorized deployment or use against systems you do not own or have explicit permission to interact with may be illegal.

