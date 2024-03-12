Commands we might have to use in the exam
# Information Gathering

## Amass

```
# Data Sources
amass intel -list

# info related to name of org
amass intel -org [name of company] -dir [name of company]

# Reverse whois
amass intel -whois -d [domain name of company] -dir [name of company]

# subdomain determination
amass enum -active -ip -src -d [domain name of company] -dir [name of company]
amass enum -v -active -brute -ip -src -d [domain name of company] -dir [name of company]

# Display
amass db -dir [name of company] -d [domain] -show -ip
```

## Google Dorking
[Google Dorking commands](https://stationx.net/google-dorking-commands/)

## Alternative commands

```
host <website>

whois <domain>

dnsrecon -d <domain>

wafw00f <domain>

wafw00f <domain> -a

sublist3r -d <domain>

theHarvester -d <domain> -b <search engine>

dnsenum <domain>

dig [server] [name] [type]

whatweb <url>
```


## Alternative Sites
-  [dnsdumpster site](https://dnsdumpster.com/)
- [NetCraft Site tools](https://www.netcraft.com/tools/)
- [theHarvester repository](https://github.com/laramies/theHarvester)

# Footprinting & Scanning

## Nmap
```
nmap -sV <ip>

nmap -O <ip>

nmap -T4 -sS -sV -O -p- <ip>

nmap -T4 -sS -sV -O --osscan-guess -p- <ip>

nmap -T4 -sS -sV --version-intensity -O -p- <ip>

# to find scripts
ls -la user/share/nmap/scripts | grep "http"

nmap -sS -sV -sC -p- -T4 <ip>

nmap --script-help=<script name>

# ack on closed ports
nmap -sA -p<port> <ip>

# fragmented packets
nmap -Pn -sS -f <ip>

nmap -Pn -sS -sV -p<ports> -f --mtu <size> <ip>

nmap -Pn -sS -sV -p80,445 -f --data-length 200 -D <gateway IP> <target IP>

# timing & performance
nmap -sS -sV -F --scan-delay 15s <ip>

nmap -sS -sV -F --max-scan-delay 15s <ip>

nmap -Pn -sS -F --host-timeout 1s;5m;2h <ip>

nmap -sV -sS <ip> -oN filename.txt
```

# Enumeration
## nmap
```
--script smb-protocols
--script smb-security-mode
--script smb-enum-sessions
--script smb-enum-shares
--script smb-enum-users
--script smb-server-stats
--script smb-enum-domain
--script smb-enum-groups
--script smb-enum-services

nmap -p<port Number> --script smb-enum-shares,smb-ls --script-args smbusername=<username> smbpassword=<password> <ip>

nmap <ip> -p445 --script smb-os-discovery

nmap <ip> --script ftp-brute --script-args userdb=<filepath of txt file> -p21
nmap -p21 <ip> --script ftp-anon

# ssh
nmap <ip> -p<port> --script ssh2-enum-algos
nmap <ip> -p<port> --script ssh-hostkey --script-args ssh_hostkey=full
nmap <ip> -p<port> --script ssh-brute --script-args userdb=/root/user

# http
nmap <ip> -sV -p80 --script http-enum
nmap <ip> -sV -p80 --script http-headers
nmap <ip> -sV -p80 --script http-methods --script-args http-methods.url-path=</path/to/file>
nmap <ip> -sV -p80 --script http-methods --script-args http-methods.url-path=/webadv/
nmap <ip> -sV -p80 --script http-webdav-scan --script-args http-methods.url-path=/webadv/

nmap <ip> -sV -p80 --script banner

# mysql
--script=mysql-empy-password
--script=mysql-info
--script=mysql-users --script-args="mysqluser='root',mysqlpass''"
--script=mysql-databases --script-args="mysqluser='root',mysqlpass''"
--script=mysql-variables --script-args="mysqluser='root',mysqlpass''"

--script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password'',mysql-audit.filename='<filepath>'"
/usr/share/nmap/nselib/data/mysql-cis.audit

# smtp
nmap -sV -script banner <TARGET_IP>
--script=smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t <TARGET_IP>

```

## SMB map
```
smbmap -u <username> -p <password> -d . -H <ip>
```
[smbmap docs](https://www.kali.org/tools/smbmap/)

## Metasploit
```
auxiliary/scanner/smb/smb_version

auxiliary/scanner/smb/smb_login
/usr/share/wordlists/metasploit/unix_passwords.txt

auxiliar/scanner/smb/pipe_auditor

# ssh
use auxiliary/scanner/ssh/
/usr/share/wordlists/metasploit/root_userpass.txt

# http
use auxiliary/scanner/http/brute_dirs
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/http_header
use auxiliary/scanner/http/http_login
use auxiliary/scanner/http/http_version

set USER_FILE <USERS_LIST>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set AUTH_URI /<DIR>/
exploit

# mysql
use auxiliary/scanner/mysql/mysql_schemadump
use auxiliary/scanner/mysql/mysql_writable_dirs
use auxiliary/scanner/mysql/mysql_file_enum
use auxiliary/scanner/mysql/mysql_hashdump
use auxiliary/scanner/mysql/mysql_login

## ms Sql
use auxiliary/scanner/mssql/mssql_login
use auxiliary/admin/mssql/mssql_enum
use auxiliary/admin/mssql/mssql_enum_sql_logins
use auxiliary/admin/mssql/mssql_exec
use auxiliary/admin/mssql/mssql_enum_domain_accounts
use auxiliary/scanner/mysql/mysql_writable_dirs
set dir_list /usr/share/metasploit-framework/data/wordlists/directory.txt

set USERNAME root
set PASSWORD ""

set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE false
set PASSWORD ""

set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt
set PASSWORD ""

set USER_FILE /root/Desktop/wordlist/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set STOP_ON_SUCCESS true

# postgress
service postgresql start && msfconsole -q
use auxiliary/scanner/smtp/smtp_enum
```

## SMB client
```
smbclient -L <ip>
smbclient //<ip>/share name>/ -N

smbclient -L <TARGET_IP> -N
smbclient -L <TARGET_IP> -U <USER>
smbclient //<TARGET_IP>/<USER> -U <USER>
smbclient //<TARGET_IP>/admin -U admin
smbclient //<TARGET_IP>/public -N #NULL Session
## SMBCLIENT
smbclient //<TARGET_IP>/share_name
help
ls
get <filename>

```

## RPC client
```
rpcclient -U <username> -N <ip>

enumdomusers

lookupnames admin
```

## Enum4Linux
```
enum4linux -o <ip>   #OS
enum4linux -U <ip>   # enum users
enum4linux -G <ip>   # rights of users
enum4linux -i <ip>   # printers
enum4linux -r -u "useranme" -p "password" <ip>

enum4linux -r -u "<USER>" -p "<PW>" <TARGET_IP>
enum4linux -a -u "<USER>" -p "<PW>" <TARGET_IP>
enum4linux -U -M -S -P -G <TARGET_IP>
```

## Hydra
```
hydra -l admin -P <wordlist path> <ip> <service>

hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <ip> smb

hydra -l <username> -P /usr/share/wordlists/rockyou.txt <ip> ssh
```

## Netcat
```
nc <ip> 22
```

## Dirb
```
dirb http://<ip>
```
## Alternative Commands
```
nmblookup -A <ip>

curl <ip> | more
curl http://<ip>/dir

wget "http://<ip>/index"

browsh --startup-url <ip>
lynx http://<ip>

mysql -h <ip> -u <admin username>
```
