# Bandit

Wargame homepage: https://overthewire.org/wargames/bandit/

ssh login template:
```sh
ssh bandit@bandit.labs.overthewire.org -p 2220
```

- [Bandit](#bandit)
  - [L0](#l0)
  - [L1](#l1)
  - [L2](#l2)
  - [L3](#l3)
  - [L4 Hidden Files](#l4-hidden-files)
  - [L5](#l5)
  - [L6 `find  your/path/ -type f -exec COMMAND {} +`](#l6-find--yourpath--type-f--exec-command--)
  - [L7](#l7)
  - [L8](#l8)
  - [L9 `sort | uniq -u`](#l9-sort--uniq--u)
  - [L10 `strings` and Printing Binaries](#l10-strings-and-printing-binaries)
  - [L11 base64](#l11-base64)
  - [L12 `tr` \& ROT13](#l12-tr--rot13)
  - [L13 Hexdump, xxd](#l13-hexdump-xxd)
  - [L14 ssh key: `ssh -i your_key`](#l14-ssh-key-ssh--i-your_key)
  - [L15 Telnet](#l15-telnet)
  - [L16 SSL/TLS](#l16-ssltls)
  - [L17 Port Scanning](#l17-port-scanning)
  - [L18 diff](#l18-diff)
  - [L19 ssh \[cmd\]](#l19-ssh-cmd)
  - [L20 setuid](#l20-setuid)
  - [L21 netcat TCP Listener](#l21-netcat-tcp-listener)
  - [L22 cron + Bash Script](#l22-cron--bash-script)
  - [L23 cron + Bash Script](#l23-cron--bash-script)
  - [L24 cron + Bash Script](#l24-cron--bash-script)
  - [L25 Bruteforcing](#l25-bruteforcing)
  - [L26 login shell, `/etc/passws`, `more`](#l26-login-shell-etcpassws-more)

## L0
`ssh bandit0@bandit.labs.overthewire.org -p 2220`

## L1
Congratulations on your first steps into the bandit game!!
Please make sure you have read the rules at https://overthewire.org/rules/
If you are following a course, workshop, walkthrough or other educational activity,
please inform the instructor about the rules as well and encourage them to
contribute to the OverTheWire community so we can keep these games free!

The password you are looking for is: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If

## L2
ok this one is trick. So basically if your filename is just a hyphen `-`, you use double hyphen to escape it (mark the end of flags and options), as in `vim -- -` or `cat ./-`. However, somehow `cat -- -` didn't work for me.

263JGJPfgU6LtdEvgfWU1XP5yac29mFx

## L3 
Use backslash to escape. MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx

## L4 Hidden Files
File is hidden. Use `ls -a`. 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ

## L5
`file inhere/-file0{0..9}` Use `file` cmd + brace expansion.

```bash
bandit4@bandit:~$ cat inhere/-file07
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```
## L6 `find  your/path/ -type f -exec COMMAND {} +`
The simplest way to output all pipeline-able filenames plus their paths, is `find .`

> [!tip]
> `file` does not read from standard input, so it is recommend to use `file your/path/ -type f -exec COMMAND {} +`
> where `-type f` specifies we are looking for files, `{}` is a placeholder for the filenames found by `find`, and `+` tells find to pass as many filenames as possible to file in a single invocation, which is more efficient than running file separately for each file.
> See 

       -exec command ;
              Execute command; true if 0 status is returned.  All following arguments to find are taken to be arguments to the command until  an  argu‐
              ment  consisting of `;' is encountered.  The string `{}' is replaced by the current file name being processed everywhere it occurs in the
              arguments to the command, not just in arguments where it is alone, as in some versions of find.  Both of these constructions  might  need
              to  be  escaped  (with a `\') or quoted to protect them from expansion by the shell.  See the EXAMPLES section for examples of the use of
              the -exec option.  The specified command is run once for each matched file.  The command is executed in the  starting  directory.   There
              are unavoidable security problems surrounding use of the -exec action; you should use the -execdir option instead.

       -exec command {} +
              This  variant  of  the -exec action runs the specified command on the selected files, but the command line is built by appending each se‐
              lected file name at the end; the total number of invocations of the command will be much less than the number of matched files.  The com‐
              mand line is built in much the same way that xargs builds its command lines.  Only one instance of `{}' is allowed  within  the  command,
              and  it  must appear at the end, immediately before the `+'; it needs to be escaped (with a `\') or quoted to protect it from interpreta‐
              tion by the shell.  The command is executed in the starting directory.  If any invocation with the `+' form returns a non-zero  value  as
              exit  status, then find returns a non-zero exit status.  If find encounters an error, this can sometimes cause an immediate exit, so some
              pending commands may not be run at all.  For this reason -exec my-command ... {} + -quit may not result in my-command actually being run.
              This variant of -exec always returns true.

```sh
bandit5@bandit:~$ find . -type f -exec ls -alt  {} + | grep 1033
-rw-r----- 1 root bandit5 1033 Sep 19 07:08 ./inhere/maybehere07/.file2
```

HWasnPhtq9AVKe0dmk45nxy20cvUa6EG

## L7

```sh
find . -type f -exec ls -alt {} + 2>/dev/null | grep bandit7 | grep bandit6
-rw-r----- 1 bandit7 bandit6      33 Sep 19 07:08 ./var/lib/dpkg/info/bandit7.password
```

Explanation:
- `find . -type f -exec ls -alt {} +` is just the same as L6.
- `2>/dev/null` redirects stderr to /dev/null so that we don't see a lot of 'permission denied' messages like `find: ‘./run/lock/lvm’: Permission denied`
- grep lines with both `bandit7` and `bandit6`. Can just chain two grep commands to match two words that are not necessarily next to each other.

morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj

## L8
```sh
bandit7@bandit:~$ cat data.txt | grep millionth
millionth	dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
```

## L9 `sort | uniq -u`
> [!tip]
> `uniq` must be used together with `sort` first, as it detects repeated lines only if they are adjacent.

```
┌◉ keniwo  ~  v20.11.1  v3.11.9  19:50 
└───◎ tldr uniq

uniq

Output the unique lines from a input or file.
Since it does not detect repeated lines unless they are adjacent, we need to sort them first.
More information: <https://www.gnu.org/software/coreutils/uniq>.

- Display each line once:
    sort path/to/file | uniq

- Display only unique lines:
    sort path/to/file | uniq -u

- Display only duplicate lines:
    sort path/to/file | uniq -d

- Display number of occurrences of each line along with that line:
    sort path/to/file | uniq -c

- Display number of occurrences of each line, sorted by the most frequent:
    sort path/to/file | uniq -c | sort -nr
```

Solution:
```bash
bandit8@bandit:~$ cat data.txt | sort | uniq -u
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
```

## L10 `strings` and Printing Binaries
> [!tip] 
> `strings`
> ⚠️ plural form
> `strings` Find printable strings in an object file or binary. 
> Specifically, it prints sequences of printable characters. Its main use is for non-printable files like hex dumps or executables.

```
┌◉  keniwo  …/overthewire   master !?   20:03  
└───◎ tldr strings

strings

Find printable strings in an object file or binary.
More information: <https://manned.org/strings>.

- Print all strings in a binary:
    strings path/to/file

- Limit results to strings at least n characters long:
    strings -n n path/to/file

- Prefix each result with its offset within the file:
    strings -t d path/to/file

- Prefix each result with its offset within the file in hexadecimal:
    strings -t x path/to/file
```

Solution:
```sh
bandit9@bandit:~$ cat data.txt | grep --binary-files=text "==" | strings
POl%
}========== the
5bBK
4Rl_7gH
F 4Cq
#61QW
hqI.X
3JprD========== passwordi
Czmnf&v
TO"'
~fDV3========== is
g+;Y
 Uum
D9========== FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
```

## L11 base64
```sh
bandit10@bandit:~$ cat data.txt | base64 -d
The password is dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
```

## L12 `tr` & ROT13
> [!tip]
> First have a look at:
> 1. ROT13 https://en.wikipedia.org/wiki/ROT13
> 2. `tr` utility: `man tr` or `tldr tr`

```sh
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4
```

## L13 Hexdump, xxd

> [!tip] 
> `hexdump` and `xxd`:
> 
> `hexdump` is the basic util. `xxd` could revert a hexdump to plaintext with `-r -p`.
> 
> Revert a plaintext hexdump back into binary, and save it as a binary file:
>   `xxd -r -p input_file output_file`
> 
> **Magic Number**: https://en.wikipedia.org/wiki/Magic_number_(programming)
> A constant numerical or text value used to identify a file format or protocol (for files, see List of file signatures)
> Can be verified with `xxd -l 16 -g 1 filename`

⚠️ Take notice of `-p` flag with `xxd`. If you just want to revert it, use only `-r` as `-p` will add 4 extra hex digits.
```sh
# Wrongly used -p flag
bandit12@bandit:/tmp/tmp.n2pYbOTEI5$ xxd -r -p data.txt output
bandit12@bandit:/tmp/tmp.n2pYbOTEI5$ xxd -l 16 -g 1 output.gz 
# -l: Display output only up to a length of 16 bytes; -g: Separate the output of every <bytes> bytes
00000000: 00 00 00 00 1f 8b 08 08 df cd eb 66 02 03 64 61  ...........f..da
bandit12@bandit:/tmp/tmp.n2pYbOTEI5$ gunzip output.gz
gzip: output.gz: not in gzip format

# Correct
bandit12@bandit:/tmp/tmp.n2pYbOTEI5$ xxd -r data.txt output
bandit12@bandit:/tmp/tmp.n2pYbOTEI5$ xxd -l 16 -g 1 output
00000000: 1f 8b 08 08 df cd eb 66 02 03 64 61 74 61 32 2e  .......f..data2
bandit12@bandit:/tmp/tmp.n2pYbOTEI5$ file output
output: gzip compressed data, was "data2.bin", last modified: Thu Sep 19 07:08:15 2024, max compression, from Unix, original size modulo 2^32 3154116610
```
In this case, `.gz` (gzip file)'s magic number is `1f 8b`. 
In the first try, `-p` actually prepended four `00` to the output, causing `gunzip` to not work.

> [!tip] 
> **Compression**
> 
> `.tar.gz` is the defacto archive & compression standard in CLI.
> 
> - Creating a Tar.gz Archive
>   - `tar -czvf archive_name.tar.gz file1 file2 directory1`
> - Extracting a Tar.gz Archive
>   - `tar -xvzf archive_name.tar.gz`

Reference:
```
-c      Create a new archive containing the specified items.  The long option form is --create.
-f file, --file file
        Read the archive from or write the archive to the specified file.  The filename can be - for standard input or standard output.  The default
        varies by system; on FreeBSD, the default is /dev/sa0; on Linux, the default is /dev/st0.
-v, --verbose
        Produce verbose output.  In create and extract modes, tar will list each file name as it is read from or written to the archive.  In list mode,
        tar will produce output similar to that of ls(1).  An additional -v option will also provide ls-like details in create and extract mode.
-x      Extract to disk from the archive.  If a file with the same name appears more than once in the archive, each copy will be extracted, with later
        copies overwriting (replacing) earlier copies.  The long option form is --extract.
-z, --gunzip, --gzip
        (c mode only) Compress the resulting archive with gzip(1).  In extract or list modes, this option is ignored.  Note that this tar implementation
        recognizes gzip compression automatically when reading archives.
```

After reverting hexdump with `xxd -r`, it is a bunch of very painful decompression and unarchiving with `bzip2 -d`, `gunzip -v`, and `tar xvf`.

```sh
bandit12@bandit:/tmp/tmp.n2pYbOTEI5$ cat finally
The password is FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn
```

## L14 ssh key: `ssh -i your_key`
```powershell
bandit13@bandit:~$ ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
```

## L15 Telnet

My first try: `telnet`

> [!tip]
> Simply put, Telnet is a lesser version of ssh. Transmission of data are in plaintext (unencrypted). 
> 
> Does not support key authentication or secured file transfer. 
> 
> Port is 23 by default. 

```powershell
bandit14@bandit:~$ telnet localhost 30000
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
Correct!
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```

After finishing Lv 16, i realized that this level essentially requires a TCP transport-layer connection.
So `nc` is also viable.

> [!tip]
> `nc` or netcat. TCP/UDP工具，构建简单的TCP/HTTP服务，网络守护进程测试 etc.
> - Handles TCP and UDP connections. 
> - It can open TCP connections, send UDP packets, listen on arbitrary TCP and UDP ports, do port scanning, and deal with both IPv4 and IPv6.  
> - Unlike telnet(1), nc scripts nicely, and separates error messages onto standard error instead of sending them to standard output, as telnet(1) does with some.

## L16 SSL/TLS
> [!note]
> **SSL/TLS, OpenSSL Takeaways**
> 
> SSL/TLS: A cryptographic protocal tp provide security for the *transport layer* in the OSI model.
> 
> OpenSSL: A library of the TLS protocal. Is the world's most widely used implementation.
> 
> HTTPS could also be understood as HTTP over SSL/TLS

This level is about the usage of `openssl s_client`. To refer to its man page, the command is `man openssl-s_client`.

tldr:
```
openssl s_client

OpenSSL command to create TLS client connections.
More information: <https://www.openssl.org/docs/manmaster/man1/openssl-s_client.html>.

- Display the start and expiry dates for a domain's certificate:
    openssl s_client -connect host:port 2>/dev/null | openssl x509 -noout -dates

- Display the certificate presented by an SSL/TLS server:
    openssl s_client -connect host:port </dev/null

- Set the Server Name Indicator (SNI) when connecting to the SSL/TLS server:
    openssl s_client -connect host:port -servername hostname

- Display the complete certificate chain of an HTTPS server:
    openssl s_client -connect host:443 -showcerts </dev/null
```

Solution
```
bandit15@bandit:~$ openssl s_client -connect 127.0.0.1:30001
...TLS messages...
---
read R BLOCK
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
Correct!
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

closed
```

🧐 My personal thoughts on this level: https://samizdat.fly.dev/m/ABnfi5QTS6QxQkFCTWfZ5A

## L17 Port Scanning

`nmap <ip>` carries out a basic port scanning process.

> [!important]
> `nmap <ip>` by default does not do a full scan. It only scans the most well-known hosts, and ports that aren't on that list are omitted.
> 
> To do a full scan, use `nmap -p 1-65535` or `nmap -p-`. [source](https://unix.stackexchange.com/questions/238640/nmap-doesnt-appear-to-list-all-open-ports)

It is also adviced to enable `service detection` with `-sv`
```
SERVICE AND VERSION DETECTION
       Point Nmap at a remote machine and it might tell you that ports 25/tcp, 80/tcp, and 53/udp are open. Using its nmap-services database of about 2,200 well-known services,
       Nmap would report that those ports probably correspond to a mail server (SMTP), web server (HTTP), and name server (DNS) respectively. This lookup is usually accurate—the
       vast majority of daemons listening on TCP port 25 are, in fact, mail servers. However, you should not bet your security on this! People can and do run services on strange
       ports.

       Even if Nmap is right, and the hypothetical server above is running SMTP, HTTP, and DNS servers, that is not a lot of information. When doing vulnerability assessments
       (or even simple network inventories) of your companies or clients, you really want to know which mail and DNS servers and versions are running. Having an accurate version
       number helps dramatically in determining which exploits a server is vulnerable to. Version detection helps you obtain this information.

       After TCP and/or UDP ports are discovered using one of the other scan methods, version detection interrogates those ports to determine more about what is actually
       running. The nmap-service-probes database contains probes for querying various services and match expressions to recognize and parse responses. Nmap tries to determine
       the service protocol (e.g. FTP, SSH, Telnet, HTTP), the application name (e.g. ISC BIND, Apache httpd, Solaris telnetd), the version number, hostname, device type (e.g.
       printer, router), the OS family (e.g. Windows, Linux). When possible, Nmap also gets the Common Platform Enumeration (CPE) representation of this information. Sometimes
       miscellaneous details like whether an X server is open to connections, the SSH protocol version, or the KaZaA user name, are available. Of course, most services don't
provide all of this information. If Nmap was compiled with OpenSSL support, it will connect to SSL servers to deduce the service listening behind that encryption layer.
       Some UDP ports are left in the open|filtered state after a UDP port scan is unable to determine whether the port is open or filtered. Version detection will try to elicit
       a response from these ports (just as it does with open ports), and change the state to open if it succeeds.  open|filtered TCP ports are treated the same way. Note that
       the Nmap -A option enables version detection among other things.  A paper documenting the workings, usage, and customization of version detection is available at
       https://nmap.org/book/vscan.html.

       When RPC services are discovered, the Nmap RPC grinder is automatically used to determine the RPC program and version numbers. It takes all the TCP/UDP ports detected as
       RPC and floods them with SunRPC program NULL commands in an attempt to determine whether they are RPC ports, and if so, what program and version number they serve up.
       Thus you can effectively obtain the same info as rpcinfo -p even if the target's portmapper is behind a firewall (or protected by TCP wrappers). Decoys do not currently
       work with RPC scan.

       When Nmap receives responses from a service but cannot match them to its database, it prints out a special fingerprint and a URL for you to submit it to if you know for
       sure what is running on the port. Please take a couple minutes to make the submission so that your find can benefit everyone. Thanks to these submissions, Nmap has about
       6,500 pattern matches for more than 650 protocols such as SMTP, FTP, HTTP, etc.

       Version detection is enabled and controlled with the following options:

       -sV (Version detection)
           Enables version detection, as discussed above. Alternatively, you can use -A, which enables version detection among other things.

        -sR is an alias for -sV. Prior to March 2011, it was used to active the RPC grinder separately from version detection, but now these options are always combined.
```

Solution Part 1
```
bandit16@bandit:~$ nmap -sV -p 31000-32000 localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-05 01:13 UTC
Stats: 0:01:15 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 83.33% done; ETC: 01:15 (0:00:15 remaining)
Stats: 0:01:57 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 83.33% done; ETC: 01:16 (0:00:23 remaining)
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00029s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31888/tcp open  echo
31960/tcp open  echo
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31790-TCP:V=7.94SVN%T=SSL%I=7%D=1/5%Time=6779DCDF%P=x86_64-pc-linux
SF:-gnu%r(GenericLines,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x20
SF:current\x20password\.\n")%r(GetRequest,32,"Wrong!\x20Please\x20enter\x2
SF:0the\x20correct\x20current\x20password\.\n")%r(HTTPOptions,32,"Wrong!\x
SF:20Please\x20enter\x20the\x20correct\x20current\x20password\.\n")%r(RTSP
SF:Request,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20p
SF:assword\.\n")%r(Help,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x2
SF:0current\x20password\.\n")%r(FourOhFourRequest,32,"Wrong!\x20Please\x20
SF:enter\x20the\x20correct\x20current\x20password\.\n")%r(LPDString,32,"Wr
SF:ong!\x20Please\x20enter\x20the\x20correct\x20current\x20password\.\n")%
SF:r(SIPOptions,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current
SF:\x20password\.\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 162.97 seconds
```

So, we would say 31790 is the one. But when we tried submitting the code to 31790, strange stuff happened.

⚠️ The server shouted KEYUPDATE.

```
bandit16@bandit:~$ openssl s_client -connect localhost:31790
...TLS messages
...
---
read R BLOCK
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
KEYUPDATE
```

This is probably due to the CONNECTED COMMANDS.

Below is an excerpt from the man page of openssl-s_client
```
CONNECTED COMMANDS
       If a connection is established with an SSL server then any data received from the server is displayed and any key presses will be
       sent  to  the  server.  If  end  of file is reached then the connection will be closed down. When used interactively (which means
       neither -quiet nor -ign_eof have been given), then certain commands are also recognized which perform special  operations.  These
       commands are a letter which must appear at the start of a line. They are listed below.

       Q   End the current SSL connection and exit.

       R   Renegotiate the SSL session (TLSv1.2 and below only).

       k   Send a key update message to the server (TLSv1.3 only)

       K   Send a key update message to the server and request one back (TLSv1.3 only)
```

What we gotta do is to escape `k`, or starting `s_client` with `-ign_eof`.

After some tests, `\k` really didn't worked out for me. So i used `openssl s_client -connect localhost:31790 -ign_eof`.

```
bandit16@bandit:~$ openssl s_client -connect localhost:31790 -ign_eof
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed
```

ssh requires your private key to be in mode `600` or `.rw-------`. Use `chmod 600 .ssh/your-key` before connection.

## L18 diff
Use `ssh -i path/to/your_key` to log in.

> [!tip]
> When comparing using `diff`, the old file always comes first in positional arguments.
> Use `-u` flag to output in a git-like format.

```
bandit17@bandit:~$ diff -u passwords.old  passwords.new
--- passwords.old       2024-09-19 07:08:22.603693566 +0000
+++ passwords.new       2024-09-19 07:08:22.608693607 +0000
@@ -39,7 +39,7 @@
 Udq1Zw8oOdLjcLZSoWFb3XVsLVr2J7e7
 fwJjyJfLsqI7eA3q1pmW0WjptEJPyjVj
 9jbIrrT9OlPADZDBfF1UOoz4lhboOnsT
-ktfgBvpMzWKR5ENj26IbLGSblgUG9CzB
+x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
 dX464MV2LHPWYN9RDa7AnVBqsxjl1zui
 GOTGHQIZKu2qwhUTibu5PQaMEMWvoUDR
 t7szZtdGClutCs1g4uWKN5I1oV3cnA0c
 ```
 
## L19 ssh [cmd]

Provide the ssh command with customized commands so that it skips login shell.

```md
SSH(1)                                                   General Commands Manual                                                   SSH(1)

NAME
     ssh – OpenSSH remote login client

SYNOPSIS
     ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address] [-c cipher_spec] [-D [bind_address:]port] [-E log_file]
         [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file] [-J destination] [-L address] [-l login_name] [-m mac_spec]
         [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address] [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]] destination
         [command [argument ...]]
     ssh [-Q query_option]

DESCRIPTION
     ...

     **If a command is specified, it will be executed on the remote host instead of a login shell.  A complete command line may be
     specified as command, or it may have additional arguments.  If supplied, the arguments will be appended to the command, separated by
     spaces, before it is sent to the server to be executed.**
```

In our case, simply ask it to print out the results
```
└───◎ ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password:
cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
```

## L20 setuid

reading material: https://en.wikipedia.org/wiki/Setuid

> [!TIP]
> **补充知识：File Mode & setuid**
> 
> Unix file mode 的数值形式(numeric  representation)是一个八进制的四位数(a four-digit octal number)，其中常见的三个位是后三位，也就是我们熟悉的`rwx`。
> 
> 文件的不同权限叫**mode bits**, 因为mode bits的值仅有4, 2, 1，每个digit的数值表示=各个bit的加和，一般只有4567这些值。4=read bits, 5=`r-x`, 7=`rwx`. 我们常见的让脚本可执行的命令，就是`chmod 755`.
> 
> 当然除了数值也有symbolic representation，在chmod里更改mode的符号格式为`[u/g/o][+/-/=][modebit]`，具体含义可以自行查阅man page。
>
> **setuid & setgid bits**
> 
> 被我们忽略掉的四位数的第一位就是s位。其中4=setuid bit, 2=setgid bit, 1=sticky bit. 那么6711 = 6(4:`setuid` + 2:`setgid`) + 711(`rwx--x--x`)

Below is an excerpt from `man chmod`
```
MODES
     Modes may be absolute or symbolic.  An absolute mode is an octal number constructed from the sum of one or more of the following
     values:

           4000    (the setuid bit).  Executable files with this bit set will run with effective uid set to the uid of the file owner.
                   Directories with this bit set will force all files and sub-directories created in them to be owned by the directory
                   owner and not by the uid of the creating process, if the underlying file system supports this feature: see chmod(2)
                   and the suiddir option to mount(8).
           2000    (the setgid bit).  Executable files with this bit set will run with effective gid set to the gid of the file owner.
           1000    (the sticky bit).  See chmod(2) and sticky(7).
           0400    Allow read by owner.
           0200    Allow write by owner.
           0100    For files, allow execution by owner.  For directories, allow the owner to search in the directory.
           0040    Allow read by group members.
           0020    Allow write by group members.
           0010    For files, allow execution by group members.  For directories, allow group members to search in the directory.
           0004    Allow read by others.
           0002    Allow write by others.
           0001    For files, allow execution by others.  For directories allow others to search in the directory.

    (...)

     The op symbols represent the operation performed, as follows:

     +     If no value is supplied for perm, the ``+'' operation has no effect.  If no value is supplied for who, each permission bit
           specified in perm, for which the corresponding bit in the file mode creation mask (see umask(2)) is clear, is set.  Otherwise,
           the mode bits represented by the specified who and perm values are set.

     -     If no value is supplied for perm, the ``-'' operation has no effect.  If no value is supplied for who, each permission bit
           specified in perm, for which the corresponding bit in the file mode creation mask is set, is cleared.  Otherwise, the mode
           bits represented by the specified who and perm values are cleared.

     =     The mode bits specified by the who value are cleared, or, if no who value is specified, the owner, group and other mode bits
           are cleared.  Then, if no value is supplied for who, each permission bit specified in perm, for which the corresponding bit in
           the file mode creation mask (see umask(2)) is clear, is set.  Otherwise, the mode bits represented by the specified who and
           perm values are set.

    (...)

EXAMPLES OF VALID MODES
     644           make a file readable by anyone and writable by the owner only.

     go-w          deny write permission to group and others.

     =rw,+X        set the read and write permissions to the usual defaults, but retain any execute permissions that are currently set.

     +X            make a directory or file searchable/executable by everyone if it is already searchable/executable by anyone.

     755
     u=rwx,go=rx
     u=rwx,go=u-w  make a file readable/executable by everyone and writable by the owner only.

     go=           clear all mode bits for group and others.

     g=u-w         set the group bits equal to the user bits, but clear the group write bit.  
```

Our solution:

Let's see how this binary works. `bandit20-do` is owned by `bandit20` and belongs to group `bandit19`, and can represent bandit20 to run our command under group `bandit19`.
Group `bandit19` means that any user that belongs to group `bandit19` (in this case, perhaps just the user `bandit19`) can do what the group has permission to do.

`s` means that when executing, `bandit20-do` has the same permission as the user `bandit20` 
and `x` in the group digit means that `bandit20-do` can be executed in group `bandit19`, and therefore user `bandit19`.
```
bandit19@bandit:~$ ls -alt bandit*
-rwsr-x--- 1 bandit20 bandit19 14880 Sep 19 07:08 bandit20-do
bandit19@bandit:~$ ./bandit20-do
Run a command as another user.
  Example: ./bandit20-do id
bandit19@bandit:~$ ./bandit20-do id
uid=11019(bandit19) gid=11019(bandit19) euid=11020(bandit20) groups=11019(bandit19)
```

If we try printing out the credential directly, it turns out to be forbidden, as it is only readable by its owner bandit20. But using bandit20-do as a workaround we can bypass the permission wall. 
```
bandit19@bandit:~$ cat /etc/bandit_pass/bandit20
cat: /etc/bandit_pass/bandit20: Permission denied
bandit19@bandit:~$ ls -alt /etc/bandit_pass/bandit20
-r-------- 1 bandit20 bandit20 33 Sep 19 07:07 /etc/bandit_pass/bandit20
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
```

## L21 netcat TCP Listener
This one actually took me some time. 
At first I thought is about Access Control and file modes again, 
so it really baffled me when starting from the executable and having no clue what is going on.

Let's see what is happening locally first. I use nmap to identify what service is running on 2220 localhost (ssh).
```
bandit20@bandit:~$ nmap -sV -p 2220 localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-06 00:38 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).

PORT     STATE SERVICE VERSION
2220/tcp open  ssh     OpenSSH 9.6p1 (protocol 2.0)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds

bandit20@bandit:~$ ./suconnect 2220
Read: SSH-2.0-OpenSSH_9.6p1
ERROR: This doesn't match the current password!

bandit20@bandit:~$ nc localhost 2220
SSH-2.0-OpenSSH_9.6p1
```

When I use `nc nc localhost 2220` to connect to port 2220, the ssh server prints `SSH-2.0-OpenSSH_9.6p1` which is just **the SSH server's initial greeting message**,
so `./suconnect 2220` actually connects to `bandit20@localhost:2220`, reads the first line and see if this line matches.

And as far as I can tell, `./suconnect` cannot connect to another username (we're gonna be stuck with bandit20)
So, the problem here is for suconnect to match. We'll in this case create our own network daemon. 

The perfect way to do this is to use netcat `nc` again. `nc` implements TCP and can of course initialize a TCP listener on `bandit20@localhost:SOMEPORT`.
We echo the password for Lv.20 and pass it for `nc -l` to serve it on port 2223 with a listener `-l`.
`&` is for detach mode so `nc` gives back our shell control.

```
bandit20@bandit:~$ echo "0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO" | nc -l -p 2223 &
[2] 248374

bandit20@bandit:~$ ./suconnect 2223
Read: 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
Password matches, sending next password
EeoULMCra2q0dSkYj561DX7s1CpBuOBt
```

## L22 cron + Bash Script
> [!tip]
> **GTK**
>
> - `cron`
> - `crontab`
> - `cron.d`


```
bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null

bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

bandit21@bandit:~$ file /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv: ASCII text

bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q
```

## L23 cron + Bash Script

```bash
bandit22@bandit:~$ cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null

bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget

bandit22@bandit:~$ /usr/bin/cronjob_bandit23.sh
Copying passwordfile /etc/bandit_pass/bandit22 to /tmp/8169b67bd894ddbb4412f91573b38db3
```

So when i take a peek at `/tmp/8169b67bd894ddbb4412f91573b38db3`, i'm actually look at bandit22's password. 
Now that this script runs on bandit23 too, so the passwd for bandit 23 must be there too. 

```
bandit22@bandit:~$ ls /tmp/
ls: cannot open directory '/tmp/': Permission denied
```

Seems that we don't have permission for `/tmp/`. In that case, the passwd filename is reproduceable.

```
bandit22@bandit:~$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
0Zf11ioIjMVN551jX3CmStKLYqjk54Ga
```

## L24 cron + Bash Script

```bash
bandit23@bandit:~$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*; #all files, hidden files
do
    if [ "$i" != "." -a "$i" != ".." ]; # $i is not `.` or `..`
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)" # display file status
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i # send signal (-s) SIGKILL (9) to ./$i after ruuning ./$i for 60s
        fi
        rm -f ./$i
    fi
done
```

from man pages
```
#stat
    -f, --file-system
            display file system status instead of file status
    %U     user name of owner

#timeout
    -s, --signal=SIGNAL

            specify the signal to be sent on timeout;

            SIGNAL may be a name like 'HUP' or a number; see 'kill -l' for a list of signals
```

Seems that `/usr/bin/cronjob_bandit24.sh` can run scripts owned by user `bandit23` and delete them. Two possibilities comes to my mind:
1) Some script already in that dir has output some information about the password somewhere, and we gotta find a way to execute that script. This possibility the ruled out because every script seems to be deleted after cron runs the scheduled jobs, which means nothing absolutely is in that dir.
2) We can submit our script for it to be run by cron.
Turns out option 2) is the right way to go. I've tested vim-saving a script in `~/` and `/usr/bin/`, and none seemed to work. However, files could be actually saved after `:w` in `/var/spool/bandit24/foo/`. 

The next question is: what exactly should we put in this script. AFAIK, there's sure no sign of password in `/usr/bin/cronjob_bandit24.sh`. It's not like it could insert some piece of information somewhere during the execution. It struck me that we used to get out password from some `/tmp/` file. And rewind two levels, in Lv21->22, the password is given by
```
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
So, This is what we should do too.

```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/password24
```

And wait a minute... (i mean, literally waiting for 60s...) Oh wait. `cat` is just carried out immediately before a `-9` KILL signal is sent to it. There's no need to wait.

```
bandit23@bandit:/var/spool/bandit24/foo$ cat /tmp/password24
cat: /tmp/password24: No such file or directory
```

It ain't there! But not so fast. Remember last time when we need to operate in `/tmp/` and the wargame just asked us to use `mktemp`? Maybe we don't have permission to write in `/tmp/`.

```
bandit23@bandit:/var/spool/bandit24/foo$ echo can we write? > /tmp/canwe
bandit23@bandit:/var/spool/bandit24/foo$ cat /tmp/canwe
can we write?
```

Seems that we are indeed able to write. Seems that either this script is not run by cron, or /tmp/ is not a shared directory accross devices. 

So I recreated the script in /tmp/, used `chmod 755` to open its execution perssion for everyone, and `cp`'d the script to `foo/` again.
When I tried `cat /tmp/password24` again. It worked.

```
bandit23@bandit:~$ cat /tmp/password24
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8
```

## L25 Bruteforcing

> A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

Let's see how it works first.
```
bandit24@bandit:~$ nc localhost 30002
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80000
Wrong! Please enter the correct current password and pincode. Try again.

```

This obviously need some coding, it's just i'm not sure yet whether I should use bash or this could be done within `nc`.


Since `nc`'s TCP connection is just plaintext transmitting, `localhost:30002` is listening on whatever incoming connection and send
```
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
```
to the person who connects. After that, it's waiting for out STDIN to summit new information,
and when we hit `\n`, the message is sent.
From our point of view, in our endless rounds of trials, what we sent to `localhost:30002` could be cumulatively represented as a file
```txt
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80000\ngb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80001\ngb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80002\n....
```
Or in print format:
```
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80000
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80001
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80002
...
```
The solution is to send him this file that 

Let's test out hypothesis first:
```
bandit24@bandit:~$ cat /tmp/25try
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80000
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80001
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G80002

bandit24@bandit:~$ nc localhost 30002 < /tmp/25try
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
```
Great! `localhost:30002` is consuming our file as expected. Just that it's ignoring the first line, so our first line's gotta be a dummy.

<!-- Now we need some knowledge for echo's formatted print.
> [!tip]
> Recall that`{0001..9999}` is a bash [expansion](https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html).
> 
> For echo, `-e` enables interpretation of backslash escapes, e.g. making us able to print `\n`. -->

```bash
#!/bin/bash

PASSWORD24=gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8
echo dummy > /tmp/brute-force

for i in {0000..9999}; do
    echo ${PASSWORD24} $i >> /tmp/brute-force
done
```

And then feed this file `/tmp/brute-force` to the checker.

<!-- It seems that this method is not ideal, because the checker won't stop after receiving the correct answer, so the code is buried in the logs.

However, we can still redirect the output to a log file, and use `uniq` to search for the password line.

```
$nc localhost 30002 < /tmp/brute-force | tee /tmp/log

bandit24@bandit:~$ cat /tmp/log | sort | uniq -c
1 I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
  10002 Wrong! Please enter the correct current password and pincode. Try again.
``` -->

```
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Correct!
The password of user bandit25 is iCi86ttT4KSNe1armKiwbQNmB3YJP3q4
```

## L26 login shell, `/etc/passws`, `more`
This is the most tricky one I've encountered so far. I had to resort to an online step-by-step guide that employs a clever way of taking back control of the ssh connection using `more` and `vim` built-in CMDs.

First, problem detected:
```
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit25@bandit.labs.overthewire.org -p 2220
The authenticity of host '[bandit.labs.overthewire.org]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit25/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit25/.ssh/known_hosts).
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

!!! You are trying to log into this SSH server with a password on port 2220 from localhost.
!!! Connecting from localhost is blocked to conserve resources.
!!! Please log out and log in again.

bandit25@bandit.labs.overthewire.org: Permission denied (publickey).
bandit25@bandit:~$
```
After logging into bandit26, the ssh closes immediately after displaying a piece of welcome text. Clearly we are shut out before reaching `/bin/bash`.

> [!tip]
> Login shell information for users is stored at `/etc/passwd`, as well as other critical information.
> 
> ![](https://www.cyberciti.biz/media/ssb.images/uploaded_images/passwd-file-791527.png)
> 
> `username:password:UID:GID:userIDinfo:home_directory:command_or_shell`
>
> Since each line here starts with username, we can grep it by `cat /etc/passwd | grep "^$USER"`

```
bandit25@bandit:~$ cat /etc/passwd | grep "bandit26"
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
```

The login command for bandit26 is just `/usr/bin/showtext`. However, it appears that this `/etc/passwd` is something that only root user has access to. The same is applied to `/usr/bin/showtext` too.

```
bandit25@bandit:~$ ls -alt  /etc/passwd
-rw-r--r-- 1 root root 6283 Sep 19 07:09 /etc/passwd

bandit25@bandit:~$ ls -alt /usr/bin/showtext
-rwxr-xr-x 1 root root 58 Sep 19 07:08 /usr/bin/showtext
```

Now that we know `/usr/bin/showtext` is going to be executed anyway. Let's see what strings could be pulled on the exact commands `/usr/bin/showtext` is going to tun.

```
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

exec more ~/text.txt
exit 0
```

I admit that starting from here I'm stuck. So the following solution is rephrased from what i've gathered from online.

> [!tip]
> `more` is a lesser (but no `less`er) version of the pager `less` that offers similar functionalities. 
> 
> As some of you have already noticed, when using `bat` to print out files, if the file's not short enough, bat will redirect the STDOUT to your `$PAGER` which is often `less`. So from here you can access the built-in commands of `less`. 
> 
> Well, `more` does "more or less" the same thing. When you shrink your terminal window to a certain point, `more` decides that the welcome text is too long for direct printing, and would rather redirect the STDOUT to `more`'s pager interface, where we can actually pull some more strings. 



Let's see what CMD can benefit us in this situation. After a quit browsing after hitting `?`, the most promising ones are:
```
v                       Start up '/usr/bin/vi' at current line
!<cmd> or :!<cmd>       Execute <cmd> in a subshell
```

`v` takes us to `$EDITOR` which is usually `vim` by default in today's linux machines, while `!<cmd>` executes `<cmd>`. I tried `!/bin/sh` but nothing happened. So press `v` and we are in `vim`.