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
> `.tar.gz` is the defacto archive & compression standard in CLI.
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
> Does not support key authentication or secured file transfer. 
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
> SSL/TLS: A cryptographic protocal tp provide security for the *transport layer* in the OSI model.
> OpenSSL: A library of the TLS protocal. Is the world's most widely used implementation.
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
> `nmap <ip>` by default does not do a full scan. It only scans the most well-known hosts and ports that aren't on that list is omitted.
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

## L18 diff
