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

> [!tip]
> `nc` or netcat. TCP/UDP工具，构建简单的TCP/HTTP服务，网络守护进程测试 etc.
> - Handles TCP and UDP connections. 
> - It can open TCP connections, send UDP packets, listen on arbitrary TCP and UDP ports, do port scanning, and deal with both IPv4 and IPv6.  
> - Unlike telnet(1), nc scripts nicely, and separates error messages onto standard error instead of sending them to standard output, as telnet(1) does with some.

## L16 SSL/TLS


## L17 Port Scanning

`nmap <ip>` carries out a basic port scanning process.

