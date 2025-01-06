# Leviathan

## L0-L1

```
leviathan0@gibson:~$ ls -alt /etc/leviathan_pass
total 48
drwxr-xr-x 124 root       root       12288 Dec 21 16:42 ..
drwxr-xr-x   2 root       root        4096 Sep 19 07:07 .
-r--------   1 leviathan7 leviathan7    11 Sep 19 07:07 leviathan7
-r--------   1 leviathan6 leviathan6    11 Sep 19 07:07 leviathan6
-r--------   1 leviathan5 leviathan5    11 Sep 19 07:07 leviathan5
-r--------   1 leviathan4 leviathan4    11 Sep 19 07:07 leviathan4
-r--------   1 leviathan3 leviathan3    11 Sep 19 07:07 leviathan3
-r--------   1 leviathan2 leviathan2    11 Sep 19 07:07 leviathan2
-r--------   1 leviathan1 leviathan1    11 Sep 19 07:07 leviathan1
-r--------   1 leviathan0 leviathan0    11 Sep 19 07:07 leviathan0
leviathan0@gibson:~$ cat /etc/leviathan_pass/leviathan0
leviathan0
leviathan0@gibson:~$ cat /etc/leviathan_pass/leviathan1
cat: /etc/leviathan_pass/leviathan1: Permission denied
```

Let's check hidden files

```
leviathan0@gibson:~$ ls -alt
total 24
drwxr-xr-x 83 root       root       4096 Sep 19 07:09 ..
drwxr-xr-x  3 root       root       4096 Sep 19 07:07 .
drwxr-x---  2 leviathan1 leviathan0 4096 Sep 19 07:07 .backup
-rw-r--r--  1 root       root        220 Mar 31  2024 .bash_logout
-rw-r--r--  1 root       root       3771 Mar 31  2024 .bashrc
-rw-r--r--  1 root       root        807 Mar 31  2024 .profile

leviathan0@gibson:~$ cat .backup/bookmarks.html | grep leviathan
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is 3QJ3TgzHDq" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```

3QJ3TgzHDq

## L1-L2

```
leviathan1@gibson:~$ ltrace ./check
__libc_start_main(0x80490ed, 1, 0xffffd494, 0 <unfinished ...>
printf("password: ")                                                                     = 10
getchar(0, 0, 0x786573, 0x646f67password: sawjiudaiu
)                                                        = 115
getchar(0, 115, 0x786573, 0x646f67)                                                      = 97
getchar(0, 0x6173, 0x786573, 0x646f67)                                                   = 119
strcmp("saw", "sex")                                                                     = -1
puts("Wrong password, Good Bye ..."Wrong password, Good Bye ...
)                                                     = 29
+++ exited (status 0) +++

leviathan2@gibson:~$ cat /etc/leviathan_pass/leviathan2
NsN1HwFoyN
```
