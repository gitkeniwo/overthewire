# L0
ssh bandit0@bandit.labs.overthewire.org -p 2220

# L1
Congratulations on your first steps into the bandit game!!
Please make sure you have read the rules at https://overthewire.org/rules/
If you are following a course, workshop, walkthrough or other educational activity,
please inform the instructor about the rules as well and encourage them to
contribute to the OverTheWire community so we can keep these games free!

The password you are looking for is: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If

# L2
ok this one is trick. So basically if your filename is just a hyphen `-`, you use double hyphen to escape it (mark the end of flags and options), as in `vim -- -` or `cat ./-`. However, somehow `cat -- -` didn't work for me.

263JGJPfgU6LtdEvgfWU1XP5yac29mFx

# L3 
Use backslash to escape. MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx

# L4
File is hidden. Use `ls -a`. 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ

# L5
`file inhere/-file0{0..9}` Use `file` cmd + brace expansion.

```bash
bandit4@bandit:~$ cat inhere/-file07
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```
# L6
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

# L7

