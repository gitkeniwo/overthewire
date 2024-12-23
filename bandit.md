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

