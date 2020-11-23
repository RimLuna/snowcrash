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