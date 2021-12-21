# hashy
Hashy is a tool for recovering encrypted passwords in different versions of the hash structure. You can also use this tool for encrypted messages in AES versions, other ciphers will be entered soon. Please follow me to be notified!

##### Supported ciphers: sha-512, sha-224, blake2b, blake2s, shake_128, sha3_512, sha3-384, sha3-256, shake_256, shake_128, md5, sha1, sha256, sha512, aes-cbc(128), aes-gcm(256). 

More about it:
tl;dr
It is a fast and easy to use program in order to recover a data for which you forgot the value. For instance, the idea started from my service. . . I had a problem and I forgot my password, and probably that happened for maybe 20th time, so I decided to make a password recovery tool. You can also check my service on - "http://hnoob.redirectme.net". 
Syntax is pretty easy.
Also **DO NOT USE IT** for any illegal activities!

Example syntax:
python3 hashy.py -cbc Ay8SUL9owCW1pn4tUlmDyQ== -at jeanphorn/wordlist/master/passlist.txt,duyet/bruteforce-database/master/1000000-password-seclists.txt -ck lol.txt -l 10000 -dd 200
![image](https://user-images.githubusercontent.com/73231678/146905123-eadf8ffc-7aba-41d1-890f-e1f3464fbc40.png)

You don't have to specify always a path to download a file, basically I made it to download rockyou.txt as a default path. Thanks to *Daniel Miessler* && *Jean Phorn* for providing such a good wordlists. 

Different syntax: 
python3 hashy.py -a md5 -hs a70f9e38ff015afaa9ab0aacabee2e13 

||

python3 hashy.py -a md5 a70f9e38ff015afaa9ab0aacabee2e13 -at jeanphorn/wordlist/master/passlist.txt,duyet/bruteforce-database/master/1000000-password-seclists.txt 

"-dd" argument is new and I added it in order to set a specific value for the downloading times in order to not halt the program. Perhaps, I might set a timeout instead, but we'll see in the close future. 

Different syntax for complex usage:
python3 hash.py -a md5 -cb 2.3 -ck something.txt -hs <some value with multiple ciphers>

Again, do not use it for illegal purposes!

Please respect my work!
<br>
<br>
More explainations, about different arguments:
  <br>
  <br>
 -dd  - To set the downloading times, for instance set it to 100 and It'll wait for packets 100-th times. 
  <br>
  -cbc - Is for brute force for AES-128 enciphered, encrypted messages/texts. The argument should be encoded in base 64, I made it to base 64 in order to improve comparison.
  <br>
  -at - Is to set a specific wordlist argument by providing a specific Github path and to load the wordlists from there. 
  <br>
  -hs - Is for the hashsum, which is really important in many of the options.
  <br>
  -a  - Is the algorithm option where you can specify, which hash algorithm you want to use. 
  <br>
  -p - Is for passwordlist argument, mostly if you don't want to download lists at all.
  <br>
  -l - Is to set a limit for the passwords that will be used.
  <br>
  -v - Is to view the cracked password, when the password is found, this option should not be used, I mean It'll not do anything in "-cbc" mode, because I haven't make it do it.
  <br>
  -cb - Is to specify the encryption sequence, which can be - aes(cbc) => aes(gcm) => hash and etc. This option should be used carefully. "Usage example: -cb 2.1.2.1.3". The decimal three should be always last, but I should fix it to read it. 
  <br>
  -ck - Is to specify a file with words inside (the key, vector arguments), of course seperated by semicolons, for instance - "akfkafkakfakaaaa:akfkafkakfakaaaa". 
  <br>
  <br>
  <br>
  <br>
Usage for md5: 
  <br>
  ![image](https://user-images.githubusercontent.com/73231678/146908938-72d828e4-9253-4269-a1a9-8777a2972155.png)<br>
  python3 hashy.py -a md5 -hs a70f9e38ff015afaa9ab0aacabee2e13
  <br>
  <br>
Usage for cbc:
  <br>
  ![image](https://user-images.githubusercontent.com/73231678/146909018-826880bb-9dfa-498b-861a-2927b510166f.png) <br>
  python3 hashy.py -cbc Ay8SUL9owCW1pn4tUlmDyQ== -ck lol.txt
  <br>
  <br>
Usage for sequence:
  <br>
  python3 hash.py -a md5 -hs <some encrypted value of sequence by other ciphers> -cb 1.2.3 -ck something.txt -v f 
  <br>
  <br>
Thank you for your patience! ❤️❤️
  
