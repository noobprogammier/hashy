# Update 12.23.2021 v.1.
- Update \. New stuff added, like rules, automation, identification.
- Rules are working in a specific way. From there you can set how long the words to be, for instance: **--rule set=rule,length=8** (exclude any kind of space identations!). 
* What about the automations.
  Automations are two modes - "automode" and "crack", the automode declears everything on its best, while the crack option will only try to find the identification of the actual algorithm.
  In the crack option all you have to do is only to specify the hash value/sum.
- --identify option is especially to find the algorithm of the specified hash. 


#### How to use it.
- Syntax for rule set. <br>
 **python3 hashy.py -hs <!hash-string!> --rule set=bigrand,length=8 --limit 5000**.
  ![image](https://user-images.githubusercontent.com/73231678/147237463-6ce16e40-942b-4e0a-bbca-4a296a692bf4.png)
- Syntax for crack. <br>
 **python3 hashy.py --crack <!hash-string!> --limit 5000 -at <!some-wordlist!>**
