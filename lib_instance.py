from hashy import attribs
from hashy import * 
class IntError(Exception):
	pass 
"""
The lib is Hashy to be accessed from many places.
It is easy to be used."""
class invoke__(object):
	def __init__(self, **kwargs:str):
		if "downloaddepth" in kwargs and type(kwargs["downloaddepth"]) != int:
			raise IntError("Required type of 'int' for downloaddepth, not '%s'!"%(type(kwargs["downloaddepth"])))
		elif "cbc" in kwargs and type(kwargs["cbc"]) != bool and type(kwargs["cbc"]) != str:
			raise IntError("Required type of 'bool' or 'string', not '%s'!"%(type(kwargs["cbc"])))
		elif "gcm" in kwargs and type(kwargs["gcm"]) != bool and type(kwargs["gcm"]) != str:
			raise IntError("Required type of 'bool' or 'string', not '%s'!"%(type(kwargs["gcm"])))
		elif "automatew" in kwargs and type(kwargs["automatew"]) != str:
			raise IntError("Required type of 'string', not '%s'!"%(type(kwargs["automatew"])))
		elif "hashsum" in kwargs and type(kwargs["hashsum"]) != str and type(kwargs["hashsum"]) != bool and type(kwargs["hashsum"]) != list and type(kwargs["hashsum"]) != tuple:
			raise IntError("Required type of 'string', 'bool' or 'list', not '%s'!"%(type(kwargs["hashsum"])))
		elif "algorithm" in kwargs and type(kwargs["algorithm"]) != str and type(kwargs["algorithm"]) != bool:
			raise IntError("Required type of 'string' or 'bool', not '%s'!"%(type(kwargs["algorithm"])))
		elif "password" in kwargs and type(kwargs["password"]) != str and type(kwargs["password"]) != bool:
			raise IntError("Required type of 'string' or 'bool' not '%s'!"%(type(kwargs["password"])))
		elif "limit" in kwargs and type(kwargs["limit"]) != int:
			raise IntError("Required type of 'int' not '%s'!"%(type(kwargs["limit"])))
		elif "cipher_keys" in kwargs and type(kwargs["cipher_keys"]) != str:
			raise IntError("Required type of 'string' not '%s'!"%(type(kwargs["cipher_keys"])))
		elif "ciphers" in kwargs and type(kwargs["ciphers"]) != str:
			raise IntError("Required type of 'string' or a 'bool' not '%s'!"%(type(kwargs["ciphers"])))
		args = {}
		for items in kwargs:
			args[items] = kwargs[items]
		if "hashsum" in args and "algorithm" not in args:
			raise IntError("Cannot run the instance, without having defined algorithm or vice versa.")
		if "limit" not in args:
			args["limit"] = 100
		if "automatew" not in args:
			args["automatew"] = "danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt"
		if "downloaddepth" not in args:
			args["downloaddepth"] = 40
		if "hashsum" not in args:
			args["hashsum"] = None
		if "cbc" not in args:
			args["cbc"] = None
		if "gcm" not in args:
			args["gcm"] = None
		if "ciphers" not in args:
			args["ciphers"] = None
		if "cipher_keys" not in args:
			args["cipher_keys"] = None
		if "hashsum" in args and args["hashsum"] != None:
			if type(args["hashsum"]) == list and len(args["hashsum"][0]) != len(attribs.return_sample(args["algorithm"])):
				raise IntError("Provided string doesn't meet %s requirements."%(args["algorithm"].upper()))
			else:
				if len(attribs.return_sample(args["algorithm"])) != len(args["hashsum"]):
					raise IntError("Provided string doesn't meet MD5 requirements.")
			self.file_ = attribs.get_words(limit=args["limit"], origin=args["automatew"], depth=args["downloaddepth"])
			self.mode = "hash_s"
			self.sum = args["hashsum"]
			self.list = self.file_
			self.auto = args["automatew"]
			self.algo = args["algorithm"]
		elif "cbc" in args and args["cbc"] != None:
			if "cipher_keys" not in args:
				raise NameError("Cannot run the instance, without having defined cipher_keys or vice versa. ")
			self.file_ = attribs.get_words(limit=args["limit"], origin=args["automatew"], depth=args["downloaddepth"])
			self.mode = "cbc"
			self.sum = args["cbc"]
			self.list = self.file_
			self.cipher_keys = args["cipher_keys"]
		elif "gcm" in args and args["gcm"] != None:
			if "cipher_keys" not in args:
				raise NameError("Cannot run the instance, without having defined cipher_keys or vice versa. ")
			self.file_ = attribs.get_words(limit=args["limit"], origin=args["automatew"], depth=args["downloaddepth"])
			self.mode = "gcm"
			self.sum = args["gcm"]
			self.list = self.file_
			self.cipher_keys = args["cipher_keys"]
		elif "ciphers" in args and args["ciphers"] != None:
			if "cipher_keys" not in args or "algorithm" not in args:
				raise NameError("Cannot run the instance, without having defined cipher_keys and algorithm or vice versa.")
			self.file_ = attribs.get_words(limit=args["limit"], origin=args["automatew"], depth=args["downloaddepth"])
			self.mode = "ciphers"
			self.sum = args["ciphers"]
			self.enmsg = args["hashsum"]
			self.list = self.file_
			self.cipher_keys = args["cipher_keys"]
	def launch_crack(self, **kwargs):
		if self.mode == "cbc":
			if type(self.sum) == list or type(self.sum) == tuple:
				for sums in self.sum:
					output_ = StartCBC(list=self.file_, sum=sums, cipher_keys=self.cipher_keys)
			else:
				output_ = StartCBC(list=self.file_, sum=self.sum, cipher_keys=self.cipher_keys)
		elif self.mode == "gcm":
			if type(self.sum) == list or type(self.sum) == tuple:
				for sums in self.sum:
					output_ = StartGCM(list=self.file_, sum=sums, cipher_keys=self.cipher_keys)
			else:
				output_ = StartGCM(list=self.file_, sum=self.sum, cipher_keys=self.cipher_keys)
		elif self.mode == "hash_s":
			if type(self.sum) == list or type(self.sum) == tuple:
				for items in self.sum:
					attribs(passwords=self.list, hashsum=items, algorithm=self.algo, view=None, wr=self.auto)
			else:
				attribs(passwords=self.list, hashsum=self.sum, algorithm=self.algo, view=None, wr=self.auto)
		elif self.mode == "ciphers":
			x_ = FormList(target=self.list, list_=self.cipher_keys, times=self.sum.replace("3", ""))
			if type(self.enmsg) == list or type(self.enmsg) == tuple:
				for items in self.enmsg.split(","):
					attribs(passwords=x_, hashsum=items, cipher_keys=self.cipher_keys)
			else:
				attribs(passwords=x_, hashsum=self.enmsg, cipher_keys=self.cipher_keys)






