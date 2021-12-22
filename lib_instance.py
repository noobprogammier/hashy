from hashy import attribs
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
		if "hashsum" in args:
			if type(args["hashsum"]) == list and len(args["hashsum"][0]) != len(attribs.return_sample(args["algorithm"])):
				raise IntError("Provided string doesn't meet %s requirements."%(args["algorithm"].upper()))
			else:
				if len(attribs.return_sample(args["algorithm"])) != len(args["hashsum"]):
					raise IntError("Provided string doesn't meet MD5 requirements.")
			self.file_ = attribs.get_words(limit=args["limit"], origin=args["automatew"], depth=args["downloaddepth"])
			if type(args["hashsum"]) == list or type(args["hashsum"]) == tuple:
				for hashes in args["hashsum"]:
					attribs(passwords=self.file_, hashsum=hashes, algorithm=args["algorithm"], view=None, wr=args["automatew"])
			attribs(passwords=self.file_, hashsum=args["hashsum"], algorithm=args["algorithm"], view=None, wr=args["automatew"])

