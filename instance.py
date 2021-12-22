from lib_instance import *
bob_ = invoke__(cbc="dGVzdA==", cipher_keys="lol.txt", limit=100)
bob_.launch_crack()
bobs_ = invoke__(hashsum="a70f9e38ff015afaa9ab0aacabee2e13", algorithm="md5")
bobs_.launch_crack()
bobss_ = invoke__(gcm="dGVzdA==", cipher_keys="lol.txt", limit=100)
bobss_.launch_crack()