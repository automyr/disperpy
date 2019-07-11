# coding=utf-8
import hashlib
from iota import TryteString

def get_hashchain(startingHash, n):
	"""
	Returns a list with `n` hashes (as bytes) down the main sha256 hashchain, where starting hash is the first hash in the list. 
	startingHash must be of type bytes and number must be an int.
	"""
	hashchain = [startingHash]
	nextHash = startingHash
	for _ in range(n-1):
		nextHash = hashlib.sha256(nextHash).digest()
		hashchain.append(nextHash)
	return hashchain

def get_offset_hash(startingHash, n):
	"""Returns hash `n` (as bytes) in a hashchain where `startingHash` is hash (0).
	
	Arguments:
		startingHash {bytes} -- Self-explanatory
		n {int} -- Self-explanatory
	
	Returns:
		bytes -- Hash after `n` hashchain iterations. If `n=0`, this is `startingHash`.
	"""

	nextHash = startingHash
	for _ in range(n):
		nextHash = hashlib.sha256(nextHash).digest()
	return nextHash

def createDatamapGenerator(startingHash, n=None, offset=None):
	"""Creates a generator that yields the iota addresses for each iteration, starting with `startingHash` up to `n` iterations.
	
	Arguments:
		startingHash {bytes} -- Self-explanatory.
		n {int} -- Max number of iterations. If None, there's no max number of iterations.

	Keyword Arguments:
		offset {int} -- Number of hashes to skip before returning the generator. Ex: startingHash is the genHash, but you want the first address in the generator to be the 3rd in the datamap, so the offset must be 2.

	Yields:
		iota.types.TryteString -- Iota address corresponding to the current hash.
	"""
	nextHash = startingHash
	if offset is not None:
		for _ in range(offset):
			nextHash = hashlib.sha256(nextHash).digest()
	if n is None:
		while True:
			obfuscatedhash = hashlib.sha384(nextHash).digest()
			address = TryteString.from_bytes(obfuscatedhash)[0:81]
			nextHash = hashlib.sha256(nextHash).digest()
			yield address
	else:
		for _ in range(n):
			obfuscatedhash = hashlib.sha384(nextHash).digest()
			address = TryteString.from_bytes(obfuscatedhash)[0:81]
			nextHash = hashlib.sha256(nextHash).digest()
			yield address

def get_address_batch(startingHash, n):
	"""Returns a list with `n`addresses where the first one corresponds to the `startingHash`

	Arguments:
		startingHash {bytes} -- Self-explanatory.
		n {int} -- Number of addresses to include in the list.
	
	Returns:
		list -- IOTA addresses corresponding to each hash in the datamap.
	"""

	gen = createDatamapGenerator(startingHash, n)
	addressList = [address for address in gen]

	return addressList