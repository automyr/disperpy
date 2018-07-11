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

def createDatamapGenerator(startingHash, n):
	"""Creates a generator that yields the iota addresses for each iteration, starting with `startingHash` up to `n` iterations.
	
	Arguments:
		startingHash {bytes} -- Self-explanatory.
		n {int} -- Max number of iterations.

	Yields:
		iota.types.TryteString -- Iota address corresponding to the current hash.
	"""
	nextHash = startingHash
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

def exclude_treasure_addresses_from_list(addressList, startingHash_abs_index, sectorSize=1000000):
	"""Returns a list without the addresses corresponding to treasures, to make downloading files easier.
	
	Arguments:
		addressList {list} -- Output of get_address_batch(). List of trytestrings representing IOTA addresses.
		startingHash_abs_index {int} -- Absolute index of the startingHash of the batch in the entire datamap. Ex: the abs_index of the genesis hash is 0.
	
	Keyword Arguments:
		sectorSize {int} -- Self-explanatory. This is more for testing than anything else, since sector size is fixed in rev2 (default: {1000000})
	
	Returns:
		list -- addressList without the addresses corresponding to treasures.
	"""
	#! Doesn't really work like you'd expect it to. Needs some extra work and testing.
	# TODO: Solve this.
	
	to_exclude = set()
	for i in range(startingHash_abs_index, startingHash_abs_index+len(addressList)-1):
		if i % sectorSize == 0:
			relative_idx = i - startingHash_abs_index
			to_exclude.add(relative_idx)

	correctedAddressList = [address for i, address in enumerate(addressList) if i not in to_exclude]

	return correctedAddressList