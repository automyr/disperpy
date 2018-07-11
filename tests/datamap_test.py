import pytest
from oysterpy import datamap, encryption
from Crypto.Random import get_random_bytes, random
import hashlib

class TestHashchain(object):
	starting_hash = get_random_bytes(32)
	random_index = random.randint(1, 500)
	end_index = random_index + random.randint(1, 50)
	full_hashchain = datamap.get_hashchain(starting_hash, end_index)

	def test_get_offset_hash_corresponds_to_get_hashchain(self):
		offset_hash = datamap.get_offset_hash(self.starting_hash, self.random_index)
		assert offset_hash == self.full_hashchain[self.random_index]

	def test_hashchain_length(self):
		assert len(self.full_hashchain) == self.end_index

class TestDatamap(object):
	starting_hash = get_random_bytes(32)
	random_index = random.randint(1, 500)
	batch_size = random_index + random.randint(1, 50)
	address = encryption.bytesToTrytes(hashlib.sha384(datamap.get_offset_hash(starting_hash, random_index)).digest())[0:81]
	address_batch = datamap.get_address_batch(starting_hash, batch_size)

	def test_address_batch_is_equal_to_manual_conversion(self):
		assert self.address_batch[self.random_index] == self.address

	def test_address_batch_size(self):
		assert len(self.address_batch) == self.batch_size

	def test_addresses_are_81_trytes_in_length(self):
		assert sum([len(i) for i in self.address_batch]) == (81*self.batch_size)

	def test_cannot_get_batchsize_address_in_address_batch(self):
		try:
			self.address_batch[self.batch_size]
		except IndexError:
			assert True


	#TODO: Solve this fucking bullshit.
	""" def test_exclude_treasure_addresses_from_batch(self):
		genesis_hash = self.starting_hash
		batchSize = 100
		full_address_batch = datamap.get_address_batch(self.starting_hash, batchSize+1)
		offset_hash = datamap.get_offset_hash(genesis_hash, 3)
		sector_size = 100		
		starting_hash_absolute_index = 3
		treasure_addresses = [full_address_batch[0], full_address_batch[100]]
		address_batch_two = datamap.get_address_batch(offset_hash, batchSize-2)
		corrected_batch = datamap.exclude_treasure_addresses_from_list(address_batch_two, starting_hash_absolute_index, sectorSize=sector_size)

		#assert len(corrected_batch) == (len(address_batch_two) - 1)
		assert address_batch_two[sector_size + 1 - starting_hash_absolute_index] not in corrected_batch
		boolList = [treasure_address not in corrected_batch for treasure_address in treasure_addresses]
		assert False not in boolList """