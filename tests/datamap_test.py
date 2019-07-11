import pytest
from oysterpy import datamap, encryption, iota_utils
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
	address = iota_utils.bytesToTrytes(hashlib.sha384(datamap.get_offset_hash(starting_hash, random_index)).digest())[0:81]
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