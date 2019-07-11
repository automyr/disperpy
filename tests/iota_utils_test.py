import pytest
from oysterpy import iota_utils, encryption

class TestTryteConversion(object):
	message = encryption.getPrivateHandle() #could use anything here, so let's use a random bytestring
	trytes = iota_utils.bytesToTrytes(message)

	def test_bytes_to_trytes_to_bytes(self):
		byte_string = iota_utils.trytesToBytes(self.trytes)
		
		assert byte_string == self.message

	def test_there_are_2_trytes_per_byte(self):
		assert (len(self.message) * 2) == len(self.trytes)