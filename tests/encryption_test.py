import pytest
from oysterpy import encryption

class TestPrivateHandle(object):
	handle = encryption.getPrivateHandle()

	def test_private_handle_length_is_48(self):
		assert len(self.handle) == 48

	def test_private_handle_is_bytes(self):
		assert type(self.handle) is bytes

class TestEd25519Keys(object):
	signing_key, verifying_key = encryption.getKeypair(encryption.getPrivateHandle())

	def test_keys_are_bytes(self):
		assert type(self.signing_key) is bytes
		assert type(self.verifying_key) is bytes

	def test_signing_key_is_32_bytes(self):
		assert len(self.signing_key) == 32

class TestChunkEncryption(object):
	#setup
	uncrypted_chunk = b"THIS COULD BE ANYTHING"
	private_handle = encryption.getPrivateHandle()
	signing_key, verifying_key = encryption.getKeypair(private_handle)
	encryption_key = encryption.getEncryptionKey(private_handle)

	#actually encrypt the chunk
	encrypted_chunk, nonce, tag = encryption.encryptAES(uncrypted_chunk, encryption_key)

	def test_length_encrypted_is_equal_to_length_uncrypted(self):
		assert len(self.encrypted_chunk) == len(self.uncrypted_chunk)
	
	def test_nonce_and_tag_lengths_are_16_bytes(self):
		assert len(self.nonce) == 16 and type(self.nonce) is bytes
		assert len(self.tag) == 16 and type(self.tag) is bytes

	def test_decryption_without_verification(self):
		completed_chunk = b''.join([self.encrypted_chunk, self.nonce])
		decrypted_chunk = encryption.decryptAES(completed_chunk, self.encryption_key)
		assert decrypted_chunk == self.uncrypted_chunk

	def test_decryption_with_verification(self):
		completed_chunk = b''.join([self.encrypted_chunk, self.nonce, self.tag])
		decrypted_chunk = encryption.decryptAndVerifyAES(completed_chunk, self.encryption_key)
		assert decrypted_chunk == self.uncrypted_chunk

	def test_chunk_signing_and_validation(self):
		signature = encryption.signChunk(self.uncrypted_chunk, self.signing_key)
		assert len(signature) == 64
		assert type(signature) is bytes
		
		encryption.verifyChunk(self.uncrypted_chunk, signature, self.verifying_key.hex())

