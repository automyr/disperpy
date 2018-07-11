# coding=utf-8

#using pycryptodome and PyNaCl, which is a Python binding to libsodium
import string
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA3_256, SHA3_512
from Crypto.Cipher import AES
from iota import TryteString
import nacl.signing
import nacl.encoding

def getPrivateHandle():
	"""Generates a random bytestring to use as the private handle.
	
	Returns:
		bytes -- 48 bytes long
	"""

	return get_random_bytes(48)

def getEncryptionKey(privatehandle):
	"""Wrapper method for sha3_256.
	
	Arguments:
		privatehandle {bytes} -- Can be any bytes object, but should be the output of getPrivateHandle().
	
	Returns:
		bytes -- sha3_256 digest of the input.
	"""

	return SHA3_256.new(privatehandle).digest()

def getKeypair(privatehandle):
	"""Uses the ed25519 curve to generate a signing/verifying key pair.
	
	Arguments:
		privatehandle {bytes} -- Can be any bytes object, but should be the output of getPrivateHandle().
	
	Returns:
		bytes -- Signing key in bytes.
		bytes -- Verifying key in bytes.
	"""

	seed = SHA3_256.new(privatehandle).digest()

	signing_key = nacl.signing.SigningKey(seed)
	verifying_key = signing_key.verify_key

	sk_bytes = signing_key.encode()
	vk_bytes = verifying_key.encode()

	return sk_bytes, vk_bytes

def encryptAES(data, encryptionkey):
	"""Encrypts data using AES in GCM mode.
	
	Arguments:
		data {bytes} -- Useful data that will go inside a chunk. Max length: 1013 bytes.
		encryptionkey {bytes} -- Encryption key presumably coming from getEncryptionKey().
	
	Returns:
		bytes -- Encrypted data.
		bytes -- Nonce, also called iv. Necessary to decrypt the data. 16 bytes long.
		bytes -- MAC tag. Useful to verify data integrity. 16 bytes long.
	"""

	cipher = AES.new(encryptionkey, AES.MODE_GCM)
	nonce = cipher.nonce
	
	ciphertext, tag = cipher.encrypt_and_digest(data)
	
	return ciphertext, nonce, tag

def decryptAES(chunk, encryptionkey): 
	"""Decrypts data using AES in GCM mode.
	
	Arguments:
		chunk {bytes} -- Encrypted data. Must contain the nonce as the trailing 16 bytes.
		encryptionkey {bytes} -- Encryption key used to encrypt the data.
	
	Returns:
		bytes -- Decrypted data.
	"""

	nonce = chunk[-16:] #nonce is 16 bytes
	ciphertext = chunk[0:-16]

	cipher = AES.new(encryptionkey, AES.MODE_GCM, nonce=nonce)
	plaindata = cipher.decrypt(ciphertext)
	
	return plaindata

def decryptAndVerifyAES(chunk, encryptionkey):
	"""Same as decryptAES, but this method also verifies data integrity using the MAC tag.
	
	Arguments:
		chunk {bytes} -- Encrypted data. Must have the nonce and tag as the trailing bytes. Last 16 must be the tag, and the 16 bytes before tag have to be the nonce.
		encryptionkey {[bytes]} -- Encryption key used to encrypt the data.
	
	Returns:
		bytes -- Decrypted data.
	"""

	tag = chunk[-16:]
	nonce = chunk[-32:-16]
	ciphertext = chunk[0:-32]

	cipher = AES.new(encryptionkey, AES.MODE_GCM, nonce=nonce)
	plaindata = cipher.decrypt_and_verify(ciphertext, tag)
	
	return plaindata

def signChunk(chunk, signing_key):
	"""Uses the signing key and the ed25519 curve to sign a binary object.
	
	Arguments:
		chunk {bytes} -- Everything that will go inside the iota tx, except for the signature. Max length: 1029 bytes.
		signing_key {bytes} -- Signing key in bytes.
	
	Returns:
		bytes -- 64 bytes long signature of the input.
	"""

	sk = nacl.signing.SigningKey(signing_key) #this is pretty inefficient since we're initializing a signing object for every single chunk, even if the same object could be used for all of them
	signed_chunk_object = sk.sign(chunk)

	return signed_chunk_object.signature

def verifyChunk(chunk, signature, verifying_key_hex):
	"""Checks if the signature for chunk is valid using the ed25519 curve.
	
	Arguments:
		chunk {bytes} -- Everything inside a tx except for the signature.
		signature {bytes} -- 64 bytes long signature.
		verifying_key_hex {str} -- Verifying key in hex. 

	Raises:
		nacl.exceptions.BadSignatureError -- If the signature doesn't match correctly with the verifying key.
	"""	

	#TODO: Change this method to accept a (nacl.signing.VerifyKey()) object in order to avoid creating a new one for every chunk
	#? Makes sense to leave the verifying key in hex here because this function will most likely be triggered when downloading, which means the verifying key will come from the public handle, which is in hex.
	
	vk = nacl.signing.VerifyKey(verifying_key_hex, encoder=nacl.encoding.HexEncoder)
	vk.verify(chunk, signature)

def splitChunkAndSignature(chunk):
	"""Simple wrapper method to separate the signature from the rest of the chunk.
	
	Arguments:
		chunk {bytes} -- Everything inside the message field of an IOTA tx.
	
	Returns:
		bytes -- Everything except the trailing 64 bytes.
		bytes -- 64 bytes long signature.
	"""

	signature = chunk[-64:]
	data = chunk[0:-64]
	
	return data, signature

def stripTag(chunk):
	"""Strips the tag and returns the rest of the chunk. Only useful in password-protected uploads.
	
	Arguments:
		chunk {bytes} -- Everything inside the message field of an IOTA tx, except for the signature.
	
	Returns:
		[bytes] -- Chunk without the tag.
	"""

	#tag = chunk[-16:]
	chunkAndNonce = chunk[:-16]
	return chunkAndNonce

# Everything under this line should be moved to some iota utils module in the future ----------------------------------------------------------

def bytesToTrytes(bytestring):
	"""
	Simple wrapper for iota.TryteString conversion method
	"""
	return TryteString.from_bytes(bytestring)

def trytesToBytes(trytestring):
	"""
	Simple wrapper for iota.TryteString conversion method
	"""
	return TryteString.encode(trytestring)