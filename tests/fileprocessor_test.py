import pytest
import os
from oysterpy import fileprocessor, datamap, encryption
from Crypto.Random import get_random_bytes
import nacl.exceptions

def initialize_file(path, sizeinkb=10):
	testfile_content = get_random_bytes(1024*sizeinkb)
	f = open(path, "wb")
	f.write(testfile_content)
	f.close()

def cleanup():
	ldir = os.listdir()
	for filename in ldir:
		if "testfile" in filename:
			os.remove(filename)

def read_binary_file(path):
	with open(path, "rb") as f:
		fr = f.read()
	return fr

class TestChunkingFunctionsWithoutPassword(object):
	_path = "testfile_4"
	initialize_file(_path)
	privateHandle = encryption.getPrivateHandle()
	_, genesisHash = encryption.getKeypair(privateHandle)

	raw_file = read_binary_file(_path)
	chunkList = fileprocessor.fileToChunks(_path, privateHandle, genesisHash)

	def test_verify_chunk_signatures(self):
		_, verifyingKey = encryption.getKeypair(self.privateHandle)
		address_gen = datamap.createDatamapGenerator(verifyingKey, len(self.chunkList) + 1)
		for chunk in self.chunkList: 
			datachunk, signature = encryption.splitChunkAndSignature(chunk)
			address = encryption.trytesToBytes(next(address_gen)[:-1])
			encryption.verifyChunk(datachunk + address, signature, verifyingKey.hex())
		assert True
	
	def test_decrypting_chunked_file(self):
		encryptionKey = encryption.getEncryptionKey(self.privateHandle)
		decrypted_path = self._path+"_decrypted"
		assert fileprocessor.chunksToFile(self.chunkList, encryptionKey, decrypted_path)
		
		decrypted_file = read_binary_file(decrypted_path)
		assert decrypted_file == self.raw_file
	
	#! Put functions here
			
	def test_clean_file(self):
		cleanup()

class TestChunkingFunctionsWithPassword(object):
	_path = "testfile_5"
	pwd = "oysterpy"
	initialize_file(_path)
	privateHandle = encryption.getPrivateHandle()
	_, genesisHash = encryption.getKeypair(privateHandle)

	raw_file = read_binary_file(_path)
	chunkList = fileprocessor.fileToChunks(_path, privateHandle, genesisHash, password=pwd)

	def test_verify_chunk_signatures(self):
		_, verifyingKey = encryption.getKeypair(self.privateHandle)
		address_gen = datamap.createDatamapGenerator(verifyingKey, len(self.chunkList) + 1)
		for chunk in self.chunkList: 
			datachunk, signature = encryption.splitChunkAndSignature(chunk)
			address = encryption.trytesToBytes(next(address_gen)[:-1])
			encryption.verifyChunk(datachunk + address, signature, verifyingKey.hex())
		assert True
	
	def test_decrypting_chunked_file(self):
		encryptionKey = encryption.getEncryptionKey(self.privateHandle)
		decrypted_path = self._path+"_decrypted"
		assert fileprocessor.chunksToFile(self.chunkList, encryptionKey, decrypted_path, password=self.pwd)
		
		decrypted_file = read_binary_file(decrypted_path)
		assert decrypted_file == self.raw_file
	
	#! Put functions here
			
	def test_clean_file(self):
		cleanup()