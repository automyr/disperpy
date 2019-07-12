import pytest
import os
from disperpy import encryption, fileprocessor, datamap, iota_utils
from Crypto.Random import get_random_bytes, random
from Crypto.Hash import SHA256
import numpy as np

def initialize_file(path, sizeinkb=10):
	testfile_content = get_random_bytes(1024*sizeinkb)
	f = open(path, "wb")
	f.write(testfile_content)
	f.close()

def initialize_multiple_files(pathList):
	for path in pathList:
		initialize_file(path, sizeinkb=50)

def cleanup():
	ldir = os.listdir()
	for filename in ldir:
		if "testfile" in filename:
			os.remove(filename)

def read_binary_file(path):
	with open(path, "rb") as f:
		fr = f.read()
	return fr

def test_End_to_End():
	number_of_files = random.randint(4, 10)

	filenameList = ["testfile_" + str(i+1) for i in range(number_of_files)]
	initialize_multiple_files(filenameList)
	passwordFlagList = [bool(random.getrandbits(1)) for i in filenameList]
	passwordDict = {filename:"oyster" for filename, flag in zip(filenameList, passwordFlagList) if flag}

	privateHandle = encryption.getPrivateHandle()
	_, verifyingKey = encryption.getKeypair(privateHandle)
	encryptionKey = encryption.getEncryptionKey(privateHandle)

	rawMetadataChunk = fileprocessor.makeMetadataChunk(filenameList, passwordFlagList, verifyingKey)
	metadataChunkTuple = fileprocessor.squashAndSplitMetadataChunk(rawMetadataChunk)

	allChunksList = [b"TreasureChunkHere"] + fileprocessor.prepareMetadataChunks(metadataChunkTuple, privateHandle)

	for filename in filenameList:
		offsetHash = bytes.fromhex(rawMetadataChunk[filename]["offsetHash"])
		if filename in passwordDict: # This statement is only True if filename has been added to the keys in the dict, which means it has a password
			fileChunks = fileprocessor.fileToChunks(filename, privateHandle, offsetHash, password=passwordDict[filename])
		else:
			fileChunks = fileprocessor.fileToChunks(filename, privateHandle, offsetHash)
		allChunksList += fileChunks

	firstMetadataChunk = allChunksList[1]
	metadataChunkNumberFlag_bytes, _ = fileprocessor.stripMetadataFlags(firstMetadataChunk)
	numberFlag = int(np.fromstring(metadataChunkNumberFlag_bytes, dtype='uint8'))

	metadataArray = allChunksList[1:numberFlag+1]
	metadataJSON = fileprocessor.unpackMetadata(metadataArray, encryptionKey)

	decrypted_filenameList = list(metadataJSON.keys())

	for filename in decrypted_filenameList:
		startIdx = metadataJSON[filename]["startIdx"]
		endIdx = startIdx + metadataJSON[filename]["chunkCount"]
		passwordFlag = bool(metadataJSON[filename]["password"])
		decrypted_filename = "decrypted_"+filename
				
		fileList = allChunksList[startIdx:endIdx]
		if passwordFlag:
			fileprocessor.chunksToFile(fileList, encryptionKey, decrypted_filename, password=passwordDict[filename])
		else:
			fileprocessor.chunksToFile(fileList, encryptionKey, decrypted_filename)

		assert read_binary_file(filename) == read_binary_file(decrypted_filename)

		assert SHA256.new(read_binary_file(filename)).digest() == SHA256.new(read_binary_file(decrypted_filename)).digest()
	
	address_gen = datamap.createDatamapGenerator(verifyingKey, None, 1)
	for chunk in allChunksList[1:]: #first chunk is the protocol chunk and doesn't get signed when doing local simulations
		data_chunk, signature = encryption.splitChunkAndSignature(chunk)
		address = iota_utils.trytesToBytes(next(address_gen)[:-1])
		encryption.verifyChunk(data_chunk + address, signature, verifyingKey.hex())
	assert True

	cleanup()