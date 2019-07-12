import os, time
import iota
from disperpy import encryption, fileprocessor, datamap, iota_utils
from Crypto.Random import get_random_bytes, random
from Crypto.Hash import SHA256
import numpy as np

### IMPORTANT TEST PARAMETERS

filesize_kb = 1 #use a small size with remote PoW nodes
node_url = "https://piota-node.com:443"

### -------------------------

def initialize_file(path, sizeinkb=1):
	testfile_content = get_random_bytes(1024*sizeinkb)
	f = open(path, "wb")
	f.write(testfile_content)
	f.close()

def initialize_multiple_files(pathList):
	for path in pathList:
		initialize_file(path, sizeinkb=filesize_kb)

def cleanup():
	ldir = os.listdir()
	for filename in ldir:
		if "testfile" in filename:
			os.remove(filename)

def read_binary_file(path):
	with open(path, "rb") as f:
		fr = f.read()
	return fr

def generate_fake_input(num_of_files=1):
	filenameList = ["testfile_" + str(i+1) for i in range(num_of_files)]
	initialize_multiple_files(filenameList)
	passwordFlagList = [False for i in filenameList]
	passwordDict = {filename:"disper" for filename, flag in zip(filenameList, passwordFlagList) if flag}

	return filenameList, passwordFlagList, passwordDict


def test_End_to_End():
	
	filenameList, passwordFlagList, _ = generate_fake_input()
	
	privateHandle = encryption.getPrivateHandle()
	_, verifyingKey = encryption.getKeypair(privateHandle)
	encryptionKey = encryption.getEncryptionKey(privateHandle)

	rawMetadataChunk = fileprocessor.makeMetadataChunk(filenameList, passwordFlagList, verifyingKey)
	metadataChunkTuple = fileprocessor.squashAndSplitMetadataChunk(rawMetadataChunk)

	allChunksList = [b"Protocol Chunk Here"] + fileprocessor.prepareMetadataChunks(metadataChunkTuple, privateHandle)
	offsetHash = bytes.fromhex(rawMetadataChunk[filenameList[0]]["offsetHash"])
	fileChunks = fileprocessor.fileToChunks(filenameList[0], privateHandle, offsetHash)
	allChunksList += fileChunks
	
	""" Just use non-password files for now
	for filename in filenameList:
		offsetHash = bytes.fromhex(rawMetadataChunk[filename]["offsetHash"])
		if filename in passwordDict: # This statement is only True if filename has been added to the keys in the dict, which means it has a password
			fileChunks = fileprocessor.fileToChunks(filename, privateHandle, offsetHash, password=passwordDict[filename])
		else:
			fileChunks = fileprocessor.fileToChunks(filename, privateHandle, offsetHash)
		allChunksList += fileChunks
	"""
	### Now the file is prepared to be sent. Every element in allChunksList is the message part of an iota tx in bytes

	#Initialize iota api and generate a random seed.
	api = iota.Iota(node_url)

	# Check node connection
	try:
		api.get_node_info()
	except:
		print("Connection to node failed:", node_url)
		exit
	else:
		print("Connection to node established:", node_url)
	
	# Send chunked file to the Tangle
	iota_utils.send_file(api, verifyingKey, allChunksList)
		
	# Wait 5s to give the node time to publish the tx
	time.sleep(5)
	
	# Retrieve transactions
	metadataJSON = iota_utils.retrieve_metadata(api, verifyingKey, encryptionKey)
	filename = list(metadataJSON.keys())[0]
	chunk_list = iota_utils.retrieve_file(api, metadataJSON[filename])

	# Decrypt and rebuild file
	decrypted_filename = "decrypted_" + filename
	fileprocessor.chunksToFile(chunk_list, encryptionKey, decrypted_filename)

	# Asserts
	assert read_binary_file(filename) == read_binary_file(decrypted_filename)
	
	assert SHA256.new(read_binary_file(filename)).digest() == SHA256.new(read_binary_file(decrypted_filename)).digest()
	
	""" Just a single file for now
	for filename in list(metadata.keys()):
		decrypted_filename = "decrypted_"+filename
		fileList = iota_utils.retrieve_file(api, metadata[filename])
		passwordFlag = bool(metadata[filename]["password"])
		
		if passwordFlag:
			fileprocessor.chunksToFile(fileList, encryptionKey, decrypted_filename, password=passwordDict[filename])
		else:
			fileprocessor.chunksToFile(fileList, encryptionKey, decrypted_filename)

		print(read_binary_file(filename) == read_binary_file(decrypted_filename))
	"""
	cleanup()