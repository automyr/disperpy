import os, time
import iota
from oysterpy import encryption, fileprocessor, datamap, iota_utils
from Crypto.Random import get_random_bytes, random
from Crypto.Hash import SHA256
import numpy as np

### IMPORTANT TEST PARAMETERS

filesize_kb = 1 #use a small size with remote PoW nodes
node_url = "https://piota-node.com:443"

### -------------------------

def initialize_file(path, sizeinkb=10):
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

def test_End_to_End():
	number_of_files = 1

	filenameList = ["testfile_" + str(i+1) for i in range(number_of_files)]
	initialize_multiple_files(filenameList)
	passwordFlagList = [bool(random.getrandbits(1)) for i in filenameList]
	passwordDict = {filename:"disper" for filename, flag in zip(filenameList, passwordFlagList) if flag}

	privateHandle = encryption.getPrivateHandle()
	_, verifyingKey = encryption.getKeypair(privateHandle)
	#encryptionKey = encryption.getEncryptionKey(privateHandle)

	rawMetadataChunk = fileprocessor.makeMetadataChunk(filenameList, passwordFlagList, verifyingKey)
	metadataChunkTuple = fileprocessor.squashAndSplitMetadataChunk(rawMetadataChunk)

	allChunksList = [b"Protocol Chunk Here"] + fileprocessor.prepareMetadataChunks(metadataChunkTuple, privateHandle)

	for filename in filenameList:
		offsetHash = bytes.fromhex(rawMetadataChunk[filename]["offsetHash"])
		if filename in passwordDict: # This statement is only True if filename has been added to the keys in the dict, which means it has a password
			fileChunks = fileprocessor.fileToChunks(filename, privateHandle, offsetHash, password=passwordDict[filename])
		else:
			fileChunks = fileprocessor.fileToChunks(filename, privateHandle, offsetHash)
		allChunksList += fileChunks
	
	#useful prints
	print("Private Handle:", privateHandle.hex())
	print("File", filename, "chunked and encrypted successfully")
	print("Number of transactions needed:", len(allChunksList))
	
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
	
	### This should go in iota_utils

	address_gen = datamap.createDatamapGenerator(verifyingKey)
	tx_list = []
	
	for chunk in allChunksList:
		p_tx = iota.ProposedTransaction(
			address = iota.Address(next(address_gen)),
			message = encryption.bytesToTrytes(chunk),
			value = 0,
			tag = iota.Tag(b'DISPERPYTWO'),
		)
		tx_list.append(p_tx)

	#print([e.address for e in tx_list])

	# Send transactions
	depth = 1
	try:
		api.send_transfer(depth, tx_list)
	except ValueError as e:
		# pylint: disable=no-member
		print(e.context)
		raise
	else:
		print("Transactions sent")
	
	"""
	# Wait 10s to give the node time to publish the tx
	print("Waiting 10s")
	time.sleep(10)
	
	# Retrieve transactions
	metadata = iota_utils.retrieve_metadata(api, privateHandle)
	print(metadata)
	
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
		address = encryption.trytesToBytes(next(address_gen)[:-1])
		encryption.verifyChunk(data_chunk + address, signature, verifyingKey.hex())
    """
	#cleanup()

test_End_to_End()