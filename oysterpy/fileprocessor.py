# coding=utf-8
import os
import math
from oysterpy import encryption, datamap
import json
import numpy as np

def fileToChunks(filename, privateHandle, startingHash, password = None):
	"""Takes a filename and returns the file converted to rev2 compliant chunks, already signed.
	
	Arguments:
		filename {str} -- Self-explanatory. Also needs to include the extension.
		privateHandle {bytes} -- Bytestring to use as the private handle. Can and should be generated using encryption.getPrivateHandle().
		startingHash {bytes} -- Hash on the main hashchain corresponding to the position of the first chunk of the file on the datamap.
	
	Keyword Arguments:
		password {str} -- Optional argument. Use it to password protect a particular file in a multi-file upload (default: {None})
	
	Returns:
		list -- Every element is a chunk, in the same order as the bytes are read from the file. 
	"""
	
	signingKey, _ = encryption.getKeypair(privateHandle)	
	encryptionKey = encryption.getEncryptionKey(privateHandle)

	f = open(filename, mode="rb")
	filesize = os.path.getsize(filename)
	chunksize = 1013
	numberOfChunks = math.ceil(filesize/chunksize)

	fileList = []

	if password is not None:
		encryptionKey = encryption.getEncryptionKey(encryptionKey + password.encode("utf-8"))
		numberOfChunks = math.ceil((filesize - 997)/chunksize) + 1
		chunksize = 997

	address_gen = datamap.createDatamapGenerator(startingHash, numberOfChunks + 1)

	for i in range(0, numberOfChunks):
		chunk = f.read(chunksize)
		encrypted_chunk, nonce, tag = encryption.encryptAES(chunk, encryptionKey)
		address_trytes = next(address_gen)[:-1] #the real address is 81 chars, but the byte conversion only works with even numbers, so we use the first 80 chars of the address to sign and check 
		address_bytes = encryption.trytesToBytes(address_trytes)
		
		if password is not None and i == 0:
			unsigned_chunk = b"".join([encrypted_chunk, nonce, tag])
			chunksize = 1013
		else:
			unsigned_chunk = b"".join([encrypted_chunk, nonce])
			
		signature = encryption.signChunk(unsigned_chunk + address_bytes, signingKey)
		completed_chunk = unsigned_chunk + signature
		fileList.append(completed_chunk)
	
	f.close()
	
	return fileList

def chunksToFile(fileList, encryptionKey, filename, password = None, max_bytes_in_mem=1013*1000):
	"""Takes a list of chunks and writes the decrypted file to disk.

	Arguments:
		fileList {list} -- Each item should be a raw chunk in bytes.
		encryptionKey {bytes} -- Bytestring to use as the decryption key.
		filename {str} -- Name of the file being written to disk.
	
	Keyword Arguments:
		password {str} -- Optional argument. Used with password protected files, needs utf-8 encoding. (default: {None})
		max_bytes_in_mem {int} -- Optional argument. Sets the max amount (+- 1012) of bytes to hold in memory before writing to file, to limit I/o operations.
	
	Raises:
		Both errors will only be relevant in password protected files.

		ValueError -If the decryption key can't decrypt the file correctly.
		KeyError -- Haven't seen this one ever trigger #TODO: Change this to something else
	
	Returns:
		bool -- True upon function completion, if no errors were raised during execution.
	"""
	
	f = open(filename, mode="wb")
	data = []

	if password is not None:
		realEncryptionKey = encryption.getEncryptionKey(encryptionKey + password.encode("utf-8"))
		for i, chunk in enumerate(fileList):
			datachunk, _ = encryption.splitChunkAndSignature(chunk)
			if i == 0:
				try:
					data.append(encryption.decryptAndVerifyAES(datachunk, realEncryptionKey))
				except ValueError:
					raise ValueError
				except KeyError:
					raise KeyError
			else:
				data.append(encryption.decryptAES(datachunk, realEncryptionKey))
			
			if len(data) == max_bytes_in_mem or i+1 == len(fileList):
				data = b"".join(data)
				f.write(data)
				data = []

	else:
		for i, chunk in enumerate(fileList):
			datachunk, _ = encryption.splitChunkAndSignature(chunk)
			data.append(encryption.decryptAES(datachunk, encryptionKey))
				
			#This is here so that everything doesn't break with big files/low memory
			if len(data) == max_bytes_in_mem or i+1 == len(fileList):
				data = b"".join(data)
				f.write(data)
				data = []
	
	f.close()
	return True

def splitBytestring(bytestring, sliceSize):
	"""Splits a bytesting into sliceSize slices. The last slice can be shorter than sliceSize.
	
	Arguments:
		bytestring {[bytes]} -- Any kind of bytestring works.
		sliceSize {[int]} -- Desired length in bytes of each slice.
	
	Returns:
		[tuple] -- Tuple containing the split slices.
	"""

	byteList = []
	remainingSize = len(bytestring)
	lastIndex = 0

	while remainingSize >= sliceSize:
		byteList.append(bytestring[lastIndex:lastIndex+sliceSize])
		lastIndex += sliceSize
		remainingSize += -sliceSize
	if remainingSize > 0:
		byteList.append(bytestring[lastIndex:])

	return tuple(byteList)

def addRevFlag(firstTreasureChunk):
	"""Adds the revision flag to the first chunk in the datamap.
	
	Arguments:
		firstTreasureChunk {bytes} -- This should already be encrypted and have the nonce. This should come directly from the broker and only lack the flag and signature.
	
	Returns:
		bytes -- Treasure chunk ready to be signed.
	"""
	#pylint: disable=E1101
	revFlag = np.uint32(2).tobytes()
	return b"".join([revFlag, firstTreasureChunk])

def stripRevFlag(firstTreasureChunk):
	"""Strips the revision flag from the first chunk in the datamap.
	
	Arguments:
		firstTreasureChunk {bytes} -- Self-explanatory. In this particular case this refers to the chunk straight from the iota tx.
	
	Returns:
		int -- Revision flag number. Could be either 1 or 2 as of this writing.
		bytes -- The rest of the treasure chunk.
	"""
	revFlag = int(np.fromstring(firstTreasureChunk[:4], dtype="uint32"))
	treasureChunk = firstTreasureChunk[4:]

	return revFlag, treasureChunk

def addMetadataFlags(metadataChunk, numberOfMetadataChunks):
	"""Adds binary flag the number of metadata chunks this upload has (uint8).
	
	Arguments:
		metadataChunk {bytes} -- First metadata chunk already encrypted, but before signing.
		numberOfMetadataChunks {int} -- Self-explanatory.
	
	Returns:
		bytes -- Metadata chunk ready to be signed.
	"""
	numberFlag = np.uint8(numberOfMetadataChunks).tobytes()
	fullMetadataChunk = b"".join([numberFlag, metadataChunk])

	return fullMetadataChunk

def stripMetadataFlags(metadataChunk):
	"""Strip binary flags from the start of the metadata chunk.
	
	Arguments:
		metadataChunk {bytes} -- This refers only to the first metadata chunk. If there are additional ones they won't have any flags.
	
	Returns:
		bytes -- Number of metadata chunks, uint8.
		bytes -- Rest of the metadata chunk.
	"""
	metadataChunkNumberFlag = metadataChunk[0:1]
	metadata = metadataChunk[1:]
	
	return metadataChunkNumberFlag, metadata

def correctMetadataIndexes(fullMetadata, numberOfMetadataChunks):
	"""Offsets indexes and offset hashes inside the metadata in those cases where more than 1 metadata chunk is present.
	
	Arguments:
		fullMetadata {dict} -- JSON-compliant dict. Output of makeMetadataChunk().
		numberOfMetadataChunks {int} -- Self-explanatory.
	"""

	extraMetadataChunks = numberOfMetadataChunks - 1
	for filename in fullMetadata.keys():
		fullMetadata[filename]["startIdx"] += extraMetadataChunks
		old_offsetHash = fullMetadata[filename]["offsetHash"]
		new_offsetHash = datamap.get_offset_hash(bytes.fromhex(old_offsetHash), extraMetadataChunks).hex()
		fullMetadata[filename]["offsetHash"] = new_offsetHash

def squashAndSplitMetadataChunk(fullMetadata):
	"""Converts the metadata to bytes and splits it into 1000 byte chunks. Also fixes the indexes and offset hashes inside the metadata in case there are multiple offset metadata chunks.
	
	Arguments:
		fullMetadata {dict} -- Output dict coming from makeMetadataChunk().
	
	Returns:
		tuple -- Contains all metadata chunks as bytes objects, in their correct order.
		int -- Total number of metadata chunks in this upload.
	"""

	maxChunkSize = 1000

	str_jsonChunk = json.dumps(fullMetadata)
	byte_jsonChunk = str_jsonChunk.encode("utf-8")
	
	numberOfMetadataChunks = ((len(byte_jsonChunk)) // maxChunkSize) + 1 #be careful of the edge case where len(byte_jsonChunk) == maxChunkSize

	if numberOfMetadataChunks > 1:
		correctMetadataIndexes(fullMetadata, numberOfMetadataChunks)
		str_jsonChunk = json.dumps(fullMetadata)
		byte_jsonChunk = str_jsonChunk.encode("utf-8")

	MetadataChunkTuple = splitBytestring(byte_jsonChunk, 1000)
	
	return MetadataChunkTuple

def makeMetadataChunk(filenameList, passwordFlagArray, genesisHash):
	"""Takes a list of filenames and returns a JSON-compliant dict with all the metadata inside
	
	Arguments:
		filenameList {list} -- Each item must be a filename present in the same directory as the executed script. Each filename must be a {str} object, with this format: "path/to/file"
		passwordFlagArray {list} -- List of boolean vales. Each index corresponds to whether the corresponding file in filename list should have a password or not.
		genesisHash {bytes} -- Self-explanatory. Coincides with the verifying key in rev2.
	
	Returns:
		dict -- JSON-compliant dict that contains all the metadata.
	"""
	#TODO: Clean up inline comments

	fullMetadata = {} 
	chunkSize = 1013 #in bytes
	#sectorSize = 1000000 #number of chunks
	lastIndexUsed = 1 #First attempt is made supposing there's only one metadata chunk. So first index (0) goes to the treasure, second (1) to the metadata. If there's more than one metadata chunk then another function will trigger and fix it later.

	for filename, passwordFlag in zip(filenameList, passwordFlagArray):
		filesize = os.path.getsize(filename)
		
		chunkCount = math.ceil(filesize/chunkSize)
		
		#in the squash function we'll check if we need extra metadata chunks and adjust the idx in consequence
		startIdx = lastIndexUsed + 1

		lastChunkSize = filesize % chunkSize
		if passwordFlag:
			lastChunkSize += 16
			if lastChunkSize > chunkSize:
				lastChunkSize += - chunkSize
				chunkCount += 1

		offsetHash = datamap.get_offset_hash(genesisHash, startIdx)

		fullMetadata[filename]={"chunkSize": chunkSize, "startIdx": startIdx, "chunkCount": chunkCount, "offsetHash": offsetHash.hex(), "password": passwordFlag, "lastChunkSize": lastChunkSize}

		lastIndexUsed = startIdx + chunkCount - 1 #TODO needs to account for additional treasures in other sectors.

	return fullMetadata

def unpackMetadata(fullMetadataArray, encryptionKey):
	"""Takes the raw metadata chunks from the iota tx and returns a JSON object with the metadata.
	
	Arguments:
		fullMetadataArray {iterable} -- Each item must correspond to one untouched chunk (with the signature included)
		encryptionKey {bytes} -- Self-explanatory
	
	Returns:
		json -- Basically a dict for all intents and purposes. Contains the metadata.
	"""

	for i, chunk in enumerate(fullMetadataArray):
		data, _ = encryption.splitChunkAndSignature(chunk)
		if i == 0:
			_, encryptedChunk = stripMetadataFlags(data)
			metadata = encryption.decryptAES(encryptedChunk, encryptionKey)
		else:
			metadata += encryption.decryptAES(data, encryptionKey)

	metadataJSON = json.loads(metadata.decode())

	return metadataJSON

def prepareMetadataChunks(metadataTuple, privateHandle):
	"""Encrypts, signs and adds the necessary flags to the metadata chunks.
	
	Arguments:
		metadataTuple {tuple of {bytes}} -- Output of squashAndSplitMetadataChunk(), where every element of the tuple is a metadata chunk.
		privateHandle {bytes} -- Self-explanatory.
	
	Returns:
		list -- List of metadata chunks - in order - ready to be encoded into trytes and sent in an iota tx.
	"""

	encryptionKey = encryption.getEncryptionKey(privateHandle)
	signingKey, verifyingKey = encryption.getKeypair(privateHandle)
	metadataChunkList = []

	address_gen = datamap.createDatamapGenerator(verifyingKey, len(metadataTuple) + 2)
	next(address_gen) # first address is the treasure chunk's so we don't need it right now

	for i, metadataChunk in enumerate(metadataTuple):
		encryptedChunk, nonce, _ = encryption.encryptAES(metadataChunk, encryptionKey)
		preparedChunk = encryptedChunk+nonce
		address = encryption.trytesToBytes(next(address_gen)[:-1])
		if i == 0:
			preparedChunk = addMetadataFlags(preparedChunk, len(metadataTuple))
		signature = encryption.signChunk(preparedChunk + address, signingKey)
		finalMetadataChunk = b"".join([preparedChunk, signature])
		metadataChunkList.append(finalMetadataChunk)

	return metadataChunkList

	