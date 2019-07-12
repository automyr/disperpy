import iota, itertools
from oysterpy import encryption, datamap, fileprocessor

def bytesToTrytes(bytestring):
	"""
	Simple wrapper for iota.TryteString conversion method
	"""
	return iota.TryteString.from_bytes(bytestring)

def trytesToBytes(trytestring):
	"""
	Simple wrapper for iota.TryteString conversion method
	"""
	return iota.TryteString.encode(trytestring)

def remove_message_padding(message, last_chunk_data=None):
	"""Returns the message without the trailing 9 (\x00\'s). Is a bit of a hack, since there could be a case where one of the removed 9 was part of the signature. Though the file could still be decrypted.
	
	Arguments:
		message {iota.types.tryteString} -- tryteString contained in the message field of an iota transaction, minus the last tryte to make it even for the byte conversion.
	
	Keyword Arguments:
		last_chunk_data {dict} -- Dict containing relrevant data for the last chunk in the file. Only used if the message IS the last chunk. Ex:{"passwordFlag": True, "lastChunkSize": 113, "chunkCount": 36}

	Returns:
		clean_message {bytes} -- message in bytes without the trailing \x00\'s
	"""
	byte_message = trytesToBytes(message)
	if last_chunk_data is None:
		i_fin = len(byte_message) - 1
		for i, e in enumerate(reversed(byte_message)):
			if e is not 0:
				i_fin = i
				break
		real_i = len(byte_message) - 1 - i_fin
		clean_message = byte_message[:real_i+1]
		return clean_message
	else:	
		passwordFlag = last_chunk_data['passwordFlag']
		chunkCount = last_chunk_data['chunkCount']
		lastChunkSize = last_chunk_data['lastChunkSize']

		# Size in bytes of various possible inclusions in the message
		MAC_tag = 16
		signature = 64
		nonce = 16

		if chunkCount == 1 and passwordFlag:
			extra_bytes = nonce + MAC_tag + signature
			Non_padded_size = lastChunkSize + extra_bytes
			return byte_message[:Non_padded_size]
		else:
			extra_bytes = nonce + signature
			Non_padded_size = lastChunkSize + extra_bytes
			return byte_message[:Non_padded_size]

def retrieve_metadata(iota_api, verifyingKey, encryptionKey):

	address_gen = datamap.createDatamapGenerator(verifyingKey, None, 1)
	
	#first metadata chunk suposing there's only one tx in this address
	address_base = next(address_gen) #Address from the datamap in tryteString
	full_address = iota.Address(address_base) #Same as above but with its own class, which works better with the API
	txs_list = iota_api.find_transactions(addresses=[full_address])['hashes']
	full_tx = iota_api.get_trytes(txs_list)
	tx = iota.Transaction.from_tryte_string(full_tx['trytes'][0])

	message_trytes = tx.signature_message_fragment[:-1]
	clean_m = remove_message_padding(message_trytes)

	#Check the metadata's signature
	address_check = trytesToBytes(address_base[:-1]) #First 80 trytes of the address in bytes, for signature verification.
	data_chunk, signature = encryption.splitChunkAndSignature(clean_m)
	encryption.verifyChunk(data_chunk + address_check, signature, verifyingKey.hex())

	#This only matters if there's more than one metadata chunk
	#metadataChunkNumberFlag_bytes, _ = fileprocessor.stripMetadataFlags(clean_m)
	#numberFlag = int(np.fromstring(metadataChunkNumberFlag_bytes, dtype='uint8'))

	metadataJSON = fileprocessor.unpackMetadata([clean_m], encryptionKey)

	return metadataJSON

def retrieve_file(iota_api, metadata_single):

	# Extract useful metadata
	chunkCount = metadata_single["chunkCount"]
	offsetHash = bytes.fromhex(metadata_single["offsetHash"])

	address_gen = datamap.createDatamapGenerator(offsetHash)

	# For each chunk, send an API request, retrieve the tx, extract and clean the message and store it
	chunk_list = []
	for i in range(chunkCount):
		address_base = next(address_gen) #Address from the datamap in tryteString
		full_address = iota.Address(address_base) #Same as above but with its own class, which works better with the API
		
		txs_list = iota_api.find_transactions(addresses=[full_address])['hashes']
		full_tx = iota_api.get_trytes(txs_list)
		tx = iota.Transaction.from_tryte_string(full_tx['trytes'][0])

		message_trytes = tx.signature_message_fragment[:-1]

		if i+1 == chunkCount:
			message_trytes = remove_message_padding(message_trytes)
		else:
			message_trytes = remove_message_padding(message_trytes)

		chunk_list.append(message_trytes)

	return chunk_list

def send_file(iota_api, verifyingKey, allChunksList, depth=1):

	address_gen = datamap.createDatamapGenerator(verifyingKey)
	tx_list = []

	# Prepare all the chunks as iota tx
	for chunk in allChunksList:
		p_tx = iota.ProposedTransaction(
			address = iota.Address(next(address_gen)),
			message = bytesToTrytes(chunk),
			value = 0,
			tag = iota.Tag(b'DISPERPYTHREE'), #TODO: Change the tag to empty after testing
		)
		tx_list.append(p_tx)

	# Send the tx to the node. This could be adapted to send to multiple nodes to speed up the upload
	try:
		iota_api.send_transfer(depth, tx_list)
	except ValueError as e:
		# pylint: disable=no-member
		print(e.context)
		raise

def send_single_chunk(iota_api, chunk, address, depth=1):

	p_tx = iota.ProposedTransaction(
			address = iota.Address(address),
			message = bytesToTrytes(chunk),
			value = 0,
			tag = iota.Tag(b'DISPERPYTHREE'), #TODO: Change the tag to empty after testing
		)

	try:
		iota_api.send_transfer(depth, [p_tx])
	except ValueError as e:
		# pylint: disable=no-member
		print(e.context)
		raise