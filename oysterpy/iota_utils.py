import iota, itertools
from oysterpy import encryption, datamap, fileprocessor

def remove_message_padding(message, num_important_trytes=None):
	"""Returns the message without the trailing 9 (\x00\'s). Is a bit of a hack, since there could be a case where one of the removed 9 was part of the signature. Though the file could still be decrypted.
	
	Arguments:
		message {iota.types.tryteString} -- tryteString contained in the message field of an iota transaction, minus the last tryte to make it even for the byte conversion.
	
	Returns:
		clean_message {bytes} -- message in bytes without the trailing \x00\'s
	"""
	byte_message = encryption.trytesToBytes(message)
	i_fin = len(byte_message) - 1
	for i, e in enumerate(reversed(byte_message)):
		if e is not 0:
			i_fin = i
			break
	real_i = len(byte_message) - 1 - i_fin
	clean_message = byte_message[:real_i+1]
	return clean_message

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

	address_check = encryption.trytesToBytes(address_base[:-1]) #First 80 trytes of the address in bytes, for signature verification.
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
	for _ in range(chunkCount):
		address_base = next(address_gen) #Address from the datamap in tryteString
		full_address = iota.Address(address_base) #Same as above but with its own class, which works better with the API
		
		txs_list = iota_api.find_transactions(addresses=[full_address])['hashes']
		full_tx = iota_api.get_trytes(txs_list)
		tx = iota.Transaction.from_tryte_string(full_tx['trytes'][0])

		message_trytes = tx.signature_message_fragment[:-1]
		clean_m = remove_message_padding(message_trytes)

		chunk_list.append(clean_m)

	return chunk_list