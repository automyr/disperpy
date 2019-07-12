import iota
from oysterpy import encryption, fileprocessor, datamap, iota_utils

### IMPORTANT TEST PARAMETERS

filename = "Install.txt" #must be in the same dir as this script
node_url = "https://piota-node.com:443"

### -------------------------

# Generate handle and keys
privateHandle = encryption.getPrivateHandle()
_, verifyingKey = encryption.getKeypair(privateHandle)
encryptionKey = encryption.getEncryptionKey(privateHandle)

# Show handle on terminal
print("Private Handle:", privateHandle.hex())

# Generate metadata chunk
rawMetadataChunk = fileprocessor.makeMetadataChunk([filename], [False], verifyingKey)
metadataChunkTuple = fileprocessor.squashAndSplitMetadataChunk(rawMetadataChunk)

allChunksList = [b"Protocol Chunk Here"] + fileprocessor.prepareMetadataChunks(metadataChunkTuple, privateHandle)

# Split, encrypt and sign the file as chunks
offsetHash = bytes.fromhex(rawMetadataChunk[filename]["offsetHash"])
fileChunks = fileprocessor.fileToChunks(filename, privateHandle, offsetHash)
allChunksList += fileChunks

# Print data
print("File >>>", filename, "<<< chunked and encrypted successfully")
print("Number of transactions needed:", len(allChunksList))

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

# Print confirmation message
print("File sent to the Tangle")