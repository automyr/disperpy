import iota
from oysterpy import encryption, iota_utils, datamap, fileprocessor

def read_binary_file(path):
	with open(path, "rb") as f:
		fr = f.read()
	return fr

### GLOBAL Vars ###

#filename = 
privateHandle_hex = "08647a37e610d2c99778bf5d178e92ceebf2adcd87498282e8fb80224901ccc7b8c53dafcc1fa1f3ca5edb3ba60b41af"

### ----------- ###

# Create API object
node_url = "https://piota-node.com:443"
api = iota.Iota(node_url)

# Check node connection
try:
    api.get_node_info()
except:
    print("Connection to node failed:", node_url)
    exit
else:
    print("Connection to node established:", node_url)

# Generate needed keys from handle
privateHandle = bytes.fromhex(privateHandle_hex)
_, verifyingKey = encryption.getKeypair(privateHandle)
encryptionKey = encryption.getEncryptionKey(privateHandle)

# Retrieve metadata for the download
metadataJSON = iota_utils.retrieve_metadata(api, verifyingKey, encryptionKey)
print(metadataJSON)

# Download and store data chunks
filename = list(metadataJSON.keys())[0]
chunk_list = iota_utils.retrieve_file(api, metadataJSON[filename])

# Decrypt and rebuild file
decrypted_filename = "decrypted_" + filename
fileprocessor.chunksToFile(chunk_list, encryptionKey, decrypted_filename)

# Print confirmation message
print("File >>>", filename, "<<< downloaded successfully and stored as >>>", decrypted_filename, "<<<")
