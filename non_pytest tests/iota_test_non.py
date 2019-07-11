import iota
from oysterpy import encryption, iota_utils, datamap, fileprocessor

def read_binary_file(path):
	with open(path, "rb") as f:
		fr = f.read()
	return fr

### GLOBAL Vars ###

#filename = 
privateHandle_hex = "c87f49cc1d6dca8d50c649edaf4a60ff4388936adb776625f7b70d3519a8c8c3f97b391cc2e18f74cfac269de3484c56"

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

decrypted_filename = "decrypted_" + filename

fileprocessor.chunksToFile(chunk_list, encryptionKey, decrypted_filename)

result = read_binary_file(filename) == read_binary_file(decrypted_filename)

print("Is the file the same:", result)

