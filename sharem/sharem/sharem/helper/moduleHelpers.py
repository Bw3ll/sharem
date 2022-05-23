import json

def readRaw(appName):
    f = open(appName, "rb")
    myBinary = f.read()
    f.close()
    return myBinary

def readDLLsAddsFromFile(foundDLLAddrs, export_dict):
    with open(foundDLLAddrs, 'r') as f:
        export_dict = json.load(f)
    return export_dict

def insertIntoBytes(binaryBlob, start, size, value):
    lBinary = list(binaryBlob)
    for x in range (size):
        lBinary.insert(start, value)
    final=bytes(lBinary)
    return final