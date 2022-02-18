import pefile
from modules import *

export_dict = {}
foundDLLAddresses = "foundDLLAddresses.txt"
expandedDLLsPath = "DLLs\\"

def insertIntoBytes(binaryBlob, start, size, value):
    lBinary = list(binaryBlob)
    for x in range (size):
        lBinary.insert(start, value)
    final=bytes(lBinary)
    return final

def padDLL(dllPath, dllName):
    pe = pefile.PE(dllPath)

    virtualAddress = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
    i = 0
    padding = 0
    while True:
        try:
            section = pe.sections[i]

            pointerToRaw = section.PointerToRawData
            sectionVA = section.VirtualAddress
            sizeOfRawData = section.SizeOfRawData

            if (virtualAddress >= sectionVA and virtualAddress < (sectionVA + sizeOfRawData)):
                padding = virtualAddress - (virtualAddress - sectionVA + pointerToRaw)
                print("\'%s\': %s, " % (dllName, hex(padding)), end="")
                break
        except:
            break
        i += 1

    # Replace e_lfanew value
    elfanew = pe.DOS_HEADER.e_lfanew
    pe.DOS_HEADER.e_lfanew = elfanew + padding

    tmpPath = expandedDLLsPath + dllName
    pe.write(tmpPath)

    # Add padding to dll, then save it.
    out = readRaw(tmpPath)

    final = insertIntoBytes(out, 0x40, padding, 0x00)
    newBin = open(tmpPath, "wb")
    newBin.write(final)
    newBin.close()

def readRaw(appName):
    f = open(appName, "rb")
    myBinary = f.read()
    f.close()
    return myBinary

def saveDLLsToFile():       #help function called by loaddllsfromPE
    output=""
    for address in export_dict:
        apiName=export_dict[address][0]
        dllName=export_dict[address][1]

        output+=str(hex(address)) +", " + apiName+ ", "  + dllName + "\n"
    with open(foundDLLAddresses, 'w') as out:
        print("Writing to file")
        out.write(output)
        out.close()

def loadDLLsFromPE():
    path = 'C:\\Windows\\SysWOW64\\'

    for m in mods:
        dllPath = path + mods[m].name
        padDLL(dllPath, mods[m].name)

        pe=pefile.PE(expandedDLLsPath + mods[m].name)
        pe=pefile.PE(dllPath)
        print(expandedDLLsPath + mods[m].name)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                export_dict[mods[m].base + exp.address] = (exp.name.decode(), mods[m].name)
            except:
                export_dict[mods[m].base + exp.address] = "unknown_function"
        print("Loaded ", mods[m].name)
    print("finished loading ")
    saveDLLsToFile()        # saving the output to disc by default

if __name__ == '__main__':
    loadDLLsFromPE()