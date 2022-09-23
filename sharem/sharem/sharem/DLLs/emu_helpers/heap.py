from struct import pack
from sharem.sharem.DLLs.emu_helpers.handles import Handle, HandleType
from sharem.sharem.DLLs.emu_helpers.sim_values import emuSimVals
from sharem.sharem.helper.emuHelpers import Uc

HeapsDict: 'dict[int,Heap]' = {}  # Dictionary of All Heaps

# Convert Heaps to Handles Some Day Shelby

# Heap Functions
class Heap:

    def __init__(self, uc: Uc, handle: int, size: int):
        self.availableSize = size
        if handle == 0:
            self.handle = Handle(HandleType.Heap)
        else:
            self.handle = Handle(HandleType.Heap)
        self.allocations: dict[int,HeapAllocation] = {}
        self.usedSize = 0
        HeapsDict.update({self.handle.value: self})

    def createAllocation(self, uc: Uc, size: int):
        # Check avaible Memory Increase if Necessary
        while (self.usedSize + size) > self.availableSize:
            self.increaseSize()

        newAllocation = HeapAllocation(uc, size)
        self.usedSize = self.usedSize + size
        self.allocations.update({newAllocation.address: newAllocation})
        return newAllocation

    def reAlloc(self, uc: Uc, addr: int, size: int):
        # Check avaible Memory Increase if Necessary
        while (self.usedSize + size) > self.availableSize:
            self.increaseSize()

        newAllo = HeapAllocation(uc, size)
        oldAllo = self.allocations[addr]

        try:
            memory = uc.mem_read(oldAllo.address, oldAllo.size)
            fmt = '<' + str(oldAllo.size) + 's'
            uc.mem_write(newAllo.address, pack(fmt, memory))
        except:
            return oldAllo

        self.usedSize = self.usedSize - oldAllo.size + size
        self.free(uc, oldAllo.address)
        self.allocations.update({newAllo.address: newAllo})
        return newAllo

    def increaseSize(self):
        # Double or increase By 1/2 or Just Make Enough Room for new Allocation
        # print('Heap Size Increased')
        self.availableSize = self.availableSize * 2

    def free(self, uc: Uc, addr: int):
        if addr in self.allocations:
            uc.mem_unmap(self.allocations[addr].address, self.allocations[addr].size)
            self.usedSize -= self.allocations[addr].size
            self.allocations.pop(addr)

    def destroy(self, uc: Uc):
        for i in self.allocations:
            self.usedSize -= self.allocations[i].size
            uc.mem_unmap(self.allocations[i].address, self.allocations[i].size)
        self.allocations = {}
        HeapsDict.pop(self.handle)

    def printInfo(self):
        print('Heap Info')
        print('Handle: ', hex(self.handle))
        print('Used Size: ', self.usedSize)
        print('Total Size: ', self.availableSize)
        print('Allocations: ', len(self.allocations))
        for i in self.allocations:
            print(' Address:', hex(self.allocations[i].address), 'Size:', self.allocations[i].size)


class HeapAllocation:
    def __init__(self, uc: Uc, size: int):
        try:
            self.address = emuSimVals.availMem
            self.size = size
            uc.mem_map(self.address, self.size)
            emuSimVals.availMem += self.size
        except:
            self.address = 0
            self.size = 0
            print('Heap Allocation Failed')
