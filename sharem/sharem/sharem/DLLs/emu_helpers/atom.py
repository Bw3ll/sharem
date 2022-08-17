from dataclasses import dataclass


@dataclass
class Atom:
    ID: int
    name: str
    refCount: int = 1

    def incRefCount(self):
        self.refCount += 1

    def decRefCount(self):
        self.refCount -= 1

    def __hash__(self) -> int:
        return hash((self.ID))


class AtomTable:
    IdCounter = 0x1234
    Atoms: 'set[Atom]' = set()

    def add(name: str):
        for atom in AtomTable.Atoms:
            if name.lower() == atom.name.lower():
                atom.incRefCount()
                return atom.ID
        atom = Atom(AtomTable.getNewId(), name)
        AtomTable.Atoms.add(atom)
        return atom.ID

    def delete(id: int):
        for atom in AtomTable.Atoms:
            if id == atom.ID:
                atom.decRefCount()
                if atom.refCount < 1:
                    AtomTable.Atoms.remove(atom)
                return atom.ID
        return 0  # Atom Not Found

    def find(name: str):
        for atom in AtomTable.Atoms:
            if name.lower() == atom.name.lower():
                return atom.ID
        return 0  # Atom Not Found

    def incIdCounter():
        AtomTable.IdCounter += 1
        if AtomTable.IdCounter > 65535:  # 16 bit max value
            AtomTable.IdCounter = 1

    def decIdCounter():
        AtomTable.IdCounter -= 1
        if AtomTable.IdCounter < 1:  # 16 bit min value
            AtomTable.IdCounter = 65535

    def getNewId():
        id = AtomTable.IdCounter
        AtomTable.incIdCounter()
        return id
