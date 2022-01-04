import ssdeep
hash1 = ssdeep.hash('Also called fuzzy hashes, Ctph can match inputs that have homologies.')
hash2 = ssdeep.hash('Also called fuzzy hashes, CTPH can match inputs that have homologies.')
# hash2 = ssdeep.hash('Also called fuzzy hashes, Ctph can match inputs that have homologies.')



hash1 = ssdeep.hash('Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.')
hash2 = ssdeep.hash('Also called fuzzy hashes, Ctph can match idruts that have homologies.Also called fuzzy hashes, Ctph can match inuts that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.')
# hash2 = ssdeep.hash('Also called fuzzy hashes, Austin plays fuzzy guitars')


ssdeepHash = ssdeep.hash(open(file_address,'rb').read())

print (hash1)
print (hash2)
print(ssdeep.compare(hash1,hash2))