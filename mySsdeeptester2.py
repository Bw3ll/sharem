import ssdeep


hash2 = ssdeep.hash('Also called fuzzy hashes, Ctph can match idruts that have homologies.Also called fuzzy hashes, Ctph can match inuts that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.Also called fuzzy hashes, Ctph can match inputs that have homologies.')
# hash2 = ssdeep.hash('Also called fuzzy hashes, Austin plays fuzzy guitars')


# ssdeepHash = ssdeep.hash(open(file_address,'rb').read())



myList=["Sascha","Tarek","Cat", "Dogo", "Bramwell"]
results=[]


for each in myList:
	ssdeepHash = ssdeep.hash(each)
	print(ssdeepHash)
	results.append(ssdeepHash)


print (myList)
print(results)


for each in myList:
	pass
	# compare!
	#print output