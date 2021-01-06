import itertools
from math import factorial

def nPr(n, r):
    return int(factorial(n)/factorial(n-r))


def XOR(val):
	print("t:  I am xor", val)
def ADD(val):
	print("u:  I am add",val)
def SUB(val):
	print("w:  I am sub",val)


code="XOR(9)\nADD(7)\nSUB(7)"




def foo(): 
	print("original foo")
foo()


rewrite_txt="def foo(): print('I am new foo')"
newcode=compile(rewrite_txt,"",'exec')
eval(newcode)
foo()

t=99
newcode=compile(code,"",'exec')
eval(newcode)


XORstr="XOR(t)\n"
ADDstr="ADD(u)\n"
SUBstr="SUB(w)\n"

mylist=[]
mylist.append(XORstr)
mylist.append(ADDstr)
mylist.append(SUBstr)
# mylist.append(ADDstr)
# mylist.append(SUBstr)
me="Hi"
code2=("print(me)\n")
newcode=compile(code2,"",'exec')
eval(newcode)

t=0
u=0
w=0 
# for x in range (24):
# 	for each in (list(itertools.permutations(mylist))):
# 		# print ("first", each)
# 		temp=""
# 		# for e in each:
# 		# 	temp+=e
# 		# 	print ("\t",temp)
# 		newString="".join(each)
# 		print (newString, "\n\n\n")
# 		newcode=compile(newString,"",'exec')
# 		eval(newcode)
# 	t+=1


u=0
t=0
maxValuU=20
maxValuW=4
maxValuT=5

# maxValuU=1
# maxValuW=1
# maxValuT=1
z=0

numItems=len(mylist)
totalPerm=maxValuT*maxValuW*maxValuU * (nPr(numItems,numItems-1))
permPercent=0.1*totalPerm
for x in range (maxValuT):
	for each in (list(itertools.permutations(mylist))):
		# print ("first", each)
		temp=""
		# for e in each:
		# 	temp+=e
		# 	print ("\t",temp)
		w=0
		while w < maxValuW:
			u=0
			while (u < maxValuU):
				newString="".join(each)
				print (newString, "\n\n\n")
				newcode=compile(newString,"",'exec')
				eval(newcode) 
				z+=1 #total counter
				if z == permPercent:
					print (str(int(100*permPercent/totalPerm))+"% completed")
					permPercent+=0.1*totalPerm
				u+=1
			w+=1

	t+=1


cores=240
print (z, "total")
print (totalPerm, "Perm")
numSeconds=0.0005
print (totalPerm*numSeconds, "seconds")
print ((totalPerm*numSeconds)/60, "minutes")
print (((totalPerm*numSeconds)/60)/60, "hours")
print ((((totalPerm*numSeconds)/60)/60)/24, "days")
print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")




# print (nPr(3,3))
####   2 * 3 * 1 * 3 * 2 * 1


