

# # ebx = 03



# split function
# 	regular expression
# 		if reg
# 			get the value via unicorn
# 				write that value

# def randomFunc(str):
# 	# split	
# 	if regular expresions --> eax
# 		write the value
# 	else:
# 		write whatever it is


# 		ebx + 354
# 		5 + 354

val=""
val2 = "val="
val2 += "5 + 5"
val2 += "print(val)"
newcode=compile(val2,"",'exec')
eval(newcode)
print (val)