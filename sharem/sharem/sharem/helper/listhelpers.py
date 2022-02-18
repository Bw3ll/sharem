
def get_max_length(list_of_strings):
	max_len =-1
	for i in list_of_strings:
		if (len(i) > max_len):
			max_len = len(i)
			res = len(i)
	return res
	