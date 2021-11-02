import os


def red():
	red = os.system("color 4")

def green():
	green = os.system("color 0a")

#print(red + "Hello" + green + "world")
print("{} {} {} {}".format(red(), "Hello", green(), "World"))