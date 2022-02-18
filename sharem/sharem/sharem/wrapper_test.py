
from wrapper import SharemWrapper

if __name__ == '__main__':
	sw = SharemWrapper(r32="mg.bin")
	sw.run()

	# print(sw.read_main())
	# print("+-------------------+")
	# print(sw.read_disasm())