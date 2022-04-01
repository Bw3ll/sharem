from sharem import SharemMain
import argparse

if __name__ == "__main__":

    try:
        parser = argparse.ArgumentParser(prog='Sharem',
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog='''
         \rExamples:
  python sharem.py -r32 shellcode.bin
  python sharem.py -r64 shellcode.txt
  python sharem.py -r shellcode.txt
  python sharem.py -pe revshell.exe
  python sharem.py -d c:\\shellcodedirectory
  python sharem.py -c c:\\configpath\\config.cfg -r32 shellcode.bin


Additional information:
  PE architecture is auto detected on Windows. But on Linux it's 32bit only.
  Shellcodes could be .txt, .bin, or without extension.
  The .txt is an ascii representation of raw bytes.
  If -d argument is used, the shellcode will be processed as 32 and 64 bit since the architecture is unknown.

         ''')

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-pe', type=str, help="Reads PE file only.")
        group.add_argument('-r',type=str, help="Read shellcode architecture from the config file")
        group.add_argument('-r64',  type=str, help="Reads 64-bit shellcode only")
        group.add_argument('-r32', type=str, help="Reads 32-bit shellcode only.")
        group.add_argument('-d', type=str, required=False, help="Parse shellcodes or pe files from a given directory.")

        parser.add_argument('-c', type=str, required=False, help="Read config file from a given path.")


        # SharemMain(parser)    
        args = parser.parse_args()

        SharemMain(args)


    except KeyboardInterrupt as ke:
        exit()
