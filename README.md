# SHAREM

Welcome to SHAREM! 

SHAREM was presented at DEFCON 31 in "Game-Changing Advances in Windows Shellcode Analysis" and Black Hat USA Arsenal. A companion Ghidra plugin was made available (separately) from Trellix, courtesy of Max Kersten. Thus, you can extend the power of SHAREM to Ghidra, if you so desire. 

SHAREM is intended to be the ultimate Windows shellcode tool, with support to emulate over 20,000 WinAPIs, virtually all user-mode Windows syscalls, and SHAREM provides numerous new features. SHAREM was released on September 29, 2022. SHAREM contains an emulator, a disassembler, timeless debugging, brute-force deobfuscation, and many other features. SHAREM's emulator can also display complete structures (or even structures within structures) and it can allow encoded shellcode to deobfuscate itself. SHAREM logs output from all WinAPIs and Windows syscalls analyzed, and it also breaks each into many categories and subcategories. SHAREM's complete code coverage also allows it to discover unreachable functionality.

SHAREM's disassembler is able to integrate discovered functions into the disassembly, labelling each in the disassembler. SHAREM also will displayed the decrypted form of encoded shellcode in the disassembler, so it is not necessary to debug shellcode.

We have created a [SHAREM Wiki](https://github.com/Bw3ll/sharem/wiki) that provides some instructional  information on SHAREM usage, although there are significant portions and features not currently documented. SHAREM has been developed over a period of two years with several people working on it. SHAREM's disassembler is significantly more accurate than leading disassemblers. Additionally, SHAREM can integrate emulation data into the disassembler, allowing for nearly flawless disassembly to be obtained.

Please be aware that as SHAREM has just been released, the documentation on here is a little sparse. We will update the GitHub with more information as well in the coming weeks.

If you are new to SHAREM, feel free to check out a brief demo video, showcasing some of its capabilities Click on image to view demo:
[![Watch the video](https://github.com/Bw3ll/sharem/blob/testing/sharem/SHAREM_images/Sharem_demo.png?raw=true)](https://youtu.be/S1PI9O-q6eM)

# Install Instructions

## Windows
SHAREM is installed as a local Python package, so that we have access to it in other projects. This allows parts of SHAREM to be imported. Thus, it must be installed as a package.

1. Git is required for installation of sharem. 
It can be installed from https://git-scm.com/download/win. After installion restart computer and continue with SHAREM install. The Git is to automate the installation of the Windows SSDeep. You can also manually do this and modify the .bat to exclude the SSDeep, if you do it yourself.

2. Run .bat file. It will call the setup.py file. Depending on how you call Python, you may need to call the alternate .bat file or even modify it slightly, if using something nonstandard.

3. Do
```py -m pip list``` or  ```python3 -m pip list``` to verify that that SHAREM is installed locally as a package. It must be installed as a package to work.

After SHAREM is installed, when ou first run a shellcode, you want to be inside the sharem_cli folder. For instance, when in that directory, you could run
py main.py -r32 shellcode.bin

Note: The first time that you attempt to emulate a shellcode on Windows, it will attempt to harvest and inflate Windows DLLs. This process begins automatically when trying to first emulate a shellcode. It will copy them, moving the copied (and later inflated) DLLs to a SHAREM directory. There are additional steps, but this whole initial process can take several minutes. After it has completed, you should not have to do this again. This must be done separately both for 32- and 64-bit shellcode. 

If the file ends in .txt, it will assume the shellcode is ASCII representation of HEX (rather than pure hexadecimal), and it will interpret it as such. This works with something found online.

## Linux
1. ```chmod +x linux_installer.sh``` Enable Execution of the Installer
2. ```sudo ./linux_installer.sh``` Execute the Installer
3. Add DLL Files

You will need to add the Windows DLL files. We do not currently these available as a separate download for Linux users. At this time, users would need harvest them by installing it via Windows. (Note: These DLLs MUST be inflated by SHAREM. Dlls cannot be used if not inflated. Most, though perhaps not all, will fail if not inflated the proper amount.) Later, we may provide these as a separate download in the coming weeks. But in the meantime, the user can follow the Windows steps to generate them and move them to Linux, placing them in sharem\sharem\sharem\DLLs\x64 and sharem\sharem\sharem\DLLs\x86. You would also need the foundDLLAddresses32.json and FoundDLLAddresses64.json, which should go in sharem\sharem\sharem .

# Ghidra Script
Max Kersten's Ghidra Script as shown at Black Hat and DEFCON this August 2023 can be found here: https://github.com/advanced-threat-research/GhidraScripts/blob/main/Sharem.java
Further documentation on usage will be forthcoming. This Ghidra plugin is courtesy of Trellix! You are still required to use SHAREM. This ingests the JSON output produced by SHAREM and converts it into a format useful for Ghidra. More about Max himself can be found at https://maxkersten.nl/.

# Documentation
Documentation can be found at the [SHAREM Wiki](https://github.com/Bw3ll/sharem/wiki), which provides some instructional  information on SHAREM usage, although there are significant portions and features not currently documented. 

# Updates
* Aug. 2023: Thousands of new APIs from approximateliy 30 DLLs were added to support SHAREM, as a special update to coincide with DEFCON.
* Sept. 29, 2022: We did make a very minor update to the setup.py regarding numpy, which may affect some people with the latest version of Python.
* Nov. 25, 2022: Long overdue, we made some changes to support the [ShellWasp](https://github.com/Bw3ll/ShellWasp) style of syscalls. While we had previously implemented support for syscalls, the ShellWasp style would not work, only hardcoded SSNs (syscall values). The OSMajorVersion, OSMinorVersion, and OSBuild were initinialized for 32- and 64-bit. Whatever OS version the user has in the config or via UI will now be reflected internally - e.g. selecting Windows 10 20H2 would cause the correct values to be populated, allowing for the [ShellWasp](https://github.com/Bw3ll/ShellWasp) technique to work, as shown by this [sample output](https://github.com/Bw3ll/ShellWasp/blob/main/Samples/alternative_create_process_SHAREM_output.txt). Only Windows 7, 10, and 11 are supported for emualtion of ShellWasp technique at this time.
* Nov. 29, 2022: Added emulation support for the new OSBuilds, 22H2 for Windows 10 and 11. This is only relevant for emulating Windows syscalls. Many minor bug fixes and quality of life improvements. Better distinction of features for when SHAREM is used for shellcode (its primary focus) and when used to analyze PE files.
* Dec. 1, 2022: Changed default file location for output of bins/ASCII - moved to logs. Added the ability to output deobfuscated bins/ASCII with this command. Deobfuscated ASCII was added to the logs - the ASCII of the bin also appeared to be missing from the logs- - that has been corrected.
* Dec. 29, 2022: I addedd an **optional timeless debugging for the stack** feature. Previously, timeless debugging only captured instructions executed and register values before and after. Now we can see +/- 0xA0 from ESP. Unfortunately, it is a bit **slow**. This must be enabled separately. Additionally, I discovered some bugs that gave incorrect results from breaking out of loops, which in some cases could cause an emulation to prematurely terminate. I have corrected this. I have also now had SHAREM output when it breaks out of loops, indicating where it goes, once it breaks out of a loop.
* Jan. 4, 2023: I revamped the complete code coverage a great deal, enhancing its performance. I have also exposed several optional features that can be tweaked by expert users on case by case basis via the UI or the config file. More info at the [complete code coverage wiki page](https://github.com/Bw3ll/sharem/wiki/Complete-Code-Coverage).
* Jan. 5, 2023: Added keystroke shortcut to the complete code coverage submenu from the Emulator menu. For those with yesterday's update already downloaded, the keystroke is the letter "o".
* Jan. 16, 2023: Added three new fields to disassembly JSON files that are generated. This update is NOT needed for anyone not using those JSONs, which is a nonstandard way of using SHAREM.
* Aug. 3, 2023: Approximately 5000-6000 APIs were added from around 30 additional DLLs. Other enhancements in support of this.

# Screenshots
SHAREM is a very powerful framework with numerous capabilities, some well documented, and some which are not. This section will showcase a small number of those capabilities. 

SHAREM can take an encoded shellcode and deobfuscate it through emulation. Not only does it capture all WinAPI or syscall information, but if you choose to view it in the disassembler, it shows you the decoded form of the shellcode:

![image](https://github.com/Bw3ll/sharem/blob/testing/sharem/SHAREM_images/encodedShellcode.png?raw=true)

SHAREM not only can ennumerate 12,000+ WinAPI functions, but it can also do so with virtually all user-mode Windows syscalls. In addition, for some it displays structure information. For those dealing with the registry, it will extract registry information and add that to our Registry Manager:

![image](https://user-images.githubusercontent.com/49998815/204032319-1e10d3cc-dfc0-49e8-912d-9629571a1144.png)

SHAREM also has the ability to download files via UrldownloadToFileA, if they exist. These are downloaded into the emulator's memory - not saved to disk. If successful, it will capture the hash. There is also a limited pseudo file system, and so you can see correlations, such as a file being downloaded as one thing and renamed to another. If the needed download is not available, it will simply be simulated as a successful download. Live downloading is an option can be enabled or disabled in the config

![image](https://github.com/Bw3ll/sharem/blob/testing/sharem/SHAREM_images/downloading.png?raw=true)


# Co-Authors and Contributors
Dr. Bramwell Brizendine, Austin Babcock, Jake Hince, Shelby VandenHoek, Sascha Walker, Evan Read, Dylan Park, Tarek Abdelmotaleb, and Kade Brost.

# Acknowledgement
This research and some co-authors have been supported by NSA Grant H98230-20-1-0326.
