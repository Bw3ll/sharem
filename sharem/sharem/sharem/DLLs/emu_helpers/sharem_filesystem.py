from pathlib import Path, PureWindowsPath
from ntpath import normpath, join 
from typing import Union
from sharem.sharem.parseconf import Configuration
from .handles import Handle,HandleType,HandlesDict
from .sharem_artifacts import Artifacts_regex
import re
import urllib3
import hashlib

class Dir_nodes:
	def __init__(self, nameString,parent = None):
		self.name = nameString
		self.parentDir = parent
		self.childrenDir = {}
		self.files = {}
		# ^ lists of files, it is sorted by {name of the file: and data, if there is no data defualts to EMPTY}

class Directory: # A Directory That Contains Many Files or Sub Directories
	def __init__(self, dirName: str, parentDir: 'Directory', root = False):
		self.name = dirName
		self.childrenDir: dict[str,Directory] = {} 
		self.files: dict[str,File] = {}
		if root:
			self.parentDir = None
			self.absolutePath = str(normpath(join(self.name,'/')))
		else:
			self.parentDir = parentDir
			self.parentDir.childrenDir.update({self.name: self})
			self.absolutePath = str(normpath(join(self.parentDir.absolutePath,self.name)))
		Directory_system.allPaths.update({self.absolutePath: self})
		Directory_system.allDirPaths.update({self.absolutePath: self})

	def createChildDirectory(self, dirName: str):
		return Directory(dirName,self)

	def createChildFile(self, fileName: str, fileData: str, fileHash: str = '[NULL]', overWrite = False):
		return File(self,fileName,fileData,fileHash,overWrite)
		
class File: # An Individual File
	def __init__(self, dir: Directory, fname: str, fdata: str, fhash: str = '[NULL]', overWrite = False):
		self.name = fname
		self.data = fdata
		self.hash = fhash
		self.directory = dir
		if not overWrite:
			if self.name in self.directory.files: # Handle Duplicate File Names
				count = 0
				for eachFile in self.directory.files:
					if(eachFile == self.name):
						count += 1
				if(count > 0):
					try:
						splitName = self.name.split(".")
						self.name = f"{splitName[0]}({count}).{splitName[1]}"
					except:
						self.name =  f"{self.name}({count})"
		self.absolutePath = normpath(join(self.directory.absolutePath,self.name))
		self.directory.files.update({fname:self})
		Directory_system.allPaths.update({self.absolutePath: self})
		Directory_system.allFilePaths.update({self.absolutePath: self})

class Directory_system:
	allPaths: 'dict[str]' = {}
	allDirPaths: 'dict[str,Directory]' = {}
	allFilePaths: 'dict[str,File]' = {}

	def __init__(self):
		#drive letter is grabbed from the config
		self.rootDir = None
		self.usersDir = None
		self.windowsDir = None
		self.currentDir = None
		self.currentDirPath = None
		self.users = ['Administrator']
		self.deletedFiles = []
	
	################################
	## Initize the file system
	################################
	def InitializeFileSystem(self):
		#Allow drive letter change from the config
		driveLetter = Configuration().simulatedValues_drive_letter
		self.rootDir = Directory(driveLetter,None,True)
		self.currentDir = self.rootDir

		# Main Directories
		self.rootDir.createChildDirectory('Microsoft')
		self.rootDir.createChildDirectory('Program Files')
		self.rootDir.createChildDirectory('Program Files(x86)')
		self.rootDir.createChildDirectory('ProgramData')
		self.rootDir.createChildDirectory('Users')
		self.rootDir.createChildDirectory('Windows')
		
		# Create User Folders
		self.CreateUsers()

		#create the default windows folder
		self.CreateWindowsFolder()

		self.setCurrentDir(Configuration().simulatedValues_start_directory)
		
	def CreateUsers(self):
		def CreateUsersCommonFolders(user: Directory):
			#Add more folders if needed later
			folders = {'AppData','Desktop','Documents','Downloads','Favorites','Links','Pictures','Music','Saved Games','Videos'}
			for f in folders:
				user.createChildDirectory(f)

		self.users = Configuration().simulatedValues_users
		self.usersDir = self.rootDir.childrenDir['Users']
		CreateUsersCommonFolders(self.usersDir.createChildDirectory('Default'))
		CreateUsersCommonFolders(self.usersDir.createChildDirectory('Public'))
		CreateUsersCommonFolders(self.usersDir.createChildDirectory('Administrator'))
		
		for username in self.users:
			CreateUsersCommonFolders(self.usersDir.createChildDirectory(username))
	
	def CreateWindowsFolder(self):
		#Add more folders if needed later
		folders = {'System32','SysWOW64'}
		self.windowsDir = self.rootDir.childrenDir['Windows']
		for f in folders:
			self.windowsDir.createChildDirectory(f)
	
	def getFileDependencies(self,config):
		#get the inputted files from the user that the shellcode depends on
		#!!DOES NOT WORK CURRENTLY!!
		# Might Add
		print(1)

	################################
	## Api Functions
	################################
	def normalizePath(self, path: str):
		return str(normpath(join(self.currentDir.absolutePath,path)))

	def getFileNameFromPath(self, path: str):
		return self.normalizePath(path).split('\\')[-1]

	def getDirFromPath(self, path: str):
		# Will Return Dir of Path Createing Dirs if Necessary
		# If path ends in file it will not return file
		newPath = self.normalizePath(path)
		newSplitPath = newPath.split('\\')
		dir = self.rootDir
		for part in newSplitPath:
			if '.' not in part:
				if part in dir.childrenDir:
					dir = dir.childrenDir[part]
				else:
					dir = dir.createChildDirectory(part)
		return dir

	def setCurrentDir(self, path: str):
		self.currentDir = self.getDirFromPath(path)

	def createFile(self, path: str, fileName: str, fileData = 'EMPTY'):
		directory = self.getDirFromPath(path)
		try:
			hashedData = hashlib.md5(fileData)
			hashedData = hashedData.hexdigest()
			directory.createChildFile(fileName,fileData,hashedData)
		except:
			directory.createChildFile(fileName,fileData)
		
	def writeFile(self, path: str, fileName: str, fileData = 'EMPTY'):
		directory = self.getDirFromPath(path)
		if fileName in directory.files:
			file = directory.files[fileName]
			file.data = fileData
		else:
			directory.createChildFile(fileName,fileData)

	def moveFile(self, originPath: str, destPath: str, replace: bool):
		orginDir = self.getDirFromPath(originPath)
		orginFileName = self.getFileNameFromPath(originPath)
		destDir = self.getDirFromPath(destPath)
		destFileName = self.getFileNameFromPath(destPath)

		if orginFileName in orginDir.files:
			orginFile = orginDir.files[orginFileName]
		else:
			orginFile = orginDir.createChildFile(orginFileName,'EMPTY') # Might Add Config Default Value
		destFile = destDir.createChildFile(destFileName,orginFile.data,orginFile.hash,replace) 
		self.deleteFile(orginFile.absolutePath)

		return destFile.absolutePath, orginFile.absolutePath, orginFile.name, destFile.name

	def copyFile(self, originPath: str, destPath: str): 
		orginDir = self.getDirFromPath(originPath)
		orginFileName = self.getFileNameFromPath(originPath)
		destDir = self.getDirFromPath(destPath)
		destFileName = self.getFileNameFromPath(destPath)
		if orginFileName in orginDir.files:
			orginFile = orginDir.files[orginFileName]
		else:
			orginFile = orginDir.createChildFile(orginFileName,'EMPTY') # Might Add Config Default Value
		destFile = destDir.createChildFile(destFileName,orginFile.data)

		return destFile.name, orginFile.name, destFile.absolutePath, orginFile.absolutePath

	def deleteFile(self,path: str):
		deletedFileDir = self.getDirFromPath(path) 
		fileName = self.getFileNameFromPath(path)
		if fileName in deletedFileDir.files:
			file = deletedFileDir.files.pop(fileName)
			filedata = file.data
			path = file.absolutePath
		else:
			filedata = 'File did not exist when shellcode tried to delete'
		self.deletedFiles.append({fileName:filedata})
		return path, fileName

	def readFile(self,node,filename): # Needs Redone
		if(filename in node.files):
			filedata = node.files.get(filename)
		else:
			filedata = 'File did not exist when shellcode tried to read'
		path = []
		path = self.getPath(node,path)
		
		return '\\'.join(path),filename, filedata

	def moveFolder(self, originPath: str, destPath: str, replace: bool):
		def fixDirPath(dir: Directory):
			dir.absolutePath = normpath(join(dir.parentDir.absolutePath,dir.name))
			for d in dir.childrenDir.values:
				fixDirPath(d)
			for file in dir.files.values():
				file.absolutePath = normpath(join(file.directory.absolutePath,file.name))


		orginDir = self.getDirFromPath(originPath)
		destDir = self.getDirFromPath(destPath)
		orginDir.parentDir.childrenDir.pop(orginDir.name)
		if replace:
			destDir.childrenDir.update({orginDir.name: orginDir})
			orginDir.parentDir = destDir
			fixDirPath(destDir)
		else:
			if orginDir.name in destDir.childrenDir: # Handle Duplicate Dir Names
				count = 0
				for eachDir in destDir.childrenDir:
					if(eachDir == orginDir.name):
						count += 1
				if(count > 0):
					orginDir.name =  f"{orginDir.name}({count})"
			orginDir.parentDir = destDir
			destDir.childrenDir.update({orginDir.name: orginDir})
			fixDirPath(destDir)

		return destDir.absolutePath, orginDir.absolutePath

	def internetDownload(self, url: str, dest: str):
		directory = self.getDirFromPath(dest)
		fileName = self.getFileNameFromPath(dest)
		Configuration().simulatedValues_download_files = True # Needs Fixed
		if Configuration().simulatedValues_download_files:
			http = urllib3.PoolManager(num_pools=1)
			r = http.request('GET',url)
			
			if(r.status == 200): # Check the status code
				hashedData = hashlib.md5(r.data)
				hashedData = hashedData.hexdigest()
				file = directory.createChildFile(fileName,r.data,hashedData)
				return file.absolutePath,file.name,file.hash,r.status
			else:
				# Error retrieving the file, give them a dummy data file
				file = directory.createChildFile(fileName,'[NULL]')
				hashedData = ''
				return file.absolutePath,file.name,hashedData,r.status
		else:
			# Create the file with dummy data
			file = directory.createChildFile(fileName,'[NULL]')
			hashedData = ''
			statusCode = ''
			return file.absolutePath,file.name,hashedData,statusCode

	def findFirstFile(self,path): # Needs Redone
		path = self.convertPath(path)
		# print(path)
		if('*' in path or '?' in path):
			print(1)
			#do search with wild cards
			#will have to use Regex searching for this to make like easier
		else:
			node = self.rootDir
			return (self.findFileRecurse(path,node))

	################################
	## Helper Functions
	################################
	def findFileRecurse(self,path,node): # Broken Probably
		#look for the first node in the path, unless it is the C:\ Drive
		if(self.rootDir.name in path[0]):
			path = path[1:]
		nodeToLookFor = path[0]

		
		#If the the path is the final object return the file if it is found in the directory. If it is not found, create the file and return the default file data
		if(len(path) == 1):
			for eachFile in node.files:
				if(eachFile == path[0]):
					return node,eachFile,node.files.get(eachFile)
			#create the file
		#go through the file system and then find the file node that will contain the file
			node.files.update({path[0]:'EMPTY'})
			return node,path[0],node.files.get(path[0])
		for each in node.childrenDir:
			if(each == nodeToLookFor):
				childNode = node.childrenDir.get(each)
				return self.findFileRecurse(path[1:],childNode)
		#if the folder does not exist, create it here, along with the file needed
		filename = path[-1]
		node = self.recurseCreateFolder(node,path[:-1])
		node.files.update({path[-1]:'EMPTY'})
		return node,filename,node.files.get(filename)

	def findFileRegex(self,path):
		print(1) # don't know

	def findAndCreateFolder(self,path):
		path = self.convertPath(path)
		if(len(path) == 1 and path[0].lower() == self.rootDir.name.lower()):
			return self.rootDir
		folder = self.findFolder(path)
		if(folder == None):
			folder = self.recurseCreateFolder(self.rootDir,path)
		return folder

	# def CreateNewFolder(self,folderName: str,ParentFolder: Directory):
		# return {folderName:Directory(folderName,ParentFolder)}
		
	def recurseCreateFolder(self,dirNode,path,i = 1): # remove
		path = self.convertPath(path)
		#make sure we are not going over the path
		if(i >= len(path)):
			return dirNode
		else:
		#check if the child exists and if not create it.
			if(path[i] not in dirNode.childrenDir):
				dirNode.childrenDir.update(self.CreateNewFolder(path[i],dirNode))
				return self.recurseCreateFolder(dirNode.childrenDir.get(path[i]),path,i+1)
			else:
				return self.recurseCreateFolder(dirNode.childrenDir.get(path[i]),path,i+1)

	def getNodeAbsoulte(self,dirNode,dirName,t): # Remove
		#find the nth element of the path
		for eachChild in dirNode.childrenDir:
			child = dirNode.childrenDir.get(eachChild)
			#found part of the correct path
			if(child.name == dirName[t] and child.name != dirName[-1]):
				return self.getNodeAbsoulte(child,dirName,t+1)
			if(child.name == dirName[t] and child.name == dirName[-1]):
				return child

	def getNodeRelative(self,dirNode,dirName): # Remove
		#assuming that the currentDir has been set, as a node
		if dirName[0] == '..':
			parent = dirNode.parentDir
			dirName.remove('..')
			return self.getNodeRelative(parent,dirName)
		#assume dir does not exist
		else:
			return self.recurseCreateFolder(dirNode,dirName,0)
	
	def getPath(self,dirNode,returnList):
		if(dirNode.parentDir == None):
			if("\\" in dirNode.name):
				returnList.insert(0,dirNode.name[0:-1])
			else:
				returnList.insert(0,dirNode.name)
			return returnList
		else:
			returnList.insert(0,dirNode.name)
			return self.getPath(dirNode.parentDir,returnList)
		
	def findFolder(self,path):
		path = self.convertPath(path)
		if path[0] == '..': # The Parent of Current Directory
			return self.getNodeRelative(self.currentDir,path)
		elif path[0] == '.': # The Current Directory
			return self.getNodeRelative(self.currentDir,path)
		else:
			return self.getNodeAbsoulte(self.rootDir,path,1)
		
	def convertPath(self, path): # Don't need will remove
		if isinstance(path,str):
			#normalize a path to oly be a single \,( \\ -> \, / -> \ )
			if('/' in path):
				pathSplit = path.split('/')
			elif('\\\\' in path):
				pathSplit = path.split('\\\\')
			else:
				pathSplit = path.split('\\')
		else:
			pathSplit = path
		for each in pathSplit:
			if (each == ''):
				pathSplit.remove(each)
		return pathSplit

	def fileOrFolder(self,path):
		REGEX = Artifacts_regex()
		REGEX.initializeRegex()
		if re.search(REGEX.find_totalFiles,path):
			return 1
		else:
			return 0
	
	def altFileName(self,filename,node): # needs work probably remove
		print('==================')
		print(node,filename)
		
		
		#count the numder of repeat files
		n = self.countDuplicateFiles(node,filename)
		print(n)
		filename = filename.upper()
		filenamestr = filename.split('.')
		filename = filenamestr[0]
		# print(filename)
		fileExt = filenamestr[1]
		# print(fileExt)
		if(len(filename) > 8):
			if (n > 9):
				#ex altFile = TE0b15~1
				hex_n = hex(n)
				hex_n = format(n,"04X")
				#default the naming scheme back to 1 for now, later increment this value more
				n = 1
				altFileName = filename[0:2]+str(hex_n) + "~"+str(n)+"."+fileExt
				return altFileName
			else:
				#ex altFile = TestDo~1
				altFilename = filename[0:6] + "~"+str(n)+"."+fileExt
				return altFileName
		return filename

	def countDuplicateFiles(node,filename): # Might not need
		count = 1
		for each in node.files:
			if(each == filename):
				count = count + 1
		return count

	################################
	## Output Functions
	################################
	def printALL(self,dirNode,indent = 0):
		if(indent == 0):
			print(self.rootDir.name)
			if(len(self.rootDir.files) != 0):
				print("*F*"+str(self.rootDir.files))
			indent+=1
		for each in dirNode.childrenDir:
			print(('  ')*indent+each)
			child = dirNode.childrenDir.get(each)
			if(len(child.files) != 0):
				for files in child.files:
					print((' '*indent+"*F*"+str(child.files)))
			self.printALL(child,indent+1)

	def printDirTree(self):
		def printDirTreeRecursive(key: 'Union[Directory,File]', level=0):
			if level == 0:
				print(key.name)
			else:
				print(('  ' * level) + '└─╴' + key.absolutePath)
			for fKey, fVal in key.files.items():
				print(('  ' * (level+1)) + '└─╴' + fVal.absolutePath)
			for dKey, dVal in key.childrenDir.items():
				printDirTreeRecursive(dVal, level+1)

		print('File System Tree')
		# for name, value in self.rootDir.childrenDir.items():
			# printDirTreeRecursive(value)
		printDirTreeRecursive(self.rootDir)
		print('\n')

	def outputFilesCreated(self):
		pass # Will add soon
		#check if output is enabled or not.
		# print(Configuration().search_default_outdir) # 
		# if Configuration().default_outdir == "current_dir":
			# outDir = os.path.join(os.path.dirname(__file__), "sharem", "logs")
		# else:
			# outDir = sharem_out_dir
		# print(1)
		# print(Directory_system.allFilePaths)
		# self.printDirTree()
		#output the files to the output directory given in the config

############################################################################################
############################			Documentation			############################
############################################################################################
#	The file system will keep track of any movement and file changes to a blank windows 
#		file system. There is an option in our config to allow downloading files from 
#		the internet and which we will show the file hash, and the status code of the 
#		website attempted to be reached.
#
#	All the 'files' in our system have dummy data of "EMPTY" if they were touched by the
#		shellcode or if our download failed.
#
#	Folders will be auto generated for when the shellcode accesses them if they do not
#		exist before.
#
#	TO DO:
#		* Potentially allow for the existance of files that the shellcode touches to be
#			put onto the local file system. Those files would only be put with read only.
#
#		* Allow for the user to input files that the shellcode uses. These files would be
#			a list from the config, and put in the current working directory as files.
#			** Add a file priority list for in this case where if the shellcode tries to
#				find the file we look in that priority list and then return that with its data
#
#		* 
#
#
#
#