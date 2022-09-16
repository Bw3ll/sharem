from tkinter import Variable

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
class Directory_system:
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
		self.currentDir = Configuration().simulatedValues_start_directory
		self.rootDir = Dir_nodes(driveLetter)
		# self.currentDir = self.rootDir
		self.rootDir.childrenDir.update(self.CreateNewFolder('Microsoft',self.rootDir))
		self.rootDir.childrenDir.update(self.CreateNewFolder('Program Files',self.rootDir))
		self.rootDir.childrenDir.update(self.CreateNewFolder('Program Files(x86)',self.rootDir))
		self.rootDir.childrenDir.update(self.CreateNewFolder('ProgramData',self.rootDir))
		self.rootDir.childrenDir.update(self.CreateNewFolder('Users',self.rootDir))
		self.rootDir.childrenDir.update(self.CreateNewFolder('Windows',self.rootDir))
		
		##can have the possiblilty of multiple users
		self.users = Configuration().simulatedValues_users # Get List of Users To Create
		self.usersDir = self.rootDir.childrenDir.get('Users')
		self.usersDir.childrenDir.update(self.CreateUsers(self.usersDir))

		#create the default windows folder
		self.windowsDir = self.rootDir.childrenDir.get('Windows')
		self.windowsDir.childrenDir.update(self.CreateWindowsFolder(self.windowsDir))

		self.currentDirPath = self.setCurrentDir(self.currentDir,1)
		
	def CreateUsers(self,usersDir):
		usersFolder = {}
		usersFolder.update(self.CreateNewFolder('Default',usersDir))
		usersFolder.update(self.CreateNewFolder('Public',usersDir))
		#userName derived from config
		usersFolder.update(self.CreateNewFolder('Administrator',usersDir))
		for username in self.users:
		#    username =details_dict.get(each)
		#    username = str(username)
			usersFolder.update(self.CreateNewFolder(username,usersDir))
		for each in usersFolder:
			uFolder = usersFolder.get(each)
			self.CreateUsersCommonFolders(uFolder)
		return usersFolder
	
	def CreateWindowsFolder(self,windowsDir):
		#add more folders if needed later
		windowsFolder = {}
		windowsFolder.update(self.CreateNewFolder('System32',windowsDir))
		windowsFolder.update(self.CreateNewFolder('SysWOW64',windowsDir))
		return windowsFolder
	
	def CreateUsersCommonFolders(self,user):
		user.childrenDir.update(self.CreateNewFolder('AppData',user))
		user.childrenDir.update(self.CreateNewFolder('Desktop',user))
		user.childrenDir.update(self.CreateNewFolder('Documents',user))
		user.childrenDir.update(self.CreateNewFolder('Downloads',user))
		user.childrenDir.update(self.CreateNewFolder('Favorites',user))
		user.childrenDir.update(self.CreateNewFolder('Links',user))
		user.childrenDir.update(self.CreateNewFolder('Pictures',user))
		user.childrenDir.update(self.CreateNewFolder('Music',user))
		user.childrenDir.update(self.CreateNewFolder('Saved Games',user))
		user.childrenDir.update(self.CreateNewFolder('Videos',user))
	
	def getFileDependencies(self,config):
		#get the inputted files from the user that the shellcode depends on
		#!!DOES NOT WORK CURRENTLY!!
		print(1)
	################################
	## Api Functions
	################################
	def setCurrentDir(self,dirSTR,typePath):
		dirSTR = self.convertPath(dirSTR)

		#Absolute Path
		if (typePath != 0):
			self.currentDir = (self.getNodeAbsoulte(self.rootDir,dirSTR,1))
			#create folder(s) and set the current directory
			if(self.currentDir == None):
				self.recurseCreateFolder(self.rootDir,dirSTR)
				self.currentDir = (self.getNodeAbsoulte(self.rootDir,dirSTR,1))
			#return the absolute path
			path_list = []
			path_list = self.getPath(self.currentDir,path_list)
			path_list = "\\".join(path_list)
			return path_list
		# Relative Path
		else:
			t = 0
			for each in dirSTR:
				if(each == '..'):
					t+=1
			self.currentDir = (self.getNodeRelative(self.currentDir,dirSTR))
			path_list = []
			path_list = self.getPath(self.currentDir,path_list)
			path_list = "\\".join(path_list)
			return path_list

	def createFile(self,path,fileName,fileData = 'EMPTY'):
		path = self.convertPath(path)
		folderNode = self.findAndCreateFolder(path)
		try:
			folderNode.files.update({fileName:fileData})
		except:
			hashedData = hashlib.md5(fileData)
			hashedData = hashedData.hexdigest()
			folderNode.files.update({fileName:hashedData})
		
	def writeFile(self,path,fileName,fileData = 'EMPTY'):
		path = self.convertPath(path)
		folderNode = self.findAndCreateFolder(path)
		folderNode.files.update({fileName:fileData})

	def moveFile(self,origin,destination,replace):
		#overwrite the file in the destination folder.
		if(replace == 0x1):
			origin = self.convertPath(origin)
			destination = self.convertPath(destination)
			fileName = origin[-1]
			destFileName = destination[-1]
			folderOrigin = self.findAndCreateFolder(origin[:-1])
			folderDest = self.findAndCreateFolder(destination[:-1])

			#get file data if it exists, otherwise create the file and put our sample data within it.
			fileData = folderOrigin.files.get(fileName)
			if(fileData == None):
				self.createFile(origin[:-1],fileName)
				fileData = folderOrigin.files.get(fileName)

			#if the file exists, and option 0x1 is turned on
			
			folderDest.files.update({destFileName:fileData})
			del folderOrigin.files[fileName]

		#rename the file if there is a duplicate in the dest folder
		else:
			origin = self.convertPath(origin)
			destination = self.convertPath(destination)
			fileName = origin[-1]
			destFileName = destination[-1]
			folderOrigin = self.findAndCreateFolder(origin[:-1])
			folderDest = self.findAndCreateFolder(destination[:-1])

			#check if the file exists and rename the destinationFile
			destFileName = self.checkFileDuplicate(folderDest,destFileName)


			#get file data if it exists, otherwise create the file and put our sample data within it.
			fileData = folderOrigin.files.get(fileName)
			if(fileData == None):
				self.createFile(origin[:-1],fileName)
				fileData = folderOrigin.files.get(fileName)

			folderDest.files.update({destFileName:fileData})
			del folderOrigin.files[fileName]
		
		return '\\'.join(destination), '\\'.join(origin),fileName,destFileName

	def copyFile(self,origin,destination):
		origin = self.convertPath(origin)
		destination = self.convertPath(destination)
		fileName = origin[-1]
		destFileName = destination[-1]
		folderOrigin = self.findAndCreateFolder(origin[:-1])
		folderDest = self.findAndCreateFolder(destination[:-1])
		destFileName = self.checkFileDuplicate(folderDest,destFileName)

		#get file data if it exists, otherwise create the file and put our sample data within it.
		fileData = folderOrigin.files.get(fileName)
		if(fileData == None):
			self.createFile(origin[:-1],fileName)
			fileData = folderOrigin.files.get(fileName)

		
		folderDest.files.update({destFileName:fileData})

		return destFileName, fileName, '\\'.join(destination), '\\'.join(origin)

	def deleteFile(self,path):
		path = self.convertPath(path)
		filename = path[-1]
		folder = self.findAndCreateFolder(path[:-1])
		if(filename in folder.files):
			filedata = folder.files.get(filename)
			del folder.files[filename]
		else:
			filedata = 'File did not exist when shellcode tried to delete'

		self.deletedFiles.append({filename:filedata})
		# print(self.deletedFiles)
		return '\\'.join(path),filename

	def readFile(self,node,filename):
		if(filename in node.files):
			filedata = node.files.get(filename)
		else:
			filedata = 'File did not exist when shellcode tried to read'
		path = []
		path = self.getPath(node,path)
		
		return '\\'.join(path),filename, filedata

	def moveFolder(self,origin,destination,replace):
		origin = self.convertPath(origin)
		destination = self.convertPath(destination)
		folderOrigin = self.findAndCreateFolder(origin)
		folderDest = self.findAndCreateFolder(destination)
		folderOrigin.parentDir = folderDest
		return '\\'.join(destination), '\\'.join(origin)

	def internetDownload(self,origin,dest):
		dest = self.convertPath(dest)
		if(len(dest) == 1):
			fileName = dest
			dest = self.convertPath(self.currentDirPath)
		else:
			fileName = dest[-1]
			dest = dest[:-1]
		# print(fileName,dest)
		#check that the user wants to download files
		conf = Configuration()
		conf.simulatedValues_download_files = True # Needs Fixed
		if conf.simulatedValues_download_files:
			#move the manager to somewhere else that we can turn on and off with the config useage.
			http = urllib3.PoolManager(num_pools=1)
			r = http.request('GET',origin)
			#check the status code
			if(r.status == 200):
				hashedData = hashlib.md5(r.data)
				hashedData = hashedData.hexdigest()
				# print(len(r.data))
				self.createFile(path=dest,fileName=fileName,fileData=r.data)
				return '\\'.join(dest),fileName,hashedData,r.status
			else:
				# print(r.status)
				#error retrieving the file, give them a dummy data file
				self.createFile(dest,fileName)
				hashedData = ''
				return '\\'.join(dest),fileName,hashedData,r.status
		else:
			#create the file with dummy data
			# print('download is disabled')
			self.createFile(dest,fileName)
			hashedData = ''
			statusCode = ''
			return '\\'.join(dest),fileName,hashedData,statusCode

	def findFirstFile(self,path):
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
	def findFileRecurse(self,path,node):
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
		print(1)

	def findAndCreateFolder(self,path):
		path = self.convertPath(path)
		if(len(path) == 1 and path[0].lower() == self.rootDir.name.lower()):
			return self.rootDir
		folder = self.findFolder(path)
		if(folder == None):
			folder = self.recurseCreateFolder(self.rootDir,path)
		return folder

	def CreateNewFolder(self,folderName,ParentFolder):
		return {folderName:Dir_nodes(folderName,ParentFolder)}
		
	def recurseCreateFolder(self,dirNode,path,i = 1):
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

	def getNodeAbsoulte(self,dirNode,dirName,t):
		#find the nth element of the path
		for eachChild in dirNode.childrenDir:
			child = dirNode.childrenDir.get(eachChild)
			#found part of the correct path
			if(child.name == dirName[t] and child.name != dirName[-1]):
				return self.getNodeAbsoulte(child,dirName,t+1)
			if(child.name == dirName[t] and child.name == dirName[-1]):
				return child

	def getNodeRelative(self,dirNode,dirName):
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
		
	def detectDuplicateFileHandles(self,node,handle):
		#on creation detect if there is a duplicate file name and then rename it accordingly append '(N)' where n is the number of times it is duplicated starting at 1
		count = 0

		for eachFile in node.files:
			if(eachFile == handle.name):
				count = count + 1
		if(count > 0):
			try:
				splitName = handle.name.split(".")
				newFileName =  splitName[0] +"("+str(count)+")."+ splitName[1]
			except:
				newFileName =  handle.name +"("+str(count)+")"
				
			return newFileName
		else:
			return handle.name

	def checkFileDuplicate(self,node,fileName):
		#on creation detect if there is a duplicate file name and then rename it accordingly append '(N)' where n is the number of times it is duplicated starting at 1
		count = 0

		for eachFile in node.files:
			if(eachFile == fileName):
				count = count + 1
		if(count > 0):
			try:
				splitName = fileName.split(".")
				newFileName =  splitName[0] +"("+str(count)+")."+ splitName[1]
			except:
				newFileName =  fileName +"("+str(count)+")"
				
			return newFileName
		else:
			return fileName

	def findFolder(self,path):
		path = self.convertPath(path)
		if path[0] == '..': # The Parent of Current Directory
			return self.getNodeRelative(self.currentDir,path)
		elif path[0] == '.': # The Current Directory
			return self.getNodeRelative(self.currentDir,path)
		else:
			return self.getNodeAbsoulte(self.rootDir,path,1)
		
	def convertPath(self, path):
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
	
	def altFileName(self,filename,node):
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

	def countDuplicateFiles(node,filename):
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

	def outputFilesCreated(self):
		#check if output is enabled or not.
		print(Configuration().search_default_outdir)
		# if Configuration().default_outdir == "current_dir":
			# outDir = os.path.join(os.path.dirname(__file__), "sharem", "logs")
		# else:
			# outDir = sharem_out_dir
		print(1)
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