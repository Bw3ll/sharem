from .handles import Handle,HandleType,HandlesDict
from .sharem_artifacts import Artifacts_regex
import re

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
    
    ################################
    ## Initize the file system
    ################################
    def InitializeFileSystem(self, config):
        #Allow drive letter change from the config
        driveLetter = config.drive_letter
        self.currentDir = config.start_directory
        self.rootDir = Dir_nodes(driveLetter)
        # self.currentDir = self.rootDir
        self.rootDir.childrenDir.update(self.CreateNewFolder('Microsoft',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('Program Files',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('Program Files(x86)',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('ProgramData',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('Users',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('Windows',self.rootDir))
        
        ##can have the possiblilty of multiple users
        self.users = config.users # Get List of Users To Create
        self.usersDir = self.rootDir.childrenDir.get('Users')
        self.usersDir.childrenDir.update(self.CreateUsers(self.usersDir))

        #create the default windows folder
        self.windowsDir = self.rootDir.childrenDir.get('Windows')
        self.windowsDir.childrenDir.update(self.CreateWindowsFolder(self.windowsDir))

        self.currentDirPath = self.setCurrentDir(config.start_directory,1)
        
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
        folderNode.files.update({fileName:fileData})

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

    def moveFolder(self,origin,destination,replace):
        origin = self.convertPath(origin)
        destination = self.convertPath(destination)
        folderOrigin = self.findAndCreateFolder(origin)
        folderDest = self.findAndCreateFolder(destination)
        folderOrigin.parentDir = folderDest
        return '\\'.join(destination), '\\'.join(origin)

    def internetDownload(self,destination):
        destination = self.convertPath(destination)
        fileName = destination[-1]
        self.createFile(destination[:-1],fileName)
        



    ################################
    ## Helper Functions
    ################################
    def findAndCreateFolder(self,path):
        path = self.convertPath(path)
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
        if ('..' in dirName):
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
    
    #might not need this, holding this function here for now.
    def findFile(self,filename):
        print(1)
        
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
        if('..' in path):
            return self.getNodeRelative(self.currentDir,path)
        else:
            return self.getNodeAbsoulte(self.rootDir,path,1)
        
    def convertPath(self,path):
        if (type(path) == str):
            #normalize a path to oly be a single \,( \\ -> \, / -> \ )
            if('/' in path):
                path = path.split('/')
            elif('\\\\' in path):
                path = path.split('\\\\')
            else:
                path = path.split('\\')
        for each in path:
            if (each == ''):
                path.remove(each)
        return path

    def fileOrFolder(self,path):
        REGEX = Artifacts_regex()
        REGEX.initializeRegex()
        if re.search(REGEX.find_totalFiles,path):
            return 1
        else:
            return 0
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
                print((' '*indent+"*F*"+str(child.files)))
            self.printALL(child,indent+1)

    def outputFilesCreated(self,config):
        #check if output is enabled or not.
        print(1)
        #output the files to the output directory given in the config
        #!!DOES NOT WORK CURRENTLY!!

