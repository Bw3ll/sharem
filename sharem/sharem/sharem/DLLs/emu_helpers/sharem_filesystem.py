class Dir_nodes:
    def __init__(self, nameString,parent = None):
        self.name = nameString
        self.parentDir = parent
        self.childrenDir = {}
        #self.files = []
        # ^ list of files that could be used in the future if we need that.

class Directory_system:
    def __init__(self):
        #drive letter is grabbed from the config
        self.rootDir = None
        self.usersDir = None
        self.windowsDir = None
        self.currentDIR = None  #set this to be something from the config file
       
    def CreateNewFolder(self,folderName,ParentFolder):
        return {folderName:Dir_nodes(folderName,ParentFolder)}
    def InitializeFileSystem(self):
        #Allow drive letter change from the config
        driveLetter = 'C:'
        self.rootDir = Dir_nodes(driveLetter)
        self.currentDIR = self.rootDir
        self.rootDir.childrenDir.update(self.CreateNewFolder('Microsoft',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('Program Files',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('Program Files(x86)',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('ProgramData',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('Users',self.rootDir))
        self.rootDir.childrenDir.update(self.CreateNewFolder('Windows',self.rootDir))
        
        ##can have the possiblilty of multiple users
        self.usersDir = self.rootDir.childrenDir.get('Users')
        self.usersDir.childrenDir.update(self.CreateUsers(self.usersDir))

        #create the default windows folder
        self.windowsDir = self.rootDir.childrenDir.get('Windows')
        self.windowsDir.childrenDir.update(self.CreateWindowsFolder(self.windowsDir))

    def CreateUsers(self,usersDir):
        usersFolder = {}
        usersFolder.update(self.CreateNewFolder('Default',usersDir))
        usersFolder.update(self.CreateNewFolder('Public',usersDir))
        #userName derived from config
        usersFolder.update(self.CreateNewFolder('Administrator',usersDir))
        #for each in details_dict:
        #    username =details_dict.get(each)
        #    username = str(username)
        #    usersFolder.update(self.CreateNewFolder(username,usersDir))
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
    
    def recurseCreateFolder(self,dirNode,path,i = 1):
        if(type(path) == str):
            path = path.split('\\')
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

    def setCurrentDir(self,dirSTR,typePath):
        #Absolute Path
        if (type(dirSTR) == str):
            #normalize a path to oly be a single \,( \\ -> \, / -> \ )
            if('/' in dirSTR):
                dirSTR = dirSTR.split('/')
            elif('\\\\' in dirSTR):
                dirSTR = dirSTR.split('\\\\')
            else:
                dirSTR = dirSTR.split('\\')
        if (typePath != 0):
            self.currentDIR = (self.getNodeAbsoulte(self.rootDir,dirSTR,1))
            #create folder(s) and set the current directory
            if(self.currentDIR == None):
                self.recurseCreateFolder(self.rootDir,dirSTR)
                self.currentDIR = (self.getNodeAbsoulte(self.rootDir,dirSTR,1))
            #return the absolute path
            path_list = []
            path_list = self.getPath(self.currentDIR,path_list)
            path_list = "\\".join(path_list)
            return path_list
        # Relative Path
        else:
            t = 0
            for each in dirSTR:
               if(each == '..'):
                    t+=1
            self.currentDIR = (self.getNodeRelative(self.currentDIR,dirSTR))
            path_list = []
            path_list = self.getPath(self.currentDIR,path_list)
            path_list = "\\".join(path_list)
            return path_list
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
        #assuming that the CurrentDir has been set, as a node
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
    
    def printALL(self,dirNode,indent = 0):
        if(indent == 0):
            print(self.rootDir.name)
            indent+=1
        for each in dirNode.childrenDir:
            print(('  ')*indent+each)
            child = dirNode.childrenDir.get(each)
            self.printALL(child,indent+1)


##create the class to use
directory = Directory_system()
directory.InitializeFileSystem()