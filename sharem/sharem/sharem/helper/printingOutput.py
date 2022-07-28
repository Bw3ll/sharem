import colorama
import textwrap3

colorama.init()


class PrintingOutput:
    def __init__(self):
        self.txtOut = ""
        self.emulation_dict = { 
            "api_calls":[],
            "syscalls_emulation":[],
            "dlls":[],
            "path_artifacts":[],
            "file_artifacts":[],
            "commandLine_artifacts":[],
            "web_artifacts":[],
            "exe_dll_artifacts":[],
            "registry_actions":[],
            "registry_techniques":[],
            "registry_hierarchy":[],
            "registry_miscellaneous":[]
	    }
        self.red ='\u001b[31;1m'
        self.gre = '\u001b[32;1m'
        self.yel = '\u001b[33;1m'
        self.blu = '\u001b[34;1m'
        self.mag = '\u001b[35;1m'
        self.cya = '\u001b[36;1m'
        self.whi = '\u001b[37m'
        self.res = '\u001b[0m'
        self.res2 = '\u001b[0m'



    def colors(self):
        #keep
        red ='\u001b[31;1m'
        gre = '\u001b[32;1m'
        yel = '\u001b[33;1m'
        blu = '\u001b[34;1m'
        mag = '\u001b[35;1m'
        cya = '\u001b[36;1m'
        whi = '\u001b[37m'
        res = '\u001b[0m'
        res2 = '\u001b[0m'

        return red,gre,yel,blu,mag,cya,whi,res,res2

#####################
#######  TEXT  ######
#####################

    def apisOut(self,emulation_verbose,api_names, api_params_values, api_params_types, api_params_names, api_address, ret_values, ret_type, api_bruteforce, syscallID):
        text_output = ""

        red,gre,yel,blu,mag,cya,whi,res,res2 = self.colors()

        text_output += mag + "\n************* APIs *************\n\n" + res
            # no_colors_out += "\n************* APIs *************\n\n"

        verbose_mode = emulation_verbose
        t = 0
        for eachApi in api_names:
            tuple_flag = 0
            apName = api_names[t]
            offset = api_address[t]
            pType = api_params_types[t]
            pName = api_params_names[t]
            TypeBundle = []
            retVal = ret_values[t]
            retType = ret_type[t]
            paramVal = api_params_values[t]
            paramVal_tuple = api_params_values[t]
            # print(paramVal)
            for potentialTuple in paramVal:
                if( type(potentialTuple) == tuple):
                    # print("is a tuple")
                    # print(potentialTuple)
                    tuple_flag = 1
                    

            # DLL = dll_name[t]
            for v, typ in zip(pType, pName):
                TypeBundle.append(v + " " + typ)
            joinedBund = ', '.join(TypeBundle)
            try:
                joinedBund= (textwrap3.fill(joinedBund, width=170, break_long_words=False))
            except:
                pass
            joinedBundclr = joinedBund.replace(",", cya + "," + res)
            retBundle = retType + " " + retVal

            if verbose_mode:
                temp = '{} {}{}\n'.format(gre + offset + res, yel + apName + res,
                                                cya + "(" + res + joinedBundclr + cya + ")" + res)  # Example: WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
                text_output+= (textwrap3.fill(temp, width=170, break_long_words=False))
                text_output+="\n"

            else:
                text_output += '{} {}{} {}{}\n'.format(gre + offset + res, yel + apName + res,
                                                    cya + "(" + res + joinedBundclr + cya + ")" + res,
                                                    cya + "Ret: " + res,
                                                    red + retBundle + res)  # Example: WinExec(LPCSTR lpCmdLine, UINT uCmdShow)

            t += 1
            if verbose_mode:
                if (tuple_flag == 1):
                    text_output += self.printTuples(paramVal,pType,pName,retBundle)
                else:
                    for ptyp, pname, pval in zip(pType, pName, paramVal):
                        text_output += '\t{} {} {}\n'.format(cya + ptyp, pname + ":" + res, pval)
                    text_output += "\t{} {}\n".format(red + "Return:" + res, retBundle)
                if api_bruteforce:
                    text_output += "\t{}\n\n".format(whi + "Brute-forced" + res, )
                else:
                    text_output += "\n"

                # no_colors_out += "\t{} {}\n\n".format( "Return:", retVal)

                    
        return text_output
    
    def syscallsOut(self,emulation_verbose,syscall_names, syscall_params_values, syscall_params_types, syscall_params_names, syscall_address, ret_values, ret_type, syscall_bruteforce, syscallID,em):
        text_output = ""

        red,gre,yel,blu,mag,cya,whi,res,res2 = self.colors()
        
        text_output += mag + "\n************* Syscalls *************\n\n" + res
        verbose_mode = emulation_verbose
        t = 0
        for eachApi in syscall_names:
            apName = syscall_names[t]
            offset = syscall_address[t]
            pType = syscall_params_types[t]
            pName = syscall_params_names[t]
            TypeBundle = []
            retVal = ret_values[t]
            retType = ret_type[t]
            paramVal = syscall_params_values[t]
            # DLL = dll_name[t]
            for potentialTuple in paramVal:
                if( type(potentialTuple) == tuple):
                    # print("is a tuple")
                    # print(potentialTuple)
                    tuple_flag = 1
            for v, typ in zip(pType, pName):
                TypeBundle.append(v + " " + typ)
            joinedBund = ', '.join(TypeBundle)
            joinedBundclr = joinedBund.replace(",", cya + "," + res)
            retBundle = retType + " " + retVal

            if verbose_mode:
                text_output += '{} {}{}\n'.format(gre + offset + res, yel + apName + res,
                                                    cya + "(" + res + joinedBundclr + cya + ")" + res)  # Example: WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
            else:
                text_output += '{} {}{} {}{}\n'.format(gre + offset + res, yel + apName + res,
                                                    cya + "(" + res + joinedBundclr + cya + ")" + res,
                                                    cya + "Ret: " + res,
                                                    red + retBundle + res)  # Example: WinExec(LPCSTR lpCmdLine, UINT uCmdShow)

            t += 1
            if verbose_mode:
                if (tuple_flag == 1):
                    text_output += self.printTuples(paramVal,pType,pName,retBundle)
                else:
                    for ptyp, pname, pval in zip(pType, pName, paramVal):
                        text_output += '\t{} {} {}\n'.format(cya + ptyp, pname + ":" + res, pval)
                    text_output += "\t{} {}\n".format(red + "Return:" + res, retBundle)
                text_output += "\t{} {} - ({}, SP {})\n".format(red + "EAX: " + res, hex(syscallID) + res, em.winVersion + res, em.winSP + res)
                if syscall_bruteforce:
                    text_output += "\t{}\n\n".format(whi + "Brute-forced" + res, )
                else:
                    text_output += "\n"

        return text_output

    def artifactsOut(self,art,emulation_multiline,logged_dlls):
        text_output = ""

        if emulation_multiline:
            emu_dll_list = self.multiLine(logged_dlls)
            text_output += self.mag + "\n************* DLLs *************\n" + self.res
            text_output += "{}{:<18} {}\n".format(self.cya + "DLLs" + self.res, "",emu_dll_list)

            emu_path_list = self.multiLine(art.path_artifacts)
            emu_pathMove_list = self.multiLineTransition(art.path_move)
            emu_pathCopy_list = self.multiLineTransition(art.path_copy)
            
            emu_filesMisc_list = self.multiLine(art.file_artifacts)
            emu_filesCreate_list = self.multiLine(art.files_create)
            emu_filesWrite_list = self.multiLine(art.files_write)
            emu_filesDelete_list = self.multiLine(art.files_delete)
            emu_filesAccess_list = self.multiLine(art.files_access)
            emu_filesCopy_list = self.multiLineTransition(art.files_copy)
            emu_filesMoved_list = self.multiLineTransition(art.files_move)
            
            emu_commandline_list = self.multiLine(art.commandLine_artifacts)
            
            emu_webArtifacts_list = self.multiLine(art.web_artifacts)
            
            emu_exe_dll_list = self.multiLine(art.exe_dll_artifacts)
            
            emu_registry_list = self.multiLine(art.registry_misc)
            emu_registry_add_list = self.multiLine(art.registry_add_keys)
            emu_registry_edit_list = self.multiLineTupleRegistry(art.registry_edit_keys)
            emu_registry_delete_list = self.multiLineTupleRegistry(art.registry_delete_keys)
            emu_registry_persistence_list = self.multiLine(art.registry_persistence)
            emu_registry_credentials_list = self.multiLine(art.registry_credentials)
            emu_registry_discovery_list = self.multiLine(art.registry_discovery)
            emu_registry_hkcr_list = self.multiLine(art.reg_HKCR)
            emu_registry_hkcu_list = self.multiLine(art.reg_HKCU)
            emu_registry_hklm_list = self.multiLine(art.reg_HKLM)
            emu_registry_hku_list = self.multiLine(art.reg_HKU)
            emu_registry_hkcc_list = self.multiLine(art.reg_HKCC)
            
        else:
            emu_dll_list= ', '.join(logged_dlls)
            text_output += mag + "\n************* DLLs *************\n" + res
            text_output += "{}{:<18} {}\n".format(self.cya + "DLLs" + self.res, "",emu_dll_list)
            emu_path_list = ', '.join(path_artifacts)
            # emu_fileArtifacts_list = ", ".join(art.file_artifacts)
            emu_commandline_list = ", ".join(art.commandLine_arg)
            emu_webArtifacts_list = ', '.join(art.web_artifacts)
            emu_registry_list = ", ".join(art.registry_misc)
            emu_exe_dll_list = ", ".join(art.exe_dll_artifacts)
            emu_registry_add_list = ', '.join(art.registry_add_keys)
            emu_registry_edit_list = ', '.join(art.registry_edit_keys)
            emu_registry_delete_list = ', '.join(art.registry_delete_keys)
            emu_registry_persistence_list = ', '.join(art.registry_persistence)
            emu_registry_credentials_list = ', '.join(art.registry_credentials)
            emu_registry_discovery_list = ', '.join(art.registry_discovery)
            emu_registry_hkcr_list = ', '.join(art.reg_HKCR)
            emu_registry_hkcu_list = ', '.join(art.reg_HKCU)
            emu_registry_hklm_list = ', '.join(art.reg_HKLM)
            emu_registry_hku_list = ', '.join(art.reg_HKU)
            emu_registry_hkcc_list = ', '.join(art.reg_HKCC)
            emu_filesCreate_list = ', '.join(art.files_create)
            emu_filesWrite_list = ', '.join(art.files_write)
            emu_filesDelete_list = ', '.join(art.files_delete)
            emu_filesAccess_list = ', '.join(art.files_access)
            emu_filesCopy_list = ', '.join(art.files_copy)
            emu_filesMoved_list = ', '.join(art.files_move)
            emu_filesMisc_list = ', '.join(art.file_artifacts)
            emu_pathCopy_list = ', '.join(art.path_copy)
            emu_pathMove_list = ', '.join(art.path_move)
    
        text_output += self.mag + "\n************* Artifacts *************\n" 

        #paths
        text_output += self.Ppaths(art,emu_path_list,emu_pathCopy_list,emu_pathMove_list)

        # files 
        text_output += self.Pfiles(art,emu_filesCreate_list,emu_filesWrite_list,emu_filesDelete_list,emu_filesAccess_list,emu_filesCopy_list,emu_filesMoved_list,emu_filesMisc_list)
       
        # commandline artifacts
        if len(art.commandLine_artifacts) > 0:
            text_output += "{}{:<8} {}\n".format(self.cya + "*** Command Line ***" + self.res,"", emu_commandline_list)
        #web
        if len(art.web_artifacts) > 0:
            text_output += "{}{:<13} {}\n".format(self.cya + "*** Web ***" + self.res,"", emu_webArtifacts_list)
        #exe dlls
        if len(art.exe_dll_artifacts) > 0:
            text_output += "{}{:<8} {}\n".format(self.cya + "*** EXE / DLLs ***" + self.res,"", emu_exe_dll_list)
        
        # registry
        text_output += self.Pregistry(art,emu_registry_add_list,emu_registry_edit_list,emu_registry_delete_list,emu_registry_persistence_list,emu_registry_credentials_list,emu_registry_discovery_list,emu_registry_hkcr_list,emu_registry_hkcu_list,emu_registry_hklm_list,emu_registry_hku_list,emu_registry_hkcc_list,emu_registry_list)

        return text_output


#####################
####  Artifacts  ####
#####################

    def Ppaths(self,art,emu_path_list,emu_pathCopy_list,emu_pathMove_list):
        text_output = ''

        if (len(art.path_artifacts) > 0 or len(art.path_copy) > 0 or len(art.path_move) > 0):
            text_output += "{}{:<9}\n".format(self.cya + "*** Paths ***" + self.res,"")
        if(len(art.path_copy) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Copy **" + self.res,"", emu_pathCopy_list)
        if(len(art.path_move) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Move **" + self.res,"", emu_pathMove_list)
        if(len(art.path_artifacts) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Misc **" + self.res,"", emu_path_list)	
        
        return text_output

    def Pfiles(self,art,emu_filesCreate_list,emu_filesWrite_list,emu_filesDelete_list,emu_filesAccess_list,emu_filesCopy_list,emu_filesMoved_list,emu_filesMisc_list):
        text_output = ""
        if(len(art.files_create) > 0 or len(art.files_write) > 0 or len(art.files_delete) > 0 or len(art.files_access) > 0 or len(art.files_copy) > 0 or len(art.files_move) > 0 or len(art.file_artifacts) > 0):
            text_output += "{}{:<9}\n".format(self.cya + "*** Files ***" + self.res,"")
        if(len(art.files_create) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Create **" + self.res,"", emu_filesCreate_list)
        if(len(art.files_write) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Write **" + self.res,"", emu_filesWrite_list)
        if(len(art.files_delete) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Delete **" + self.res,"", emu_filesDelete_list)
        if(len(art.files_access) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Read **" + self.res,"", emu_filesAccess_list)
        if(len(art.files_copy) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Copy **" + self.res,"", emu_filesCopy_list)
        if(len(art.files_move) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Move **" + self.res,"", emu_filesMoved_list)	
        if(len(art.file_artifacts) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Misc **" + self.res,"", emu_filesMisc_list)	
        
        return text_output

    def Pregistry(self,art,emu_registry_add_list,emu_registry_edit_list,emu_registry_delete_list,emu_registry_persistence_list,emu_registry_credentials_list,emu_registry_discovery_list,emu_registry_hkcr_list,emu_registry_hkcu_list,emu_registry_hklm_list,emu_registry_hku_list,emu_registry_hkcc_list,emu_registry_list):
        text_output = ""
        ####### Registry Actiions #########
        if (len(art.registry_add_keys) > 0 or len(art.registry_edit_keys) > 0 or len(art.registry_delete_keys) > 0):
            text_output += "{}{:<9}\n".format(self.cya + "*** Registry Actions ***" + self.res,"")
        if len(art.registry_add_keys) > 0:
            text_output += "{}{:<9} {}\n".format(self.red + "** Add **" + self.res,"", emu_registry_add_list)
        if len(art.registry_edit_keys) > 0:
            text_output += "{}{:<9} {}\n".format(self.red + "** Edit **" + self.res,"", emu_registry_edit_list)
        if len(art.registry_delete_keys) > 0:
            text_output += "{}{:<9} {}\n".format(self.red + "** Delete **" + self.res,"", emu_registry_delete_list)

        ####### Registry Techniques #########
        if (len(art.registry_persistence) > 0 or len(art.registry_credentials) > 0 or len(art.registry_discovery) > 0):
            text_output += "{}{:<9}\n".format(self.cya + "*** Registry Techniques ***" + self.res,"")
        if (len(art.registry_persistence) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Persistence **" + self.res,"", emu_registry_persistence_list)
        if (len(art.registry_credentials) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Credentials **" + self.res,"", emu_registry_credentials_list)
        if (len(art.registry_discovery) > 0):
            text_output += "{}{:<9} {}\n".format(self.red + "** Discovery **" + self.res,"", emu_registry_discovery_list)

        ####### Registry Hierarchy #########
        if(len(art.reg_HKCR) > 0 or len(art.reg_HKCU) > 0 or len(art.reg_HKLM) > 0 or len(art.reg_HKU) > 0 or len(art.reg_HKCC) > 0):
            text_output += "{}{:<9}\n".format(self.cya + "*** Registry Hierarchy ***" + self.res,"")
        if(len(art.reg_HKCR) > 0 ):
            text_output += "{}{:<9} {}\n".format(self.red + "** HKEY_Classes_Root **" + self.res,"", emu_registry_hkcr_list)
        if(len(art.reg_HKCU) > 0 ):
            text_output += "{}{:<9} {}\n".format(self.red + "** HKEY_Current_User **" + self.res,"", emu_registry_hkcu_list)
        if(len(art.reg_HKLM) > 0 ):
            text_output += "{}{:<9} {}\n".format(self.red + "** HKEY_Local_Machine **" + self.res,"", emu_registry_hklm_list)
        if(len(art.reg_HKU) > 0 ):
            text_output += "{}{:<9} {}\n".format(self.red + "** HKEY_Users **" + self.res,"", emu_registry_hku_list)
        if(len(art.reg_HKCC) > 0 ):
            text_output += "{}{:<9} {}\n".format(self.red + "** HKEY_Current_Config **" + self.res,"", emu_registry_hkcc_list)
        
        ####### Registry Miscellaneous #########
        if len(art.registry_misc) > 0:
            text_output += "{}{:<9} {}\n".format(self.cya + "*** Registry Miscellaneous ***" + self.res,"", emu_registry_list)

        return text_output

#####################
#####  Helpers  #####
#####################

    def printTuples(self,paramVal,pType,pName,retBundle):
        text_output = ""
        red,gre,yel,blu,mag,cya,whi,res,res2 = self.colors()
        index = 0

        for pv in paramVal:
            # if there is a structure
            if(type(paramVal[index]) == tuple):
                structure_names = paramVal[index][0]
                structure_types = paramVal[index][1]
                structure_values = paramVal[index][2]
                #find the dummy struct
                
                # if(next):
                #     text_output += text_output1

                        # print(dict(each))
                #structure Name:
                text_output += '\t{} {} \n'.format(cya + pType[index], pName[index] + ":")
                z = 0

                #prints the variables within the strucutes
                for sn in structure_names:
                    #checks if there is another strucutre within the struct, usually a dummy struct and prints it
                    #currently only works for one struct and one dummy struct
                    try:
                        struc_values_temp=str(structure_values[z])

                    except:
                        struc_values_temp=structure_values[z]
                    # print (struc_values_temp, type(struc_values_temp))
                    if('{' in struc_values_temp):
                        text_output += self.unionStruct(structure_values,structure_names[z],structure_types[z])
                        z += 1
                        continue
                    text_output += '\t\t{} {} {}\n'.format(gre + structure_names[z], structure_types[z] +":"+ res, structure_values[z])
                    z += 1
            #normal printing
            else:
                txt_params='\t{} {} {}\n'.format(cya + pType[index], pName[index] + ":" + res, paramVal[index])

                text_output += txt_params
            index += 1
        text_output += "\t{} {}\n".format(red + "Return:" + res, retBundle)
        return text_output
        
    def unionStruct(self,structure_values,pType,pName):
        for each in structure_values:
            # print(each)
            # print(type(each))
            if ('{' in each):
                #remove the {}s from string so we can check if there is another struct within this.
                each = each[1:-1]
                unionStruct = each.split(',')
                #have a list of values
                # print(unionStruct)
                #recurse the list to check for more structures
                
        text_output = ''
        red,gre,yel,blu,mag,cya,whi,res,res2 = self.colors()

        #structure name
        text_output += '\t\t{} {} \n'.format(cya + pType, pName + ":")
        for each in unionStruct:
            structList = each.split(" ")
            #remove a space in the list that keeps appearing
            if('' in structList):
                structList.remove("")
            structList[1] = structList[1][:-1]
            #for now this will not work as we do not have a triple struct
            # if('{' in structList):
            #     self.unionStruct(structList)
            
            text_output += '\t\t\t{} {} {}\n'.format(gre + structList[0], structList[1] +":"+ res, structList[2])
        return text_output

    def multiLine(self,artifact):
        if(len(artifact) > 0):
            emu_artifact_list = "\n"
            emu_artifact_list += "\n".join(artifact)
            emu_artifact_list += "\n"
            return emu_artifact_list
    
    def multiLineTransition(self,artifact):
        emu_artifact_list = ''
        if(len(artifact) > 0):
                for each in artifact:
                    if (type(each) == tuple):
                        p = 0
                        for o in each:
                            if p == 0:
                                emu_artifact_list += "\n"+o
                            else:
                                emu_artifact_list += " -> "+o
                            p+=1
                    else:
                        emu_artifact_list += "\n"+each
        emu_artifact_list += "\n"
        return emu_artifact_list  

    def multiLineTupleRegistry(self,artifact):
        emu_artifact_list = ''
        if(len(artifact) > 0):
                for each in artifact:
                    if (type(each) == tuple):
                        p = 0
                        for o in each:
                            if p == 0:
                                emu_artifact_list += "\n"+o
                            else:
                                emu_artifact_list += "\n\t"+o
                            p+=1
                    else:
                        emu_artifact_list += "\n"+each
                    emu_artifact_list += "\n"
        return emu_artifact_list

    