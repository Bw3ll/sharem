from capstone import *
import re
import pefile
import sys
import binascii
import copy
#import prog
global MyBytes
global objs




#MOV <REG>, [FS:0x30]
PEB_WALK_MOV = {
	'EAX_OFFSET_NONE': b"\x64\xA1\x30\x00\x00\x00",
	'EAX_OFFSET_EAX':  b"\x64\x8B\x40\x30",
	'EAX_OFFSET_EBX':  b"\x64\x8B\x43\x30",
	'EAX_OFFSET_ECX':  b"\x64\x8B\x41\x30",
	'EAX_OFFSET_EDX':  b"\x64\x8B\x42\x30",
	'EAX_OFFSET_EDI':  b"\x64\x8B\x47\x30",
	'EAX_OFFSET_ESI':  b"\x64\x8B\x46\x30",
	'EAX_OFFSET_EBP':  b"\x64\x8B\x45\x30",
	'EBX_OFFSET_NONE': b"\x64\x8B\x1D\x30\x00\x00\x00",
	'EBX_OFFSET_EAX':  b"\x64\x8B\x58\x30",
	'EBX_OFFSET_EBX':  b"\x64\x8B\x5B\x30",
	'EBX_OFFSET_ECX':  b"\x64\x8B\x59\x30",
	'EBX_OFFSET_EDX':  b"\x64\x8B\x5A\x30",
	'EBX_OFFSET_EDI':  b"\x64\x8B\x5F\x30",
	'EBX_OFFSET_ESI':  b"\x64\x8B\x5E\x30",
	'EBX_OFFSET_EBP':  b"\x64\x8B\x5D\x30",
	'ECX_OFFSET_NONE': b"\x64\x8B\x0D\x30\x00\x00\x00",
	'ECX_OFFSET_EAX':  b"\x64\x8B\x48\x30",
	'ECX_OFFSET_EBX':  b"\x64\x8B\x4B\x30",
	'ECX_OFFSET_ECX':  b"\x64\x8B\x49\x30",
	'ECX_OFFSET_EDX':  b"\x64\x8B\x4A\x30",
	'ECX_OFFSET_EDI':  b"\x64\x8B\x4F\x30",
	'ECX_OFFSET_ESI':  b"\x64\x8B\x4E\x30",
	'ECX_OFFSET_EBP':  b"\x64\x8B\x4D\x30",
	'EDX_OFFSET_NONE': b"\x64\x8B\x15\x30\x00\x00\x00",
	'EDX_OFFSET_EAX':  b"\x64\x8B\x50\x30",
	'EDX_OFFSET_EBX':  b"\x64\x8B\x53\x30",
	'EDX_OFFSET_ECX':  b"\x64\x8B\x51\x30",
	'EDX_OFFSET_EDX':  b"\x64\x8B\x52\x30",
	'EDX_OFFSET_EDI':  b"\x64\x8B\x57\x30",
	'EDX_OFFSET_ESI':  b"\x64\x8B\x56\x30",
	'EDX_OFFSET_EBP':  b"\x64\x8B\x55\x30",
	'EDI_OFFSET_NONE': b"\x64\x8B\x3D\x30\x00\x00\x00",
	'EDI_OFFSET_EAX':  b"\x64\x8B\x78\x30",
	'EDI_OFFSET_EBX':  b"\x64\x8B\x7B\x30",
	'EDI_OFFSET_ECX':  b"\x64\x8B\x79\x30",
	'EDI_OFFSET_EDX':  b"\x64\x8B\x7A\x30",
	'EDI_OFFSET_EDI':  b"\x64\x8B\x7F\x30",
	'EDI_OFFSET_ESI':  b"\x64\x8B\x7E\x30",
	'EDI_OFFSET_EBP':  b"\x64\x8B\x7D\x30",
	'ESI_OFFSET_NONE': b"\x64\x8B\x35\x30\x00\x00\x00",
	'ESI_OFFSET_EAX':  b"\x64\x8B\x70\x30",
	'ESI_OFFSET_EBX':  b"\x64\x8B\x73\x30",
	'ESI_OFFSET_ECX':  b"\x64\x8B\x71\x30",
	'ESI_OFFSET_EDX':  b"\x64\x8B\x72\x30",
	'ESI_OFFSET_EDI':  b"\x64\x8B\x77\x30",
	'ESI_OFFSET_ESI':  b"\x64\x8B\x76\x30",
	'ESI_OFFSET_EBP':  b"\x64\x8B\x75\x30",
	'EBP_OFFSET_NONE': b"\x64\x8B\x2D\x30\x00\x00\x00",
	'EBP_OFFSET_EAX':  b"\x64\x8B\x68\x30",
	'EBP_OFFSET_EBX':  b"\x64\x8B\x6B\x30",
	'EBP_OFFSET_ECX':  b"\x64\x8B\x69\x30",
	'EBP_OFFSET_EDX':  b"\x64\x8B\x6A\x30",
	'EBP_OFFSET_EDI':  b"\x64\x8B\x6F\x30",
	'EBP_OFFSET_ESI':  b"\x64\x8B\x6E\x30",
	'EBP_OFFSET_EBP':  b"\x64\x8B\x6D\x30"
}


#ADD <REG>,[FS:0x30]
PEB_WALK_ADD = {
	'EAX_OFFSET_NONE': b"\x64\x03\x05\x30\x00\x00\x00",
	'EAX_OFFSET_EAX':  b"\x64\x03\x40\x30",
	'EAX_OFFSET_EBX':  b"\x64\x03\x43\x30",
	'EAX_OFFSET_ECX':  b"\x64\x03\x41\x30",
	'EAX_OFFSET_EDX':  b"\x64\x03\x42\x30",
	'EAX_OFFSET_EDI':  b"\x64\x03\x47\x30",
	'EAX_OFFSET_ESI':  b"\x64\x03\x46\x30",
	'EAX_OFFSET_EBP':  b"\x64\x03\x45\x30",
	'EBX_OFFSET_NONE': b"\x64\x03\x1D\x30\x00\x00\x00",
	'EBX_OFFSET_EAX':  b"\x64\x03\x58\x30",
	'EBX_OFFSET_EBX':  b"\x64\x03\x5B\x30",
	'EBX_OFFSET_ECX':  b"\x64\x03\x59\x30",
	'EBX_OFFSET_EDX':  b"\x64\x03\x5A\x30",
	'EBX_OFFSET_EDI':  b"\x64\x03\x5F\x30",
	'EBX_OFFSET_ESI':  b"\x64\x03\x5E\x30",
	'EBX_OFFSET_EBP':  b"\x64\x03\x5D\x30",
	'ECX_OFFSET_NONE': b"\x64\x03\x0D\x30\x00\x00\x00",
	'ECX_OFFSET_EAX':  b"\x64\x03\x48\x30",
	'ECX_OFFSET_EBX':  b"\x64\x03\x4B\x30",
	'ECX_OFFSET_ECX':  b"\x64\x03\x49\x30",
	'ECX_OFFSET_EDX':  b"\x64\x03\x4A\x30",
	'ECX_OFFSET_EDI':  b"\x64\x03\x4F\x30",
	'ECX_OFFSET_ESI':  b"\x64\x03\x4E\x30",
	'ECX_OFFSET_EBP':  b"\x64\x03\x4D\x30",
	'EDX_OFFSET_NONE': b"\x64\x03\x15\x30\x00\x00\x00",
	'EDX_OFFSET_EAX':  b"\x64\x03\x50\x30",
	'EDX_OFFSET_EBX':  b"\x64\x03\x53\x30",
	'EDX_OFFSET_ECX':  b"\x64\x03\x51\x30",
	'EDX_OFFSET_EDX':  b"\x64\x03\x52\x30",
	'EDX_OFFSET_EDI':  b"\x64\x03\x57\x30",
	'EDX_OFFSET_ESI':  b"\x64\x03\x56\x30",
	'EDX_OFFSET_EBP':  b"\x64\x03\x55\x30",
	'EDI_OFFSET_NONE': b"\x64\x03\x3D\x30\x00\x00\x00",
	'EDI_OFFSET_EAX':  b"\x64\x03\x78\x30",
	'EDI_OFFSET_EBX':  b"\x64\x03\x7B\x30",
	'EDI_OFFSET_ECX':  b"\x64\x03\x79\x30",
	'EDI_OFFSET_EDX':  b"\x64\x03\x7A\x30",
	'EDI_OFFSET_EDI':  b"\x64\x03\x7F\x30",
	'EDI_OFFSET_ESI':  b"\x64\x03\x7E\x30",
	'EDI_OFFSET_EBP':  b"\x64\x03\x7D\x30",
	'ESI_OFFSET_NONE': b"\x64\x03\x35\x30\x00\x00\x00",
	'ESI_OFFSET_EAX':  b"\x64\x03\x70\x30",
	'ESI_OFFSET_EBX':  b"\x64\x03\x73\x30",
	'ESI_OFFSET_ECX':  b"\x64\x03\x71\x30",
	'ESI_OFFSET_EDX':  b"\x64\x03\x72\x30",
	'ESI_OFFSET_EDI':  b"\x64\x03\x77\x30",
	'ESI_OFFSET_ESI':  b"\x64\x03\x76\x30",
	'ESI_OFFSET_EBP':  b"\x64\x03\x75\x30",
	'EBP_OFFSET_NONE': b"\x64\x03\x2D\x30\x00\x00\x00",
	'EBP_OFFSET_EAX':  b"\x64\x03\x68\x30",
	'EBP_OFFSET_EBX':  b"\x64\x03\x6B\x30",
	'EBP_OFFSET_ECX':  b"\x64\x03\x69\x30",
	'EBP_OFFSET_EDX':  b"\x64\x03\x6A\x30",
	'EBP_OFFSET_EDI':  b"\x64\x03\x6F\x30",
	'EBP_OFFSET_ESI':  b"\x64\x03\x6E\x30",
	'EBP_OFFSET_EBP':  b"\x64\x03\x6D\x30"
}

#ADC <REG>,[FS:0x30]
PEB_WALK_ADC = {
	'EAX_OFFSET_NONE': b"\x64\x13\x05\x30\x00\x00\x00",
	'EAX_OFFSET_EAX':  b"\x64\x13\x40\x30",
	'EAX_OFFSET_EBX':  b"\x64\x13\x43\x30",
	'EAX_OFFSET_ECX':  b"\x64\x13\x41\x30",
	'EAX_OFFSET_EDX':  b"\x64\x13\x42\x30",
	'EAX_OFFSET_EDI':  b"\x64\x13\x47\x30",
	'EAX_OFFSET_ESI':  b"\x64\x13\x46\x30",
	'EAX_OFFSET_EBP':  b"\x64\x13\x45\x30",
	'EBX_OFFSET_NONE': b"\x64\x13\x1D\x30\x00\x00\x00",
	'EBX_OFFSET_EAX':  b"\x64\x13\x58\x30",
	'EBX_OFFSET_EBX':  b"\x64\x13\x5B\x30",
	'EBX_OFFSET_ECX':  b"\x64\x13\x59\x30",
	'EBX_OFFSET_EDX':  b"\x64\x13\x5A\x30",
	'EBX_OFFSET_EDI':  b"\x64\x13\x5F\x30",
	'EBX_OFFSET_ESI':  b"\x64\x13\x5E\x30",
	'EBX_OFFSET_EBP':  b"\x64\x13\x5D\x30",
	'ECX_OFFSET_NONE': b"\x64\x13\x0D\x30\x00\x00\x00",
	'ECX_OFFSET_EAX':  b"\x64\x13\x48\x30",
	'ECX_OFFSET_EBX':  b"\x64\x13\x4B\x30",
	'ECX_OFFSET_ECX':  b"\x64\x13\x49\x30",
	'ECX_OFFSET_EDX':  b"\x64\x13\x4A\x30",
	'ECX_OFFSET_EDI':  b"\x64\x13\x4F\x30",
	'ECX_OFFSET_ESI':  b"\x64\x13\x4E\x30",
	'ECX_OFFSET_EBP':  b"\x64\x13\x4D\x30",
	'EDX_OFFSET_NONE': b"\x64\x13\x15\x30\x00\x00\x00",
	'EDX_OFFSET_EAX':  b"\x64\x13\x50\x30",
	'EDX_OFFSET_EBX':  b"\x64\x13\x53\x30",
	'EDX_OFFSET_ECX':  b"\x64\x13\x51\x30",
	'EDX_OFFSET_EDX':  b"\x64\x13\x52\x30",
	'EDX_OFFSET_EDI':  b"\x64\x13\x57\x30",
	'EDX_OFFSET_ESI':  b"\x64\x13\x56\x30",
	'EDX_OFFSET_EBP':  b"\x64\x13\x55\x30",
	'EDI_OFFSET_NONE': b"\x64\x13\x3D\x30\x00\x00\x00",
	'EDI_OFFSET_EAX':  b"\x64\x13\x78\x30",
	'EDI_OFFSET_EBX':  b"\x64\x13\x7B\x30",
	'EDI_OFFSET_ECX':  b"\x64\x13\x79\x30",
	'EDI_OFFSET_EDX':  b"\x64\x13\x7A\x30",
	'EDI_OFFSET_EDI':  b"\x64\x13\x7F\x30",
	'EDI_OFFSET_ESI':  b"\x64\x13\x7E\x30",
	'EDI_OFFSET_EBP':  b"\x64\x13\x7D\x30",
	'ESI_OFFSET_NONE': b"\x64\x13\x35\x30\x00\x00\x00",
	'ESI_OFFSET_EAX':  b"\x64\x13\x70\x30",
	'ESI_OFFSET_EBX':  b"\x64\x13\x73\x30",
	'ESI_OFFSET_ECX':  b"\x64\x13\x71\x30",
	'ESI_OFFSET_EDX':  b"\x64\x13\x72\x30",
	'ESI_OFFSET_EDI':  b"\x64\x13\x77\x30",
	'ESI_OFFSET_ESI':  b"\x64\x13\x76\x30",
	'ESI_OFFSET_EBP':  b"\x64\x13\x75\x30",
	'EBP_OFFSET_NONE': b"\x64\x13\x2D\x30\x00\x00\x00",
	'EBP_OFFSET_EAX':  b"\x64\x13\x68\x30",
	'EBP_OFFSET_EBX':  b"\x64\x13\x6B\x30",
	'EBP_OFFSET_ECX':  b"\x64\x13\x69\x30",
	'EBP_OFFSET_EDX':  b"\x64\x13\x6A\x30",
	'EBP_OFFSET_EDI':  b"\x64\x13\x6F\x30",
	'EBP_OFFSET_ESI':  b"\x64\x13\x6E\x30",
	'EBP_OFFSET_EBP':  b"\x64\x13\x6D\x30"
}

#XOR <REG>,[FS:0x30]
PEB_WALK_XOR = {
	'EAX_OFFSET_NONE': b"\x64\x33\x05\x30\x00\x00\x00",
	'EAX_OFFSET_EAX':  b"\x64\x33\x40\x30",
	'EAX_OFFSET_EBX':  b"\x64\x33\x43\x30",
	'EAX_OFFSET_ECX':  b"\x64\x33\x41\x30",
	'EAX_OFFSET_EDX':  b"\x64\x33\x42\x30",
	'EAX_OFFSET_EDI':  b"\x64\x33\x47\x30",
	'EAX_OFFSET_ESI':  b"\x64\x33\x46\x30",
	'EAX_OFFSET_EBP':  b"\x64\x33\x45\x30",
	'EBX_OFFSET_NONE': b"\x64\x33\x1D\x30\x00\x00\x00",
	'EBX_OFFSET_EAX':  b"\x64\x33\x58\x30",
	'EBX_OFFSET_EBX':  b"\x64\x33\x5B\x30",
	'EBX_OFFSET_ECX':  b"\x64\x33\x59\x30",
	'EBX_OFFSET_EDX':  b"\x64\x33\x5A\x30",
	'EBX_OFFSET_EDI':  b"\x64\x33\x5F\x30",
	'EBX_OFFSET_ESI':  b"\x64\x33\x5E\x30",
	'EBX_OFFSET_EBP':  b"\x64\x33\x5D\x30",
	'ECX_OFFSET_NONE': b"\x64\x33\x0D\x30\x00\x00\x00",
	'ECX_OFFSET_EAX':  b"\x64\x33\x48\x30",
	'ECX_OFFSET_EBX':  b"\x64\x33\x4B\x30",
	'ECX_OFFSET_ECX':  b"\x64\x33\x49\x30",
	'ECX_OFFSET_EDX':  b"\x64\x33\x4A\x30",
	'ECX_OFFSET_EDI':  b"\x64\x33\x4F\x30",
	'ECX_OFFSET_ESI':  b"\x64\x33\x4E\x30",
	'ECX_OFFSET_EBP':  b"\x64\x33\x4D\x30",
	'EDX_OFFSET_NONE': b"\x64\x33\x15\x30\x00\x00\x00",
	'EDX_OFFSET_EAX':  b"\x64\x33\x50\x30",
	'EDX_OFFSET_EBX':  b"\x64\x33\x53\x30",
	'EDX_OFFSET_ECX':  b"\x64\x33\x51\x30",
	'EDX_OFFSET_EDX':  b"\x64\x33\x52\x30",
	'EDX_OFFSET_EDI':  b"\x64\x33\x57\x30",
	'EDX_OFFSET_ESI':  b"\x64\x33\x56\x30",
	'EDX_OFFSET_EBP':  b"\x64\x33\x55\x30",
	'EDI_OFFSET_NONE': b"\x64\x33\x3D\x30\x00\x00\x00",
	'EDI_OFFSET_EAX':  b"\x64\x33\x78\x30",
	'EDI_OFFSET_EBX':  b"\x64\x33\x7B\x30",
	'EDI_OFFSET_ECX':  b"\x64\x33\x79\x30",
	'EDI_OFFSET_EDX':  b"\x64\x33\x7A\x30",
	'EDI_OFFSET_EDI':  b"\x64\x33\x7F\x30",
	'EDI_OFFSET_ESI':  b"\x64\x33\x7E\x30",
	'EDI_OFFSET_EBP':  b"\x64\x33\x7D\x30",
	'ESI_OFFSET_NONE': b"\x64\x33\x35\x30\x00\x00\x00",
	'ESI_OFFSET_EAX':  b"\x64\x33\x70\x30",
	'ESI_OFFSET_EBX':  b"\x64\x33\x73\x30",
	'ESI_OFFSET_ECX':  b"\x64\x33\x71\x30",
	'ESI_OFFSET_EDX':  b"\x64\x33\x72\x30",
	'ESI_OFFSET_EDI':  b"\x64\x33\x77\x30",
	'ESI_OFFSET_ESI':  b"\x64\x33\x76\x30",
	'ESI_OFFSET_EBP':  b"\x64\x33\x75\x30",
	'EBP_OFFSET_NONE': b"\x64\x33\x2D\x30\x00\x00\x00",
	'EBP_OFFSET_EAX':  b"\x64\x33\x68\x30",
	'EBP_OFFSET_EBX':  b"\x64\x33\x6B\x30",
	'EBP_OFFSET_ECX':  b"\x64\x33\x69\x30",
	'EBP_OFFSET_EDX':  b"\x64\x33\x6A\x30",
	'EBP_OFFSET_EDI':  b"\x64\x33\x6F\x30",
	'EBP_OFFSET_ESI':  b"\x64\x33\x6E\x30",
	'EBP_OFFSET_EBP':  b"\x64\x33\x6D\x30"
}

#OR <REG>,[FS:0x30]
PEB_WALK_OR = {
	'EAX_OFFSET_NONE': b"\x64\x0B\x05\x30\x00\x00\x00",
	'EAX_OFFSET_EAX':  b"\x64\x0B\x40\x30",
	'EAX_OFFSET_EBX':  b"\x64\x0B\x43\x30",
	'EAX_OFFSET_ECX':  b"\x64\x0B\x41\x30",
	'EAX_OFFSET_EDX':  b"\x64\x0B\x42\x30",
	'EAX_OFFSET_EDI':  b"\x64\x0B\x47\x30",
	'EAX_OFFSET_ESI':  b"\x64\x0B\x46\x30",
	'EAX_OFFSET_EBP':  b"\x64\x0B\x45\x30",
	'EBX_OFFSET_NONE': b"\x64\x0B\x1D\x30\x00\x00\x00",
	'EBX_OFFSET_EAX':  b"\x64\x0B\x58\x30",
	'EBX_OFFSET_EBX':  b"\x64\x0B\x5B\x30",
	'EBX_OFFSET_ECX':  b"\x64\x0B\x59\x30",
	'EBX_OFFSET_EDX':  b"\x64\x0B\x5A\x30",
	'EBX_OFFSET_EDI':  b"\x64\x0B\x5F\x30",
	'EBX_OFFSET_ESI':  b"\x64\x0B\x5E\x30",
	'EBX_OFFSET_EBP':  b"\x64\x0B\x5D\x30",
	'ECX_OFFSET_NONE': b"\x64\x0B\x0D\x30\x00\x00\x00",
	'ECX_OFFSET_EAX':  b"\x64\x0B\x48\x30",
	'ECX_OFFSET_EBX':  b"\x64\x0B\x4B\x30",
	'ECX_OFFSET_ECX':  b"\x64\x0B\x49\x30",
	'ECX_OFFSET_EDX':  b"\x64\x0B\x4A\x30",
	'ECX_OFFSET_EDI':  b"\x64\x0B\x4F\x30",
	'ECX_OFFSET_ESI':  b"\x64\x0B\x4E\x30",
	'ECX_OFFSET_EBP':  b"\x64\x0B\x4D\x30",
	'EDX_OFFSET_NONE': b"\x64\x0B\x15\x30\x00\x00\x00",
	'EDX_OFFSET_EAX':  b"\x64\x0B\x50\x30",
	'EDX_OFFSET_EBX':  b"\x64\x0B\x53\x30",
	'EDX_OFFSET_ECX':  b"\x64\x0B\x51\x30",
	'EDX_OFFSET_EDX':  b"\x64\x0B\x52\x30",
	'EDX_OFFSET_EDI':  b"\x64\x0B\x57\x30",
	'EDX_OFFSET_ESI':  b"\x64\x0B\x56\x30",
	'EDX_OFFSET_EBP':  b"\x64\x0B\x55\x30",
	'EDI_OFFSET_NONE': b"\x64\x0B\x3D\x30\x00\x00\x00",
	'EDI_OFFSET_EAX':  b"\x64\x0B\x78\x30",
	'EDI_OFFSET_EBX':  b"\x64\x0B\x7B\x30",
	'EDI_OFFSET_ECX':  b"\x64\x0B\x79\x30",
	'EDI_OFFSET_EDX':  b"\x64\x0B\x7A\x30",
	'EDI_OFFSET_EDI':  b"\x64\x0B\x7F\x30",
	'EDI_OFFSET_ESI':  b"\x64\x0B\x7E\x30",
	'EDI_OFFSET_EBP':  b"\x64\x0B\x7D\x30",
	'ESI_OFFSET_NONE': b"\x64\x0B\x35\x30\x00\x00\x00",
	'ESI_OFFSET_EAX':  b"\x64\x0B\x70\x30",
	'ESI_OFFSET_EBX':  b"\x64\x0B\x73\x30",
	'ESI_OFFSET_ECX':  b"\x64\x0B\x71\x30",
	'ESI_OFFSET_EDX':  b"\x64\x0B\x72\x30",
	'ESI_OFFSET_EDI':  b"\x64\x0B\x77\x30",
	'ESI_OFFSET_ESI':  b"\x64\x0B\x76\x30",
	'ESI_OFFSET_EBP':  b"\x64\x0B\x75\x30",
	'EBP_OFFSET_NONE': b"\x64\x0B\x2D\x30\x00\x00\x00",
	'EBP_OFFSET_EAX':  b"\x64\x0B\x68\x30",
	'EBP_OFFSET_EBX':  b"\x64\x0B\x6B\x30",
	'EBP_OFFSET_ECX':  b"\x64\x0B\x69\x30",
	'EBP_OFFSET_EDX':  b"\x64\x0B\x6A\x30",
	'EBP_OFFSET_EDI':  b"\x64\x0B\x6F\x30",
	'EBP_OFFSET_ESI':  b"\x64\x0B\x6E\x30",
	'EBP_OFFSET_EBP':  b"\x64\x0B\x6D\x30"
}

#XCHG <REG>,[FS:0x30]
PEB_WALK_XCHG = {
	'EAX_OFFSET_NONE': b"\x64\x87\x05\x30\x00\x00\x00",
	'EAX_OFFSET_EAX':  b"\x64\x87\x40\x30",
	'EAX_OFFSET_EBX':  b"\x64\x87\x43\x30",
	'EAX_OFFSET_ECX':  b"\x64\x87\x41\x30",
	'EAX_OFFSET_EDX':  b"\x64\x87\x42\x30",
	'EAX_OFFSET_EDI':  b"\x64\x87\x47\x30",
	'EAX_OFFSET_ESI':  b"\x64\x87\x46\x30",
	'EAX_OFFSET_EBP':  b"\x64\x87\x45\x30",
	'EBX_OFFSET_NONE': b"\x64\x87\x1D\x30\x00\x00\x00",
	'EBX_OFFSET_EAX':  b"\x64\x87\x58\x30",
	'EBX_OFFSET_EBX':  b"\x64\x87\x5B\x30",
	'EBX_OFFSET_ECX':  b"\x64\x87\x59\x30",
	'EBX_OFFSET_EDX':  b"\x64\x87\x5A\x30",
	'EBX_OFFSET_EDI':  b"\x64\x87\x5F\x30",
	'EBX_OFFSET_ESI':  b"\x64\x87\x5E\x30",
	'EBX_OFFSET_EBP':  b"\x64\x87\x5D\x30",
	'ECX_OFFSET_NONE': b"\x64\x87\x0D\x30\x00\x00\x00",
	'ECX_OFFSET_EAX':  b"\x64\x87\x48\x30",
	'ECX_OFFSET_EBX':  b"\x64\x87\x4B\x30",
	'ECX_OFFSET_ECX':  b"\x64\x87\x49\x30",
	'ECX_OFFSET_EDX':  b"\x64\x87\x4A\x30",
	'ECX_OFFSET_EDI':  b"\x64\x87\x4F\x30",
	'ECX_OFFSET_ESI':  b"\x64\x87\x4E\x30",
	'ECX_OFFSET_EBP':  b"\x64\x87\x4D\x30",
	'EDX_OFFSET_NONE': b"\x64\x87\x15\x30\x00\x00\x00",
	'EDX_OFFSET_EAX':  b"\x64\x87\x50\x30",
	'EDX_OFFSET_EBX':  b"\x64\x87\x53\x30",
	'EDX_OFFSET_ECX':  b"\x64\x87\x51\x30",
	'EDX_OFFSET_EDX':  b"\x64\x87\x52\x30",
	'EDX_OFFSET_EDI':  b"\x64\x87\x57\x30",
	'EDX_OFFSET_ESI':  b"\x64\x87\x56\x30",
	'EDX_OFFSET_EBP':  b"\x64\x87\x55\x30",
	'EDI_OFFSET_NONE': b"\x64\x87\x3D\x30\x00\x00\x00",
	'EDI_OFFSET_EAX':  b"\x64\x87\x78\x30",
	'EDI_OFFSET_EBX':  b"\x64\x87\x7B\x30",
	'EDI_OFFSET_ECX':  b"\x64\x87\x79\x30",
	'EDI_OFFSET_EDX':  b"\x64\x87\x7A\x30",
	'EDI_OFFSET_EDI':  b"\x64\x87\x7F\x30",
	'EDI_OFFSET_ESI':  b"\x64\x87\x7E\x30",
	'EDI_OFFSET_EBP':  b"\x64\x87\x7D\x30",
	'ESI_OFFSET_NONE': b"\x64\x87\x35\x30\x00\x00\x00",
	'ESI_OFFSET_EAX':  b"\x64\x87\x70\x30",
	'ESI_OFFSET_EBX':  b"\x64\x87\x73\x30",
	'ESI_OFFSET_ECX':  b"\x64\x87\x71\x30",
	'ESI_OFFSET_EDX':  b"\x64\x87\x72\x30",
	'ESI_OFFSET_EDI':  b"\x64\x87\x77\x30",
	'ESI_OFFSET_ESI':  b"\x64\x87\x76\x30",
	'ESI_OFFSET_EBP':  b"\x64\x87\x75\x30",
	'EBP_OFFSET_NONE': b"\x64\x87\x2D\x30\x00\x00\x00",
	'EBP_OFFSET_EAX':  b"\x64\x87\x68\x30",
	'EBP_OFFSET_EBX':  b"\x64\x87\x6B\x30",
	'EBP_OFFSET_ECX':  b"\x64\x87\x69\x30",
	'EBP_OFFSET_EDX':  b"\x64\x87\x6A\x30",
	'EBP_OFFSET_EDI':  b"\x64\x87\x6F\x30",
	'EBP_OFFSET_ESI':  b"\x64\x87\x6E\x30",
	'EBP_OFFSET_EBP':  b"\x64\x87\x6D\x30"
}


PEB_WALK_PUSH = {
	'NONE': b"\x64\xFF\x35\x30\x00\x00\x00",
	'EAX': b"\x64\xFF\x30",
	'EBX': b"\x64\xFF\x33",
	'ECX': b"\x64\xFF\x31",
	'EDX': b"\x64\xFF\x32",
	'EDI': b"\x64\xFF\x37",
	'ESI': b"\x64\xFF\x36",
	'EBP': b"\x64\xFF\x75\x00",
	'EAX_30': b"\x64\xFF\x70\x30",
	'EBX_30': b"\x64\xFF\x73\x30",
	'ECX_30': b"\x64\xFF\x71\x30",
	'EDX_30': b"\x64\xFF\x72\x30",
	'EDI_30': b"\x64\xFF\x77\x30",
	'ESI_30': b"\x64\xFF\x76\x30",
	'EBP_30': b"\x64\xFF\x75\x30"
}

PEB_WALK_PUSH64 = {
	'RAX': b"\x65\xFF\x30",
	'RBX': b"\x65\xFF\x33",
	'RCX': b"\x65\xFF\x31",
	'RDX': b"\x65\xFF\x32",
	'RDI': b"\x65\xFF\x37",
	'RSI': b"\x65\xFF\x36",
	'RBP': b"\x65\xFF\x75\x00",
	'R9':  b"\x65\x41\xFF\x31",
	'R10': b"\x65\x41\xFF\x32",
	'R11': b"\x65\x41\xFF\x33",
	'R12': b"\x65\x41\xFF\x34\x24",
	'R13': b"\x65\x41\xFF\x75\x00",
	'R14': b"\x65\x41\xFF\x36",
	'R15': b"\x65\x41\xFF\x37",
	'RAX_60': b"\x65\xFF\x70\x60",
	'RBX_60': b"\x65\xFF\x73\x60",
	'RCX_60': b"\x65\xFF\x71\x60",
	'RDX_60': b"\x65\xFF\x72\x60",
	'RDI_60': b"\x65\xFF\x77\x60",
	'RSI_60': b"\x65\xFF\x76\x60",
	'RBP_60': b"\x65\xFF\x75\x60",
	'R9_60':  b"\x65\x41\xFF\x71\x60",
	'R10_60': b"\x65\x41\xFF\x72\x60",
	'R11_60': b"\x65\x41\xFF\x73\x60",
	'R12_60': b"\x65\x41\xFF\x74\x24\x60",
	'R13_60': b"\x65\x41\xFF\x75\x60",
	'R14_60': b"\x65\x41\xFF\x76\x60",
	'R15_60': b"\x65\x41\xFF\x77\x60"
}

#################### 64 BIT PEB WALK ###########################################

PEB_WALK_MOV_64 = {
	'RAX_OFFSET_NONE': b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00",
	'RAX_OFFSET_RAX':  b"\x65\x48\x8B\x40\x60",
	'RAX_OFFSET_RBX':  b"\x65\x48\x8B\x43\x60",
	'RAX_OFFSET_RCX':  b"\x65\x48\x8B\x41\x60",
	'RAX_OFFSET_RDX':  b"\x65\x48\x8B\x42\x60",
	'RAX_OFFSET_RDI':  b"\x65\x48\x8B\x47\x60",
	'RAX_OFFSET_RSI':  b"\x65\x48\x8B\x46\x60",
	'RAX_OFFSET_RBP':  b"\x65\x48\x8B\x45\x60",
	'RAX_OFFSET_R9':   b"\x65\x49\x8B\x41\x60",
	'RAX_OFFSET_R10':  b"\x65\x49\x8B\x42\x60",
	'RAX_OFFSET_R11':  b"\x65\x49\x8B\x43\x60",
	'RAX_OFFSET_R12':  b"\x65\x49\x8B\x44\x24\x60",
	'RAX_OFFSET_R13':  b"\x65\x49\x8B\x45\x60",
	'RAX_OFFSET_R14':  b"\x65\x49\x8B\x46\x60",
	'RAX_OFFSET_R15':  b"\x65\x49\x8B\x47\x60",
	'RBX_OFFSET_NONE': b"\x65\x48\x8B\x1C\x25\x60\x00\x00\x00",
	'RBX_OFFSET_RAX':  b"\x65\x48\x8B\x58\x60",
	'RBX_OFFSET_RBX':  b"\x65\x48\x8B\x5B\x60",
	'RBX_OFFSET_RCX':  b"\x65\x48\x8B\x59\x60",
	'RBX_OFFSET_RDX':  b"\x65\x48\x8B\x5A\x60",
	'RBX_OFFSET_RDI':  b"\x65\x48\x8B\x5F\x60",
	'RBX_OFFSET_RSI':  b"\x65\x48\x8B\x5E\x60",
	'RBX_OFFSET_RBP':  b"\x65\x48\x8B\x5D\x60",
	'RBX_OFFSET_R9':   b"\x65\x49\x8B\x59\x60",
	'RBX_OFFSET_R10':  b"\x65\x49\x8B\x5A\x60",
	'RBX_OFFSET_R11':  b"\x65\x49\x8B\x5B\x60",
	'RBX_OFFSET_R12':  b"\x65\x49\x8B\x5C\x24\x60",
	'RBX_OFFSET_R13':  b"\x65\x49\x8B\x5D\x60",
	'RBX_OFFSET_R14':  b"\x65\x49\x8B\x5E\x60",
	'RBX_OFFSET_R15':  b"\x65\x49\x8B\x5F\x60",
	'RCX_OFFSET_NONE': b"\x65\x48\x8B\x0C\x25\x60\x00\x00\x00",
	'RCX_OFFSET_RAX':  b"\x65\x48\x8B\x48\x60",
	'RCX_OFFSET_RBX':  b"\x65\x48\x8B\x4B\x60",
	'RCX_OFFSET_RCX':  b"\x65\x48\x8B\x49\x60",
	'RCX_OFFSET_RDX':  b"\x65\x48\x8B\x4A\x60",
	'RCX_OFFSET_RDI':  b"\x65\x48\x8B\x4F\x60",
	'RCX_OFFSET_RSI':  b"\x65\x48\x8B\x4E\x60",
	'RCX_OFFSET_RBP':  b"\x65\x48\x8B\x4D\x60",
	'RCX_OFFSET_R9':   b"\x65\x49\x8B\x49\x60",
	'RCX_OFFSET_R10':  b"\x65\x49\x8B\x4A\x60",
	'RCX_OFFSET_R11':  b"\x65\x49\x8B\x4B\x60",
	'RCX_OFFSET_R12':  b"\x65\x49\x8B\x4C\x24\x60",
	'RCX_OFFSET_R13':  b"\x65\x49\x8B\x4D\x60",
	'RCX_OFFSET_R14':  b"\x65\x49\x8B\x4E\x60",
	'RCX_OFFSET_R15':  b"\x65\x49\x8B\x4F\x60",
	'RDX_OFFSET_NONE': b"\x65\x48\x8B\x14\x25\x60\x00\x00\x00",
	'RDX_OFFSET_RAX':  b"\x65\x48\x8B\x50\x60",
	'RDX_OFFSET_RBX':  b"\x65\x48\x8B\x53\x60",
	'RDX_OFFSET_RCX':  b"\x65\x48\x8B\x51\x60",
	'RDX_OFFSET_RDX':  b"\x65\x48\x8B\x52\x60",
	'RDX_OFFSET_RDI':  b"\x65\x48\x8B\x57\x60",
	'RDX_OFFSET_RSI':  b"\x65\x48\x8B\x56\x60",
	'RDX_OFFSET_RBP':  b"\x65\x48\x8B\x55\x60",
	'RDX_OFFSET_R9':   b"\x65\x49\x8B\x51\x60",
	'RDX_OFFSET_R10':  b"\x65\x49\x8B\x52\x60",
	'RDX_OFFSET_R11':  b"\x65\x49\x8B\x53\x60",
	'RDX_OFFSET_R12':  b"\x65\x49\x8B\x54\x24\x60",
	'RDX_OFFSET_R13':  b"\x65\x49\x8B\x55\x60",
	'RDX_OFFSET_R14':  b"\x65\x49\x8B\x56\x60",
	'RDX_OFFSET_R15':  b"\x65\x49\x8B\x57\x60",
	'RDI_OFFSET_NONE': b"\x65\x48\x8B\x3C\x25\x60\x00\x00\x00",
	'RDI_OFFSET_RAX':  b"\x65\x48\x8B\x78\x60",
	'RDI_OFFSET_RBX':  b"\x65\x48\x8B\x7B\x60",
	'RDI_OFFSET_RCX':  b"\x65\x48\x8B\x79\x60",
	'RDI_OFFSET_RDX':  b"\x65\x48\x8B\x7A\x60",
	'RDI_OFFSET_RDI':  b"\x65\x48\x8B\x7F\x60",
	'RDI_OFFSET_RSI':  b"\x65\x48\x8B\x7E\x60",
	'RDI_OFFSET_RBP':  b"\x65\x48\x8B\x7D\x60",
	'RDI_OFFSET_R9':   b"\x65\x49\x8B\x79\x60",
	'RDI_OFFSET_R10':  b"\x65\x49\x8B\x7A\x60",
	'RDI_OFFSET_R11':  b"\x65\x49\x8B\x7B\x60",
	'RDI_OFFSET_R12':  b"\x65\x49\x8B\x7C\x24\x60",
	'RDI_OFFSET_R13':  b"\x65\x49\x8B\x7D\x60",
	'RDI_OFFSET_R14':  b"\x65\x49\x8B\x7E\x60",
	'RDI_OFFSET_R15':  b"\x65\x49\x8B\x7F\x60",
	'RSI_OFFSET_NONE': b"\x65\x48\x8B\x34\x25\x60\x00\x00\x00",
	'RSI_OFFSET_RAX':  b"\x65\x48\x8B\x70\x60",
	'RSI_OFFSET_RBX':  b"\x65\x48\x8B\x73\x60",
	'RSI_OFFSET_RCX':  b"\x65\x48\x8B\x71\x60",
	'RSI_OFFSET_RDX':  b"\x65\x48\x8B\x72\x60",
	'RSI_OFFSET_RDI':  b"\x65\x48\x8B\x77\x60",
	'RSI_OFFSET_RSI':  b"\x65\x48\x8B\x76\x60",
	'RSI_OFFSET_RBP':  b"\x65\x48\x8B\x75\x60",
	'RSI_OFFSET_R9':   b"\x65\x49\x8B\x71\x60",
	'RSI_OFFSET_R10':  b"\x65\x49\x8B\x72\x60",
	'RSI_OFFSET_R11':  b"\x65\x49\x8B\x73\x60",
	'RSI_OFFSET_R12':  b"\x65\x49\x8B\x74\x24\x60",
	'RSI_OFFSET_R13':  b"\x65\x49\x8B\x75\x60",
	'RSI_OFFSET_R14':  b"\x65\x49\x8B\x76\x60",
	'RSI_OFFSET_R15':  b"\x65\x49\x8B\x77\x60",
	'RBP_OFFSET_NONE': b"\x65\x48\x8B\x2C\x25\x60\x00\x00\x00",
	'RBP_OFFSET_RAX':  b"\x65\x48\x8B\x68\x60",
	'RBP_OFFSET_RBX':  b"\x65\x48\x8B\x6B\x60",
	'RBP_OFFSET_RCX':  b"\x65\x48\x8B\x69\x60",
	'RBP_OFFSET_RDX':  b"\x65\x48\x8B\x6A\x60",
	'RBP_OFFSET_RDI':  b"\x65\x48\x8B\x6F\x60",
	'RBP_OFFSET_RSI':  b"\x65\x48\x8B\x6E\x60",
	'RBP_OFFSET_RBP':  b"\x65\x48\x8B\x6D\x60",
	'RBP_OFFSET_R9':   b"\x65\x49\x8B\x69\x60",
	'RBP_OFFSET_R10':  b"\x65\x49\x8B\x6A\x60",
	'RBP_OFFSET_R11':  b"\x65\x49\x8B\x6B\x60",
	'RBP_OFFSET_R12':  b"\x65\x49\x8B\x6C\x24\x60",
	'RBP_OFFSET_R13':  b"\x65\x49\x8B\x6D\x60",
	'RBP_OFFSET_R14':  b"\x65\x49\x8B\x6E\x60",
	'RBP_OFFSET_R15':  b"\x65\x49\x8B\x6F\x60",
	'R9_OFFSET_NONE':  b"\x65\x4C\x8B\x0C\x25\x60\x00\x00\x00",
	'R9_OFFSET_RAX':   b"\x65\x4C\x8B\x48\x60",
	'R9_OFFSET_RBX':   b"\x65\x4C\x8B\x4B\x60",
	'R9_OFFSET_RCX':   b"\x65\x4C\x8B\x49\x60",
	'R9_OFFSET_RDX':   b"\x65\x4C\x8B\x4A\x60",
	'R9_OFFSET_RDI':   b"\x65\x4C\x8B\x4F\x60",
	'R9_OFFSET_RSI':   b"\x65\x4C\x8B\x4E\x60",
	'R9_OFFSET_RBP':   b"\x65\x4C\x8B\x4D\x60",
	'R9_OFFSET_R9':    b"\x65\x4D\x8B\x49\x60",
	'R9_OFFSET_R10':   b"\x65\x4D\x8B\x4A\x60",
	'R9_OFFSET_R11':   b"\x65\x4D\x8B\x4B\x60",
	'R9_OFFSET_R12':   b"\x65\x4D\x8B\x4C\x24\x60",
	'R9_OFFSET_R13':   b"\x65\x4D\x8B\x4D\x60",
	'R9_OFFSET_R14':   b"\x65\x4D\x8B\x4E\x60",
	'R9_OFFSET_R15':   b"\x65\x4D\x8B\x4F\x60",
	'R10_OFFSET_NONE': b"\x65\x4C\x8B\x14\x25\x60\x00\x00\x00",
	'R10_OFFSET_RAX':  b"\x65\x4C\x8B\x50\x60",
	'R10_OFFSET_RBX':  b"\x65\x4C\x8B\x53\x60",
	'R10_OFFSET_RCX':  b"\x65\x4C\x8B\x51\x60",
	'R10_OFFSET_RDX':  b"\x65\x4C\x8B\x52\x60",
	'R10_OFFSET_RDI':  b"\x65\x4C\x8B\x57\x60",
	'R10_OFFSET_RSI':  b"\x65\x4C\x8B\x56\x60",
	'R10_OFFSET_RBP':  b"\x65\x4C\x8B\x55\x60",
	'R10_OFFSET_R9':   b"\x65\x4D\x8B\x51\x60",
	'R10_OFFSET_R10':  b"\x65\x4D\x8B\x52\x60",
	'R10_OFFSET_R11':  b"\x65\x4D\x8B\x53\x60",
	'R10_OFFSET_R12':  b"\x65\x4D\x8B\x54\x24\x60",
	'R10_OFFSET_R13':  b"\x65\x4D\x8B\x55\x60",
	'R10_OFFSET_R14':  b"\x65\x4D\x8B\x56\x60",
	'R10_OFFSET_R15':  b"\x65\x4D\x8B\x57\x60",
	'R11_OFFSET_NONE': b"\x65\x4C\x8B\x1C\x25\x60\x00\x00\x00",
	'R11_OFFSET_RAX':  b"\x65\x4C\x8B\x58\x60",
	'R11_OFFSET_RBX':  b"\x65\x4C\x8B\x5B\x60",
	'R11_OFFSET_RCX':  b"\x65\x4C\x8B\x59\x60",
	'R11_OFFSET_RDX':  b"\x65\x4C\x8B\x5A\x60",
	'R11_OFFSET_RDI':  b"\x65\x4C\x8B\x5F\x60",
	'R11_OFFSET_RSI':  b"\x65\x4C\x8B\x5E\x60",
	'R11_OFFSET_RBP':  b"\x65\x4C\x8B\x5D\x60",
	'R11_OFFSET_R9':   b"\x65\x4D\x8B\x59\x60",
	'R11_OFFSET_R10':  b"\x65\x4D\x8B\x5A\x60",
	'R11_OFFSET_R11':  b"\x65\x4D\x8B\x5B\x60",
	'R11_OFFSET_R12':  b"\x65\x4D\x8B\x5C\x24\x60",
	'R11_OFFSET_R13':  b"\x65\x4D\x8B\x5D\x60",
	'R11_OFFSET_R14':  b"\x65\x4D\x8B\x5E\x60",
	'R11_OFFSET_R15':  b"\x65\x4D\x8B\x5F\x60",
	'R12_OFFSET_NONE': b"\x65\x4C\x8B\x24\x25\x60\x00\x00\x00",
	'R12_OFFSET_RAX':  b"\x65\x4C\x8B\x60\x60",
	'R12_OFFSET_RBX':  b"\x65\x4C\x8B\x63\x60",
	'R12_OFFSET_RCX':  b"\x65\x4C\x8B\x61\x60",
	'R12_OFFSET_RDX':  b"\x65\x4C\x8B\x62\x60",
	'R12_OFFSET_RDI':  b"\x65\x4C\x8B\x67\x60",
	'R12_OFFSET_RSI':  b"\x65\x4C\x8B\x66\x60",
	'R12_OFFSET_RBP':  b"\x65\x4C\x8B\x65\x60",
	'R12_OFFSET_R9':   b"\x65\x4D\x8B\x61\x60",
	'R12_OFFSET_R10':  b"\x65\x4D\x8B\x62\x60",
	'R12_OFFSET_R11':  b"\x65\x4D\x8B\x63\x60",
	'R12_OFFSET_R12':  b"\x65\x4D\x8B\x64\x24\x60",
	'R12_OFFSET_R13':  b"\x65\x4D\x8B\x65\x60",
	'R12_OFFSET_R14':  b"\x65\x4D\x8B\x66\x60",
	'R12_OFFSET_R15':  b"\x65\x4D\x8B\x67\x60",
	'R13_OFFSET_NONE': b"\x65\x4C\x8B\x2C\x25\x60\x00\x00\x00",
	'R13_OFFSET_RAX':  b"\x65\x4C\x8B\x68\x60",
	'R13_OFFSET_RBX':  b"\x65\x4C\x8B\x6B\x60",
	'R13_OFFSET_RCX':  b"\x65\x4C\x8B\x69\x60",
	'R13_OFFSET_RDX':  b"\x65\x4C\x8B\x6A\x60",
	'R13_OFFSET_RDI':  b"\x65\x4C\x8B\x6F\x60",
	'R13_OFFSET_RSI':  b"\x65\x4C\x8B\x6E\x60",
	'R13_OFFSET_RBP':  b"\x65\x4C\x8B\x6D\x60",
	'R13_OFFSET_R9':   b"\x65\x4D\x8B\x69\x60",
	'R13_OFFSET_R10':  b"\x65\x4D\x8B\x6A\x60",
	'R13_OFFSET_R11':  b"\x65\x4D\x8B\x6B\x60",
	'R13_OFFSET_R12':  b"\x65\x4D\x8B\x6C\x24\x60",
	'R13_OFFSET_R13':  b"\x65\x4D\x8B\x6D\x60",
	'R13_OFFSET_R14':  b"\x65\x4D\x8B\x6E\x60",
	'R13_OFFSET_R15':  b"\x65\x4D\x8B\x6F\x60",
	'R14_OFFSET_NONE': b"\x65\x4C\x8B\x34\x25\x60\x00\x00\x00",
	'R14_OFFSET_RAX':  b"\x65\x4C\x8B\x70\x60",
	'R14_OFFSET_RBX':  b"\x65\x4C\x8B\x73\x60",
	'R14_OFFSET_RCX':  b"\x65\x4C\x8B\x71\x60",
	'R14_OFFSET_RDX':  b"\x65\x4C\x8B\x72\x60",
	'R14_OFFSET_RDI':  b"\x65\x4C\x8B\x77\x60",
	'R14_OFFSET_RSI':  b"\x65\x4C\x8B\x76\x60",
	'R14_OFFSET_RBP':  b"\x65\x4C\x8B\x75\x60",
	'R14_OFFSET_R9':   b"\x65\x4D\x8B\x71\x60",
	'R14_OFFSET_R10':  b"\x65\x4D\x8B\x72\x60",
	'R14_OFFSET_R11':  b"\x65\x4D\x8B\x73\x60",
	'R14_OFFSET_R12':  b"\x65\x4D\x8B\x74\x24\x60",
	'R14_OFFSET_R13':  b"\x65\x4D\x8B\x75\x60",
	'R14_OFFSET_R14':  b"\x65\x4D\x8B\x76\x60",
	'R14_OFFSET_R15':  b"\x65\x4D\x8B\x77\x60",
	'R15_OFFSET_NONE': b"\x65\x4C\x8B\x3C\x25\x60\x00\x00\x00",
	'R15_OFFSET_RAX':  b"\x65\x4C\x8B\x78\x60",
	'R15_OFFSET_RBX':  b"\x65\x4C\x8B\x7B\x60",
	'R15_OFFSET_RCX':  b"\x65\x4C\x8B\x79\x60",
	'R15_OFFSET_RDX':  b"\x65\x4C\x8B\x7A\x60",
	'R15_OFFSET_RDI':  b"\x65\x4C\x8B\x7F\x60",
	'R15_OFFSET_RSI':  b"\x65\x4C\x8B\x7E\x60",
	'R15_OFFSET_RBP':  b"\x65\x4C\x8B\x7D\x60",
	'R15_OFFSET_R9':   b"\x65\x4D\x8B\x79\x60",
	'R15_OFFSET_R10':  b"\x65\x4D\x8B\x7A\x60",
	'R15_OFFSET_R11':  b"\x65\x4D\x8B\x7B\x60",
	'R15_OFFSET_R12':  b"\x65\x4D\x8B\x7C\x24\x60",
	'R15_OFFSET_R13':  b"\x65\x4D\x8B\x7D\x60",
	'R15_OFFSET_R14':  b"\x65\x4D\x8B\x7E\x60",
	'R15_OFFSET_R15':  b"\x65\x4D\x8B\x7F\x60"
}


################### AUSTIN ###############################
FSTENV_GET_BASE = {
	'EAX': b"\xD9\x30",
	'EBX': b"\xD9\x33",
	'ECX': b"\xD9\x31",
	'EDX': b"\xD9\x32",
	'EDI': b"\xD9\x37",
	'ESI': b"\xD9\x36",
	'EBP': b"\xD9\x75",
	'ESP': b"\xD9\x34\x24",
	'EAX_OFFSET_NUM': b"\xD9\x70",
	'EBX_OFFSET_NUM': b"\xD9\x73",
	'ECX_OFFSET_NUM': b"\xD9\x71",
	'EDX_OFFSET_NUM': b"\xD9\x72",
	'EDI_OFFSET_NUM': b"\xD9\x77",
	'ESI_OFFSET_NUM': b"\xD9\x76",
	'EBP_OFFSET_NUM': b"\xD9\x75",
	'ESP_OFFSET_NUM': b"\xD9\x74\x24",
	'EAX_PTR': b"\xD9\xB0",
	'EBX_PTR': b"\xD9\xB3",
	'ECX_PTR': b"\xD9\xB1",
	'EDX_PTR': b"\xD9\xB2",
	'EDI_PTR': b"\xD9\xB7",
	'ESI_PTR': b"\xD9\xB6",
	'EBP_PTR': b"\xD9\xB5",
	'ESP_PTR': b"\xD9\xB4\x24"

}

################### AUSTIN ###############################

PUSH_RET = {


	'EAX': b"\x50\xC3",
	'EBX': b"\x53\xC3",
	'ECX': b"\x51\xC3",
	'EDX': b"\x52\xC3",
	'EDI': b"\x57\xC3",
	'ESI': b"\x56\xC3",
	'EBP': b"\x55\xC3",
	'ESP': b"\x54\xC3",
	'EAX_PAD': b"\x50\xC2",
	'EBX_PAD': b"\x53\xC2",
	'ECX_PAD': b"\x51\xC2",
	'EDX_PAD': b"\x52\xC2",
	'EDI_PAD': b"\x57\xC2",
	'ESI_PAD': b"\x56\xC2",
	'EBP_PAD': b"\x55\xC2",
	'ESP_PAD': b"\x54\xC2",
	'EAX_RETF': b"\x50\xCB",
	'EBX_RETF': b"\x53\xCB",
	'ECX_RETF': b"\x51\xCB",
	'EDX_RETF': b"\x52\xCB",
	'EDI_RETF': b"\x57\xCB",
	'ESI_RETF': b"\x56\xCB",
	'EBX_RETF': b"\x55\xCB",
	'ESP_RETF': b"\x54\xCB",
	'EAX_RETF_PAD': b"\x50\xCA",
	'EBX_RETF_PAD': b"\x53\xCA",
	'ECX_RETF_PAD': b"\x51\xCA",
	'EDX_RETF_PAD': b"\x52\xCA",
	'EDI_RETF_PAD': b"\x57\xCA",
	'ESI_RETF_PAD': b"\x56\xCA",
	'EBP_RETF_PAD': b"\x55\xCA",
	'ESP_RETF_PAD': b"\x54\xCA"

}

OP_JMP_EAX = b"\xff\xe0"
OP_JMP_EBX = b"\xff\xe3"
OP_JMP_ECX = b"\xff\xe1"
OP_JMP_EDX = b"\xff\xe2"
OP_JMP_ESI = b"\xff\xe6"
OP_JMP_EDI = b"\xff\xe7"
OP_JMP_ESP = b"\xff\xe4"
OP_JMP_EBP = b"\xff\xe5"
OP_JMP_R8  = b"\x41\xff\xe0"
OP_JMP_R9  = b"\x41\xff\xe1"
OP_JMP_R10 = b"\x41\xff\xe2"
OP_JMP_R11 = b"\x41\xff\xe3"
OP_JMP_R12 = b"\x41\xff\xe4"
OP_JMP_R13 = b"\x41\xff\xe5"
OP_JMP_R14 = b"\x41\xff\xe6"
OP_JMP_R15 = b"\x41\xff\xe7"

OP_JMP_PTR_EAX = b"\xff\x20"
OP_JMP_PTR_EBX = b"\xff\x23"
OP_JMP_PTR_ECX = b"\xff\x21"
OP_JMP_PTR_EDX = b"\xff\x22"
OP_JMP_PTR_EDI = b"\xff\x27"
OP_JMP_PTR_ESI = b"\xff\x26"
OP_JMP_PTR_EBP = b"\xff\x65\x00"
OP_JMP_PTR_ESP = b"\xff\x24\x24"

OP_CALL_EAX = b"\xff\xd0"
OP_CALL_EBX = b"\xff\xd3"
OP_CALL_ECX = b"\xff\xd1"
OP_CALL_EDX = b"\xff\xd2"
OP_CALL_EDI = b"\xff\xd7"
OP_CALL_ESI = b"\xff\xd6"
OP_CALL_EBP = b"\xff\xd5"
OP_CALL_ESP = b"\xff\xd4"

OP_CALL_PTR_EAX =  b"\xff\x10"
OP_CALL_PTR_EBX =  b"\xff\x13"
OP_CALL_PTR_ECX =  b"\xff\x11"
OP_CALL_PTR_EDX =  b"\xff\x12"
OP_CALL_PTR_EDI =  b"\xff\x17"
OP_CALL_PTR_ESI =  b"\xff\x16"
OP_CALL_PTR_EBP =  b"\xff\x55\x00"
OP_CALL_PTR_ESP =  b"\xff\x14\x24"

OP_CALL_FAR_EAX =  b"\xff\x18"
OP_CALL_FAR_EBX =  b"\xff\x1b"
OP_CALL_FAR_ECX =  b"\xff\x19"
OP_CALL_FAR_EDX =  b"\xff\x1a"
OP_CALL_FAR_EDI =  b"\xff\x1f"
OP_CALL_FAR_ESI =  b"\xff\x1e"
OP_CALL_FAR_EBP =  b"\xff\x1c\x24"
OP_CALL_FAR_ESP =  b"\xff\x5d\x00"


OTHER_JMP_PTR_EAX_SHORT =  b"\xff\x60"
OTHER_JMP_PTR_EAX_LONG =  b"\xff\xa0"  #  ff a0 00 01 00 00       jmp    DWORD PTR [eax+0x100]   # should be 00 00 on last two, or too unrealistic

OTHER_JMP_PTR_EBX_SHORT =  b"\xff\x63"
OTHER_JMP_PTR_ECX_SHORT =  b"\xff\x61"
OTHER_JMP_PTR_EDX_SHORT =  b"\xff\x62"
OTHER_JMP_PTR_EDI_SHORT =  b"\xff\x67"
OTHER_JMP_PTR_ESI_SHORT =  b"\xff\x66"
OTHER_JMP_PTR_ESP_SHORT =  b"\xff\x64"
OTHER_JMP_PTR_EBP_SHORT =  b"\xff\x65"

OP_RET = b"\xc3"

listOP_Base = []
listOP_Base_CNT = []
listOP_Base_NumOps = []
listOP_Base_Module = []

listOP_BaseDG = []
listOP_BaseDG_CNT = []
listOP_BaseDG_NumOps = []
listOP_BaseDG_Module = []

push_DWORD_PTR_eax= b"\xff\x30" 
push_DWORD_PTR_ecx= b"\xff\x31" 
push_DWORD_PTR_edx = b"\xff\x32" 
push_DWORD_PTR_ebx= b"\xff\x33" 
push_DWORD_PTR_esp= b"\xff\x34" 
push_DWORD_PTR_esi= b"\xff\x36" 
push_DWORD_PTR_edi= b"\xff\x37"

inc_ecx = b"\xff\xc1"
inc_edx = b"\xff\xc2"
inc_ebx = b"\xff\xc3"
inc_esp = b"\xff\xc4"
inc_ebp = b"\xff\xc5"
inc_esi = b"\xff\xc6"
inc_edi = b"\xff\xc7"
dec_eax = b"\xff\xc8"
dec_ecx = b"\xff\xc9"
dec_edx = b"\xff\xca"
dec_ebx = b"\xff\xcb"
dec_esp = b"\xff\xcc"
dec_ebp = b"\xff\xcd"
dec_esi = b"\xff\xce"
dec_edi = b"\xff\xcf"

push_eax = b"\xff\xf0" 
push_ecx = b"\xff\xf1" 
push_edx = b"\xff\xf2" 
push_ebx = b"\xff\xf3" 
push_esp = b"\xff\xf4"
push_ebp = b"\xff\xf5"
push_esi = b"\xff\xf6" 
push_edi = b"\xff\xf7"


FFInstructions= [push_DWORD_PTR_eax, push_DWORD_PTR_ecx, push_DWORD_PTR_edx, push_DWORD_PTR_ebx, push_DWORD_PTR_esp, push_DWORD_PTR_esi, push_DWORD_PTR_edi, inc_ecx,  inc_edx,  inc_ebx,  inc_esp,  inc_ebp,  inc_esi,  inc_edi,  dec_eax,  dec_ecx,  dec_edx,  dec_ebx,  dec_esp,  dec_ebp,  dec_esi,  dec_edi,  push_eax,  push_ecx,  push_edx,  push_ebx,  push_esp,  push_ebp,  push_esi,  push_edi,  OP_JMP_PTR_EAX,  OP_JMP_PTR_EBX,  OP_JMP_PTR_ECX,  OP_JMP_PTR_EDX, OP_JMP_PTR_EDI,  OP_JMP_PTR_ESI,  OP_JMP_PTR_EBP,  OP_JMP_PTR_ESP,  OP_CALL_EAX,  OP_CALL_EBX,  OP_CALL_ECX,  OP_CALL_EDX,  OP_CALL_EDI,  OP_CALL_ESI,  OP_CALL_EBP,  OP_CALL_ESP,  OP_CALL_PTR_EAX,  OP_CALL_PTR_EBX,  OP_CALL_PTR_ECX,  OP_CALL_PTR_EDX,  OP_CALL_PTR_EDI,  OP_CALL_PTR_ESI, OP_CALL_PTR_EBP,  OP_CALL_PTR_ESP, OP_CALL_FAR_EAX,  OP_CALL_FAR_EBX,  OP_CALL_FAR_ECX,  OP_CALL_FAR_EDX,  OP_CALL_FAR_EDI,  OP_CALL_FAR_ESI,  OP_CALL_FAR_EBP,  OP_CALL_FAR_ESP,  OP_JMP_EAX,  OP_JMP_EBX, OP_JMP_ECX,  OP_JMP_EDX,  OP_JMP_ESI,  OP_JMP_EDI, OP_JMP_ESP, OP_JMP_EBP]

