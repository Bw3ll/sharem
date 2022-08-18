from ctypes import sizeof

from ...helper.emuHelpers import Uc
from sharem.sharem.helper.structHelpers import BOOL, DWORD, INT, LONG, LONGLONG, QWORD, SHORT, UINT, ULONG, ULONGLONG, USHORT, WCHAR, WORD, CHAR


class Memory:

    class Read:

        def CHAR(uc: Uc, address: int):
            try:
                return CHAR.from_buffer_copy(uc.mem_read(address, sizeof(CHAR))).value
            except:
                return 0

        def WCHAR(uc: Uc, address: int):
            try:
                return WCHAR.from_buffer_copy(uc.mem_read(address, sizeof(WCHAR))).value
            except:
                return 0

        def BOOL(uc: Uc, address: int):
            try:
                return BOOL.from_buffer_copy(uc.mem_read(address, sizeof(BOOL))).value
            except:
                return 0

        def WORD(uc: Uc, address: int):
            try:
                return WORD.from_buffer_copy(uc.mem_read(address, sizeof(WORD))).value
            except:
                return 0

        def DWORD(uc: Uc, address: int):
            try:
                return DWORD.from_buffer_copy(uc.mem_read(address, sizeof(DWORD))).value
            except:
                return 0

        def QWORD(uc: Uc, address: int):
            try:
                return QWORD.from_buffer_copy(uc.mem_read(address, sizeof(QWORD))).value
            except:
                return 0

        def SHORT(uc: Uc, address: int):
            try:
                return SHORT.from_buffer_copy(uc.mem_read(address, sizeof(SHORT))).value
            except:
                return 0

        def USHORT(uc: Uc, address: int):
            try:
                return USHORT.from_buffer_copy(uc.mem_read(address, sizeof(USHORT))).value
            except:
                return 0

        def INT(uc: Uc, address: int):
            try:
                return INT.from_buffer_copy(uc.mem_read(address, sizeof(INT))).value
            except:
                return 0

        def UINT(uc: Uc, address: int):
            try:
                return UINT.from_buffer_copy(uc.mem_read(address, sizeof(UINT))).value
            except:
                return 0

        def LONG(uc: Uc, address: int):
            try:
                return LONG.from_buffer_copy(uc.mem_read(address, sizeof(LONG))).value
            except:
                return 0

        def ULONG(uc: Uc, address: int):
            try:
                return ULONG.from_buffer_copy(uc.mem_read(address, sizeof(ULONG))).value
            except:
                return 0

        def LONGLONG(uc: Uc, address: int):
            try:
                return LONGLONG.from_buffer_copy(uc.mem_read(address, sizeof(LONGLONG))).value
            except:
                return 0

        def ULONGLONG(uc: Uc, address: int):
            try:
                return ULONGLONG.from_buffer_copy(uc.mem_read(address, sizeof(ULONGLONG))).value
            except:
                return 0

    class Write:
        def CHAR(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, CHAR(val))
            except:
                pass

        def WCHAR(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, WCHAR(val))
            except:
                pass

        def BOOL(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, BOOL(val))
            except:
                pass

        def WORD(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, WORD(val))
            except:
                pass

        def DWORD(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, DWORD(val))
            except:
                pass

        def QWORD(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, QWORD(val))
            except:
                pass

        def SHORT(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, SHORT(val))
            except:
                pass

        def USHORT(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, USHORT(val))
            except:
                pass

        def INT(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, INT(val))
            except:
                pass

        def UINT(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, bytes(UINT(val)))
            except:
                pass

        def LONG(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, LONG(val))
            except:
                pass

        def ULONG(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, ULONG(val))
            except:
                pass

        def LONGLONG(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, LONGLONG(val))
            except:
                pass

        def ULONGLONG(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, ULONGLONG(val))
            except:
                pass
