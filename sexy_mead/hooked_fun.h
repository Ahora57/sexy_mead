#ifndef HOOKED_FUN
#define HOOKED_FUN
#include "struct.h"
#include "ntapi.h"
#include "dis_util.h"
 

#ifndef OPCODE_INT3
#define OPCODE_INT3 0xCC
#endif // !OPCODE_INT3


#ifndef OPCODE_NOP
#define OPCODE_NOP 0x90
#endif // !OPCODE_NOP

#ifndef HIGHT_DIS_OFFSET_CRC_CALC_END
#define HIGHT_DIS_OFFSET_CRC_CALC_END 0x50
#endif // !HIGHT_DIS_OFFSET_CRC_CALC_END

#ifndef HIGHT_DIS_OFFSET_OBF_API
#define HIGHT_DIS_OFFSET_OBF_API 0x150
#endif // !HIGHT_DIS_OFFSET_OBF_API

#ifndef HIGHT_DIS_OFFSET_LOADER_RET
#define HIGHT_DIS_OFFSET_LOADER_RET 0x150
#endif // !HIGHT_DIS_OFFSET_LOADER_RET

#ifndef HIGHT_DIS_OFFSET_EXIT_PORT_INSTR
#define HIGHT_DIS_OFFSET_EXIT_PORT_INSTR 0x150
#endif // !HIGHT_DIS_OFFSET_EXIT_PORT_INSTR


namespace wow_ponos
{
#pragma pack(push, 1)
template <class T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <typename PTR>
struct UNICODE_STRING
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		};
		PTR dummy;
	};
	PTR _Buffer;
};

template <class T>
struct _UNICODE_STRING_T
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		};
		T dummy;
	};
	T Buffer;
};

template <class T>
struct _LDR_DATA_TABLE_ENTRY_T
{
	_LIST_ENTRY_T<T> InLoadOrderLinks;
	_LIST_ENTRY_T<T> InMemoryOrderLinks;
	_LIST_ENTRY_T<T> InInitializationOrderLinks;
	T DllBase;
	T EntryPoint;
	union
	{
		DWORD SizeOfImage;
		T dummy01;
	};
	_UNICODE_STRING_T<T> FullDllName;
	_UNICODE_STRING_T<T> BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		_LIST_ENTRY_T<T> HashLinks;
		struct
		{
			T SectionPointer;
			T CheckSum;
		};
	};
	union
	{
		T LoadedImports;
		DWORD TimeDateStamp;
	};
	T EntryPointActivationContext;
	T PatchInformation;
	_LIST_ENTRY_T<T> ForwarderLinks;
	_LIST_ENTRY_T<T> ServiceTagLinks;
	_LIST_ENTRY_T<T> StaticLinks;
	T ContextInformation;
	T OriginalBase;
	_LARGE_INTEGER LoadTime;
};

template <class T>
struct _PEB_LDR_DATA_T
{
	DWORD Length;
	DWORD Initialized;
	T SsHandle;
	_LIST_ENTRY_T<T> InLoadOrderModuleList;
	_LIST_ENTRY_T<T> InMemoryOrderModuleList;
	_LIST_ENTRY_T<T> InInitializationOrderModuleList;
	T EntryInProgress;
	DWORD ShutdownInProgress;
	T ShutdownThreadId;

};

template <typename T, typename NGF, int A>
struct _PEB_T
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE _SYSTEM_DEPENDENT_01;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T _SYSTEM_DEPENDENT_02;
	T _SYSTEM_DEPENDENT_03;
	T _SYSTEM_DEPENDENT_04;
	union
	{
		T KernelCallbackTable;
		T UserSharedInfoPtr;
	};
	DWORD SystemReserved;
	DWORD _SYSTEM_DEPENDENT_05;
	T _SYSTEM_DEPENDENT_06;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T _SYSTEM_DEPENDENT_07;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	union
	{
		T ImageProcessAffinityMask;
		T ActiveProcessAffinityMask;
	};
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	UNICODE_STRING<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
};
#pragma pack(pop)

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

};
namespace hooked_fun
{
	CRC_FILE_INFO crc_file;
	CRC_RUNTIME crc_run;
	ANTI_DEB_INFO anti_deb;
	ANTI_MONITOR anti_monit;
	ANTI_VM anti_vm;
	USER_API_HOOKED imp_obf_hook;
	PVOID orig_add_vec_handler;

	std::vector<LOADER_GET_API_RET> addr_ret_loader_api;

	class crc_file_util
	{
	private:
		NO_INLINE static auto wtolower(INT c) -> INT
		{
			if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
			if (c >= L'À' && c <= L'ß') return c - L'À' + L'à';
			if (c == L'¨') return L'¸';
			return c;
		}

		NO_INLINE static auto wstricmp(CONST WCHAR* cs, CONST WCHAR* ct) -> INT
		{
			if (cs && ct)
			{
				while (wtolower(*cs) == wtolower(*ct))
				{
					if (*cs == 0 && *ct == 0) return NULL;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return wtolower(*cs) - wtolower(*ct);
			}
			return -1;
		}

		NO_INLINE static auto wstrlen(CONST WCHAR* s) -> INT
		{
			INT cnt = NULL;
			if (!s)
				return NULL;
			for (; *s != NULL; ++s)
				++cnt;
			return cnt * sizeof(WCHAR);
		}
	

		NO_INLINE static auto   str_cat_w(WCHAR* dest, const WCHAR* src) -> WCHAR*
		{
			if ((dest == 0) || (src == 0))
				return dest;

			while (*dest != 0)
				dest++;

			while (*src != 0)
			{
				*dest = *src;
				dest++;
				src++;
			}
			*dest = 0;
			return dest;
		}

		NO_INLINE static auto get_orig_file(WCHAR* path_bin, uint32_t type_file) -> BOOLEAN
		{
			uint32_t len = NULL;
			WCHAR type_save[MAX_PATH] = { NULL };
			len = wstrlen(path_bin);

			for (INT i = len; i > NULL; i--)
			{
				if (path_bin[i] == '.') //meh, just copy string
				{
					memcpy(type_save, &path_bin[i], len - i);
					memset(&path_bin[i], NULL, len - i);
					str_cat_w(path_bin, L"_orig");
					str_cat_w(path_bin, type_save);
					return TRUE;
				}
			}
			return FALSE;
		}

		NO_INLINE static auto memcpy
		(
			PVOID dest,
			CONST VOID* src,
			uint64_t count
		) -> PVOID
		{
			char* char_dest = (char*)dest;
			char* char_src = (char*)src;
			if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
			{
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest++;
					char_src++;
					count--;
				}
			}
			else
			{
				char_dest = (char*)dest + count - 1;
				char_src = (char*)src + count - 1;
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest--;
					char_src--;
					count--;
				}
			}
			return dest;
		}
	public:

		 

		static auto WINAPI create_filew
		(
			LPCWSTR               lpFileName,
			DWORD                 dwDesiredAccess,
			DWORD                 dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes,
			DWORD                 dwCreationDisposition,
			DWORD                 dwFlagsAndAttributes,
			HANDLE                hTemplateFile
		) -> HANDLE
		{
			uint32_t type_file = NULL;

			HMODULE mod_addr = NULL;
			HANDLE access = NULL;
			WCHAR path_bin[MAX_PATH] = { NULL };

			for (size_t i = 0; i < crc_file.mod_info.size(); i++)
			{ 
				if (!crc_file.mod_info[i].addr)
				{
					mod_addr = GetModuleHandleW(crc_file.mod_info[i].name_mod);
					crc_file.mod_info[i].addr = mod_addr;
				}
				else
				{
					mod_addr = reinterpret_cast<HMODULE>(crc_file.mod_info[i].addr);
				}

				if (mod_addr && GetModuleFileNameW(mod_addr, path_bin, sizeof(path_bin)))
				{
					if (!wstricmp(lpFileName, path_bin))
					{
						if (get_orig_file(path_bin, type_file))
						{
							access = reinterpret_cast<decltype(&CreateFileW)>(crc_file.orig_create_filew)(path_bin, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
							if (access == INVALID_HANDLE_VALUE)
							{ 
								access = reinterpret_cast<decltype(&CreateFileW)>(crc_file.orig_create_filew)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
							}
							return access;
						} 

					}
				}
			}
			return reinterpret_cast<decltype(&CreateFileW)>(crc_file.orig_create_filew)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		} 
	};

	class crc_runtime_util
	{
	private:

		NO_INLINE static auto wstrlen(CONST WCHAR* s) -> INT
		{
			INT cnt = NULL;
			if (!s)
				return NULL;
			for (; *s != NULL; ++s)
				++cnt;
			return cnt * sizeof(WCHAR);
		}

		NO_INLINE static auto memcpy
		(
			PVOID dest,
			CONST VOID* src,
			uint64_t count
		) -> PVOID
		{
			char* char_dest = (char*)dest;
			char* char_src = (char*)src;
			if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
			{
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest++;
					char_src++;
					count--;
				}
			}
			else
			{
				char_dest = (char*)dest + count - 1;
				char_src = (char*)src + count - 1;
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest--;
					char_src--;
					count--;
				}
			}
			return dest;
		}

		/*
		X64 - 89 45 E0  mov dword ptr ss:[rbp-20],eax
		x32 - 89 04 24 mov dword ptr ss:[esp],eax
		*/
		static NO_INLINE auto  is_crc_mov
		(
			uint8_t* addr
		) -> BOOLEAN
		{
#ifndef _WIN64
			return
				*(addr) == 0x89 &&
				*(addr + 1) == 0x04 &&
				*(addr + 2) == 0x24;
#else
			return
				*(addr) == 0x89 &&
				*(addr + 1) == 0x45 &&
				*(addr + 2) == 0xE0;
#endif // !_WIN64

		}

		static NO_INLINE auto is_inside_sec
		(
			CHAR* addr,
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sections
		) -> BOOLEAN
		{
			uint32_t rva_addr = NULL;
			rva_addr = addr - mod_addr;
			if (
				sections->VirtualAddress <= rva_addr &&
				sections->VirtualAddress + sections->Misc.VirtualSize > rva_addr
				)
			{
				return TRUE;
			}
			return FALSE;
		}
		static NO_INLINE auto is_get_crc_end
		(
			CHAR* addr,
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sections

		) -> BOOLEAN
		{
			CHAR* dis_addr = NULL;
			CHAR* next_addr_pos = NULL;
			DIS_CRC_RUN dis_info = { NULL };
			ZydisDisassembledInstruction info_instr = { NULL };

			dis_addr = addr;

#ifndef _WIN64
			for (uint16_t i = NULL; i < CRC_RUN_MAX_DIS; i++)
			{
				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, dis_addr)))
				{
					switch (info_instr.info.mnemonic)
					{
					case ZYDIS_MNEMONIC_MOV:
					{
						if (
							i == NULL && !dis_info.mov_count &&
							info_instr.info.operand_count_visible == 0x2
							)
						{
							if (
								info_instr.operands[0].mem.base == ZYDIS_REGISTER_ESP &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[1].reg.value == ZYDIS_REGISTER_EAX &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
								)
							{
								dis_info.mov_count++;
							}

						}
						if (i == NULL && dis_info.mov_count == NULL)
						{
							return FALSE;
						}

						dis_addr += info_instr.info.length;

						break;
					}
					case ZYDIS_MNEMONIC_PUSH:
					{
						if (info_instr.info.operand_count_visible == 0x1)
						{

							if (
								info_instr.operands[0].mem.base == ZYDIS_REGISTER_EBP &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[0].mem.disp.has_displacement &&
								info_instr.operands[0].mem.disp.value == 0xfffffffffffffff4
								)
							{
								dis_info.push_rbp_count++;
							}

						}

						dis_addr += info_instr.info.length;

						break;
					}
					case ZYDIS_MNEMONIC_CALL:
					{
						if (
							dis_info.push_rbp_count &&
							info_instr.info.operand_count_visible == 0x1
							)
						{
							if (
								info_instr.operands[0].mem.base == ZYDIS_REGISTER_EDI &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[0].mem.disp.has_displacement
								)
							{
								return TRUE;
							}
						}

						if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
						{
							dis_addr += info_instr.info.length;
						}
						else
						{
							next_addr_pos = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, dis_addr));
							if (is_inside_sec(next_addr_pos, mod_addr, sections))
							{
								dis_addr = next_addr_pos;
							}
							else
							{
								return FALSE;
							}
						}

						break;
					}
					case ZYDIS_MNEMONIC_JMP:
					{
						next_addr_pos = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, dis_addr));
						if (is_inside_sec(next_addr_pos, mod_addr, sections))
						{
							dis_addr = next_addr_pos;
						}
						else
						{
							return FALSE;
						}
						break;
					}
					//Just impossible
					case ZYDIS_MNEMONIC_JB:
					case ZYDIS_MNEMONIC_JBE:
					case ZYDIS_MNEMONIC_JCXZ:
					case ZYDIS_MNEMONIC_JECXZ:
					case ZYDIS_MNEMONIC_JKNZD:
					case ZYDIS_MNEMONIC_JKZD:
					case ZYDIS_MNEMONIC_JL:
					case ZYDIS_MNEMONIC_JLE:
					case ZYDIS_MNEMONIC_JNB:
					case ZYDIS_MNEMONIC_JNBE:
					case ZYDIS_MNEMONIC_JNL:
					case ZYDIS_MNEMONIC_JNLE:
					case ZYDIS_MNEMONIC_JNO:
					case ZYDIS_MNEMONIC_JNP:
					case ZYDIS_MNEMONIC_JNS:
					case ZYDIS_MNEMONIC_JNZ:
					case ZYDIS_MNEMONIC_JO:
					case ZYDIS_MNEMONIC_JP:
					case ZYDIS_MNEMONIC_JRCXZ:
					case ZYDIS_MNEMONIC_JS:
					case ZYDIS_MNEMONIC_JZ:
					{
						return FALSE;
					}
					default:
					{
						dis_addr += info_instr.info.length;
						break;
					}



					}
				}
				else
				{
					return FALSE;
				}
			}

#else  
			for (uint16_t i = NULL; i < CRC_RUN_MAX_DIS; i++)
			{
				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, dis_addr)))
				{
					switch (info_instr.info.mnemonic)
					{
					case ZYDIS_MNEMONIC_MOV:
					{
						if (
							i == NULL && !dis_info.mov_count &&
							info_instr.info.operand_count_visible == 0x2
							)
						{
							if (
								info_instr.operands[0].mem.base == ZYDIS_REGISTER_RBP &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[1].reg.value == ZYDIS_REGISTER_EAX &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
								)
							{
								dis_info.mov_count++;
							}

						}
						if (i == NULL && dis_info.mov_count == NULL)
						{
							return FALSE;
						}

						dis_addr += info_instr.info.length;

						break;
					}
					case ZYDIS_MNEMONIC_PUSH:
					{
						if (info_instr.info.operand_count_visible == 0x1)
						{

							if (
								info_instr.operands[0].mem.base == ZYDIS_REGISTER_RBP &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[0].mem.disp.has_displacement &&
								info_instr.operands[0].mem.disp.value == 0xffffffffffffffe4
								)
							{
								dis_info.push_rbp_count++;
							}

						}

						dis_addr += info_instr.info.length;

						break;
					}
					case ZYDIS_MNEMONIC_CALL:
					{
						if (
							dis_info.push_rbp_count &&
							info_instr.info.operand_count_visible == 0x1
							)
						{
							if (
								info_instr.operands[0].mem.base == ZYDIS_REGISTER_RDI &&
								info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								info_instr.operands[0].mem.disp.has_displacement
								)
							{
								return TRUE;
							}
						}

						if (info_instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
						{
							dis_addr += info_instr.info.length;
						}
						else
						{
							next_addr_pos = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, dis_addr));
							if (is_inside_sec(next_addr_pos, mod_addr, sections))
							{
								dis_addr = next_addr_pos;
							}
							else
							{
								return FALSE;
							}
						}

						break;
					}
					case ZYDIS_MNEMONIC_JMP:
					{
						next_addr_pos = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, dis_addr));
						if (is_inside_sec(next_addr_pos, mod_addr, sections))
						{
							dis_addr = next_addr_pos;
						}
						else
						{
							return FALSE;
						}
						break;
					}
					//Just impossible
					case ZYDIS_MNEMONIC_JB:
					case ZYDIS_MNEMONIC_JBE:
					case ZYDIS_MNEMONIC_JCXZ:
					case ZYDIS_MNEMONIC_JECXZ:
					case ZYDIS_MNEMONIC_JKNZD:
					case ZYDIS_MNEMONIC_JKZD:
					case ZYDIS_MNEMONIC_JL:
					case ZYDIS_MNEMONIC_JLE:
					case ZYDIS_MNEMONIC_JNB:
					case ZYDIS_MNEMONIC_JNBE:
					case ZYDIS_MNEMONIC_JNL:
					case ZYDIS_MNEMONIC_JNLE:
					case ZYDIS_MNEMONIC_JNO:
					case ZYDIS_MNEMONIC_JNP:
					case ZYDIS_MNEMONIC_JNS:
					case ZYDIS_MNEMONIC_JNZ:
					case ZYDIS_MNEMONIC_JO:
					case ZYDIS_MNEMONIC_JP:
					case ZYDIS_MNEMONIC_JRCXZ:
					case ZYDIS_MNEMONIC_JS:
					case ZYDIS_MNEMONIC_JZ:
					{
						return FALSE;
					}
					default:
					{
						dis_addr += info_instr.info.length;
						break;
					} 

					}
				}
				else
				{
					return FALSE;
				}
			}
#endif // !_WIN64
			return FALSE;
		}

		static NO_INLINE auto patch_crc_res
		(
			PVOID addr_patch,
			uint32_t id_crc_inf
		) -> VOID
		{
			crc_run.crc_inf[id_crc_inf].is_hooked = TRUE;
			crc_run.crc_inf[id_crc_inf].addr_hook = addr_patch;
			crc_run.crc_inf[id_crc_inf].instr_len = dis::get_len(reinterpret_cast<CHAR*>(addr_patch));

			*reinterpret_cast<uint8_t*>(addr_patch) = OPCODE_INT3;

		}
		static NO_INLINE auto get_crc_calc
		(
			PVOID exit_instr_addr,
			PVOID mod_addr,
			uint32_t id_crc_inf

		) -> VOID
		{
			BOOLEAN is_find_sec = FALSE;
			 
			uint32_t rva_exit_instr = NULL;
			uint32_t sec_size = NULL;
			CHAR* patch_mem = NULL;
			uint8_t* memory_sec = NULL;


			PIMAGE_NT_HEADERS  headers;
			PIMAGE_SECTION_HEADER sections;

			rva_exit_instr = static_cast<CHAR*>(exit_instr_addr) - mod_addr;

			if (static_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return;
			}

			headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(mod_addr) + static_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_lfanew);
			if (headers->Signature != IMAGE_NT_SIGNATURE)
			{
				return;
			}
			sections = IMAGE_FIRST_SECTION(headers);
			for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
			{
				if (
					sections[i].VirtualAddress <= rva_exit_instr &&
					sections[i].VirtualAddress + sections[i].Misc.VirtualSize > rva_exit_instr
					)
				{ 
					sections = &sections[i];
					memory_sec = static_cast<uint8_t*>(mod_addr) + sections[i].VirtualAddress;
					sec_size = sections[i].SizeOfRawData ? sections[i].SizeOfRawData : sections[i].Misc.VirtualSize;

					is_find_sec = TRUE;
				}
			}

			if (!is_find_sec) 
			{
				return;
			}

			sec_size -= HIGHT_DIS_OFFSET_CRC_CALC_END;

			for (size_t i = NULL; i < sec_size; i++)
			{

				if (is_crc_mov(memory_sec + i))
				{
					patch_mem = reinterpret_cast<CHAR*>(memory_sec + i);

					if (is_get_crc_end(patch_mem, mod_addr, sections))
					{
						patch_crc_res(patch_mem, id_crc_inf);
						return;
					}
				}

			}
			return;

		}

		//jmp - Fish VM and pushf[x] - other VM
		static NO_INLINE auto is_vm_entry_instr
		(
			CHAR* addr_exit
		) -> BOOLEAN
		{
			ZydisDisassembledInstruction dis_instr = { NULL };
			if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, addr_exit)))
			{
#ifndef _WIN64
				return dis_instr.info.mnemonic == ZYDIS_MNEMONIC_JMP || dis_instr.info.mnemonic == ZYDIS_MNEMONIC_PUSHFD;
#else
				return dis_instr.info.mnemonic == ZYDIS_MNEMONIC_JMP || dis_instr.info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ;
#endif // !_WIN64

			}
			return FALSE;
		}

		static NO_INLINE auto is_set_hook
		(
			PVOID addr,
			PVOID* mod_addr,
			uint32_t* id_crc_inf
		) -> BOOLEAN
		{
			PVOID protected_mod = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			//Themida sec Characteristics 0xE0000060
			if (VirtualQuery(addr, &mbi, sizeof(mbi)) && mbi.Type == MEM_IMAGE && ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)))
			{
				for (size_t i = NULL; i < crc_run.crc_inf.size(); i++)
				{

					if (!crc_run.crc_inf[i].protected_mod)
					{
						protected_mod = GetModuleHandleW(crc_run.crc_inf[i].name_mod);
						if (protected_mod)
						{
							crc_run.crc_inf[i].protected_mod = protected_mod;
						}
					}
					else
					{
						protected_mod = crc_run.crc_inf[i].protected_mod;
					}

					if (protected_mod && protected_mod == mbi.AllocationBase)
					{
						*mod_addr = mbi.AllocationBase;
						*id_crc_inf = i;

						return !crc_run.crc_inf[i].is_hooked;
					}
				}
			}
			return FALSE;
		}

		NO_INLINE static auto get_imp_detor
		(
			PEXCEPTION_POINTERS exception_info,
			PVOID* addr_detour,
			PVOID* addr_ret

		) -> BOOLEAN
		{
			HMODULE mod_addr = NULL;
			PVOID api_addr = NULL;
			
			for (size_t i = NULL; i < imp_obf_hook.imp.size(); i++)
			{
				for (size_t j = NULL; j < imp_obf_hook.imp[i].api_info.size(); j++)
				{
					if (imp_obf_hook.imp[i].api_info[j].api_addr)
					{ 
						api_addr = imp_obf_hook.imp[i].api_info[j].api_addr;
						 
						if (api_addr == *addr_ret)
						{
							*addr_detour = imp_obf_hook.imp[i].api_info[j].detour;
							return TRUE;
						}
					}
					else if(imp_obf_hook.imp[i].api_info[j].name_mod)
					{
						mod_addr = GetModuleHandleW(imp_obf_hook.imp[i].api_info[j].name_mod);
						if (mod_addr)
						{
							api_addr = GetProcAddress(mod_addr, imp_obf_hook.imp[i].api_info[j].name_api);
							if (api_addr)
							{
								imp_obf_hook.imp[i].api_info[j].api_addr = api_addr; 
								if (api_addr == *addr_ret)
								{
									*addr_detour = imp_obf_hook.imp[i].api_info[j].detour;
									return TRUE;
								}
							}
						}
					}
				}

			}
			return FALSE;

		}

		NO_INLINE static auto is_obf_imp(PEXCEPTION_POINTERS exception_info) -> BOOLEAN
		{
			PVOID addr_detour = NULL;
			PVOID addr_ret = NULL;

			for (size_t i = NULL; i < imp_obf_hook.imp.size(); i++)
			{ 
				for (size_t j = NULL; j < imp_obf_hook.imp[i].addr_bp.size(); j++)
				{ 

					if (imp_obf_hook.imp[i].addr_bp[j] == exception_info->ExceptionRecord->ExceptionAddress)
					{
#ifndef _WIN64
						addr_ret = *reinterpret_cast<PVOID*>(exception_info->ContextRecord->Esp);
						if (get_imp_detor(exception_info, &addr_detour, &addr_ret))
						{
							exception_info->ContextRecord->Eip = reinterpret_cast<DWORD>(addr_detour);
							exception_info->ContextRecord->Esp += sizeof(PVOID);
						}
						else //not detour exist
						{
							exception_info->ContextRecord->Eip = *reinterpret_cast<DWORD64*>(exception_info->ContextRecord->Esp);
							exception_info->ContextRecord->Esp += sizeof(PVOID);

						}
#else
						addr_ret = *reinterpret_cast<PVOID*>(exception_info->ContextRecord->Rsp);
						if (get_imp_detor(exception_info, &addr_detour, &addr_ret))
						{
							
							exception_info->ContextRecord->Rip = reinterpret_cast<DWORD64>(addr_detour);
							exception_info->ContextRecord->Rsp += sizeof(PVOID);
						}
						else //not detour exist
						{
							exception_info->ContextRecord->Rip = *reinterpret_cast<DWORD64*>(exception_info->ContextRecord->Rsp);
							exception_info->ContextRecord->Rsp += sizeof(PVOID);
 						}
#endif // !_WIN64 
						return TRUE;
						 
					}
				}
			}
			return FALSE; 
		}

		NO_INLINE static auto log_name(PVOID addr, CHAR* mod_address) -> VOID
		{

			uint32_t rva_api = NULL;
			PIMAGE_DOS_HEADER dos_head = NULL;
			PIMAGE_NT_HEADERS nt_head = NULL;
			PIMAGE_EXPORT_DIRECTORY export_dir = NULL;

			rva_api = reinterpret_cast<CHAR*>(addr) - mod_address;
			 
			dos_head = reinterpret_cast<PIMAGE_DOS_HEADER>(mod_address);
			if ( dos_head->e_magic != IMAGE_DOS_SIGNATURE)
				return ;
			nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(mod_address + dos_head->e_lfanew);
			if (nt_head->Signature != IMAGE_NT_SIGNATURE)
				return;
			export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(mod_address + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (!export_dir)
			{
 				return;
			}

			auto names = (PDWORD)(mod_address + export_dir->AddressOfNames);
			auto ordinals = (PWORD)(mod_address + export_dir->AddressOfNameOrdinals);
			auto functions = (PDWORD)(mod_address + export_dir->AddressOfFunctions);

			for (uint32_t i = NULL; i < export_dir->NumberOfFunctions; ++i)
			{
				if (functions[ordinals[i]] == rva_api)
				{
					//Log in file :) reinterpret_cast<CHAR*>(mod_address + names[i])
					return;
				}
			}
			return;

		}

		NO_INLINE static auto is_loader_ret
		(
			PEXCEPTION_POINTERS exception_info
		) -> BOOLEAN
		{ 
			PVOID pos_api_addr = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			for (size_t i = NULL; i < addr_ret_loader_api.size(); i++)
			{
				if (addr_ret_loader_api[i].addr_ret_loader_api == exception_info->ExceptionRecord->ExceptionAddress)
				{ 
#ifndef _WIN64
					pos_api_addr = reinterpret_cast<PVOID>(exception_info->ContextRecord->Eax);
#else
					pos_api_addr = reinterpret_cast<PVOID>(exception_info->ContextRecord->Rax);
#endif // !_WIN64

					if(VirtualQuery(pos_api_addr, &mbi, sizeof(mbi)))
					{
#ifndef _WIN64
						log_name(reinterpret_cast<PVOID>(exception_info->ContextRecord->Eax), reinterpret_cast<CHAR*>( mbi.AllocationBase));
						exception_info->ContextRecord->Eip = reinterpret_cast<DWORD>(addr_ret_loader_api[i].rip_fixed);
						
						//exception_info->ContextRecord->Eip = *reinterpret_cast<DWORD*>(exception_info ->ContextRecord->Esp);
						//exception_info->ContextRecord->Esp += (sizeof(PVOID) * 2);
#else
						log_name(reinterpret_cast<PVOID>(exception_info->ContextRecord->Rax), reinterpret_cast<CHAR*>(mbi.AllocationBase));
						
						exception_info->ContextRecord->Rip = reinterpret_cast<DWORD64>(addr_ret_loader_api[i].rip_fixed);
						
						//exception_info->ContextRecord->Rip = *reinterpret_cast<DWORD64*>(exception_info->ContextRecord->Rsp);
						//exception_info->ContextRecord->Rsp += (sizeof(PVOID) * 5);
#endif // !_WIN64 
						return TRUE;
					}
				}
			}
			return FALSE; 
		}

		//Check and fix
		NO_INLINE static auto is_crc_calc
		(
			PEXCEPTION_POINTERS exception_info
		) -> BOOLEAN
		{
			for (uint32_t i = NULL; i < crc_run.crc_inf.size(); i++)
			{
				if (crc_run.crc_inf[i].addr_hook == exception_info->ExceptionRecord->ExceptionAddress)
				{

					//don't cacl CRC
					if(!crc_run.crc_inf[i].is_manual_res_crc)
					{
#ifndef _WIN64
						crc_run.crc_inf[i].res_crc = exception_info->ContextRecord->Eax;
#else
						crc_run.crc_inf[i].res_crc = exception_info->ContextRecord->Rax;
#endif
						crc_run.crc_inf[i].is_manual_res_crc = TRUE;
					}

#ifndef _WIN64
					//mov dword ptr ss : [esp] , eax
					exception_info->ContextRecord->Eax = crc_run.crc_inf[i].res_crc;
					*reinterpret_cast<PULONG>(exception_info->ContextRecord->Esp) = crc_run.crc_inf[i].res_crc,
					exception_info->ContextRecord->Eip += crc_run.crc_inf[i].instr_len;
#else 
					//mov dword ptr ss : [rbp - 20] , eax
					exception_info->ContextRecord->Rax = crc_run.crc_inf[i].res_crc;

					*reinterpret_cast<PULONG>(exception_info->ContextRecord->Rbp - 0x20) = crc_run.crc_inf[i].res_crc;

					exception_info->ContextRecord->Rip += crc_run.crc_inf[i].instr_len;
#endif // !_WIN64

					return TRUE;
				}

			}
			return FALSE;
		}
	public:

		static auto WINAPI virtual_alloc
		(
			LPVOID lpAddress,
			SIZE_T dwSize,
			DWORD  flAllocationType,
			DWORD  flProtect
		) -> LPVOID
		{  
			PVOID ret_addr = NULL;
			LPVOID res_api = NULL;
			 
			PVOID mod_addr;
			uint32_t id_crc_inf;

			ret_addr = _ReturnAddress();

			res_api = reinterpret_cast<decltype(&VirtualAlloc)>(crc_run.orig_virt_alloc)(lpAddress, dwSize, flAllocationType, flProtect);
			if (is_vm_entry_instr(reinterpret_cast<CHAR*>(ret_addr)) && is_set_hook(ret_addr,&mod_addr, &id_crc_inf))
			{
				get_crc_calc( ret_addr, mod_addr, id_crc_inf);
			}
			return res_api;
		} 
		
		 
		static auto WINAPI veh_hook
		(
			PEXCEPTION_POINTERS exception_info
		) -> LONG
		{
			if (exception_info->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
			{
				if (is_crc_calc(exception_info))
				{
					return  EXCEPTION_CONTINUE_EXECUTION;
				}
				else if (is_obf_imp(exception_info))
				{
					return  EXCEPTION_CONTINUE_EXECUTION;
				}
				else if (is_loader_ret(exception_info))
				{
					return  EXCEPTION_CONTINUE_EXECUTION;
				}
			}

			return EXCEPTION_CONTINUE_SEARCH;
		}
		
	};

 
	class anti_analisys_util
	{
	private:
		NO_INLINE static auto  tolower(INT c) -> INT
		{
			if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
			return c;
		}

		NO_INLINE static auto stricmp(CONST CHAR* cs, CONST CHAR* ct) -> INT
		{
			if (cs && ct)
			{
				while (tolower(*cs) == tolower(*ct))
				{
					if (*cs == 0 && *ct == 0) return NULL;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return tolower(*cs) - tolower(*ct);
			}
			return -1;
		}

	public:

		static auto WINAPI add_vector_exc_handler
		(
			ULONG                       First,
			PVECTORED_EXCEPTION_HANDLER Handler
		) -> PVOID
		{
			if (addr_ret_loader_api.size())
			{
				First = FALSE;
			}
			return reinterpret_cast<decltype(&AddVectoredExceptionHandler)>(orig_add_vec_handler)(First, Handler);
		}

		static auto WINAPI find_windowa
		(
			LPCSTR lpClassName,
			LPCSTR lpWindowName
		) -> HWND
		{
			HWND res_api = NULL;
			CONST CHAR* bad_class_name[] = { "FilemonClass", "PROCMON_WINDOW_CLASS","RegmonClass","18467-41","Registry Monitor - Sysinternals: www.sysinternals.com", "OLLYDBG", "GBDYLLO" ,"pediy06"};
			CONST CHAR* bad_window_name[] = { "Process Monitor - Sysinternals: www.sysinternals.com","File Monitor - Sysinternals: www.sysinternals.com" };

			res_api = reinterpret_cast<decltype(&FindWindowA)>(anti_monit.orig_find_windowa)(lpClassName, lpWindowName);
			if (res_api)
			{
				if (lpClassName)
				{
					for (size_t i = NULL; i < _countof(bad_class_name); i++)
					{
						if (!stricmp(lpClassName, bad_class_name[i]))
						{
							return NULL;
						}
					}

				}
				if (bad_window_name)
				{
					for (size_t i = NULL; i < _countof(bad_window_name); i++)
					{
						if (!stricmp(lpWindowName, bad_window_name[i]))
						{
							return NULL;
						}
					}

				}
			}
			return res_api; 
		}

		static auto  WINAPI strcmpa
		(
			LPCSTR lpString1,
			LPCSTR lpString2
		) -> INT
		{
			INT res_api = NULL;

			CONST CHAR* bad_driver[] = { "FileMonitor.sys","Filem","REGMON","regsys","sysregm","PROCMON","Kernel Detective","CisUtMonitor","Revoflt"};
			 
			res_api = reinterpret_cast<decltype(&lstrcmpiA)>(anti_monit.orig_strcmpa)(lpString1, lpString2);
			if (lpString1 != lpString2 && !res_api)
			{
				for (size_t i = NULL; i < _countof(bad_driver); i++)
				{
					if (!stricmp(lpString1, bad_driver[i]))
					{
						return -1;
					}
					else if (!stricmp(lpString2, bad_driver[i])) //we safe
					{
						return -1;
					}
				}
			}
			return res_api;
		}
	};

	class anti_vm_util
	{
	private:

		NO_INLINE static auto tolower
		(
			INT c
		) -> INT
		{
			if (c >= 'A' && c <= 'Z') 
				return c - 'A' + 'a';
			return c;
		}

		NO_INLINE static auto toupper
		(
			INT c
		) -> INT
		{
			if (c >= 'a' && c <= 'z') 
				return c - 'a' + 'A';
			return c;
		}

		NO_INLINE static auto stricmp
		(
			CONST CHAR* cs,
			CONST CHAR* ct
		) -> INT
		{
			if (cs && ct)
			{
				while (tolower(*cs) == tolower(*ct))
				{
					if (*cs == 0 && *ct == 0) return NULL;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return tolower(*cs) - tolower(*ct);
			}
			return -1;
		}

		NO_INLINE static auto  memicmp
		(
			CONST VOID* s1, 
			CONST VOID* s2,
			unsigned __int64 n
		) ->  INT 
		{
			if (n != NULL)
			{
				const uint8_t* p1 = (uint8_t *)s1, * p2 = (uint8_t*)s2;
				do
				{
					if (toupper(*p1) != toupper(*p2)) 
						return (*p1 - *p2);
					p1++;
					p2++;
				} while (--n != NULL);
			}
			return NULL;
		}

		NO_INLINE static auto memcpy
		(
			PVOID dest,
			CONST VOID* src, 
			uint64_t count
		) -> PVOID
		{
			char* char_dest = (char*)dest;
			char* char_src = (char*)src;
			if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
			{
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest++;
					char_src++;
					count--;
				}
			}
			else
			{
				char_dest = (char*)dest + count - 1;
				char_src = (char*)src + count - 1;
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest--;
					char_src--;
					count--;
				}
			}
			return dest;
		}
		NO_INLINE static auto memset
		(
			void* src, 
			int val, 
			unsigned __int64 count
		) -> PVOID
		{
			__stosb((unsigned char*)((unsigned long long)(volatile char*)src), val, count);
			return src;
		}

		NO_INLINE static auto WINAPI reg_remove_string
		(
			PVOID buffer,
			uint32_t buf_size
		)
		{
			CONST CHAR* bad_string[] = {"VMware", "VBOX","Parallel", "Oracle","PRLS"};
			CONST INT bad_string_len[] = { sizeof("VMware")-1, sizeof("VBOX") - 1,sizeof("Parallel") - 1, sizeof("Oracle") - 1,sizeof("PRLS") - 1};
			CONST INT max_len_bad_str = sizeof("Parallel") - 1;

			CONST CHAR* good_str = { "Meh" };

			for (size_t i = NULL; i < buf_size - max_len_bad_str; i++)
			{
				for (size_t j = NULL; j < _countof(bad_string); j++)
				{
					if (!memicmp(reinterpret_cast<CHAR*>(buffer) + i, bad_string[j], bad_string_len[j]))
					{
						memset(reinterpret_cast<CHAR*>(buffer) + i, NULL, bad_string_len[j]);
						memcpy(reinterpret_cast<CHAR*>(buffer) + i,"meh", sizeof("meh") - 1);
					}
				}
			}

		}
		NO_INLINE static auto WINAPI remove_firmware_bad_string
		(
			PVOID buffer, 
			uint32_t buf_size
		) -> VOID
		{
			CONST CHAR* bad_string = { "VMware" };
			CONST CHAR* good_str = { "MehMeh" };
			for (size_t i = 0; i < buf_size - (sizeof("VMware") - 1); i++)
			{
				if (!memicmp(reinterpret_cast<CHAR*>(buffer)+i, bad_string, sizeof("VMware") - 1))
				{
					memcpy(reinterpret_cast<CHAR*>(buffer) + i, good_str, sizeof("VMware")-1);
				}
			}
		}



		NO_INLINE static auto is_obf_imp
		(
			uint8_t* addr
		) -> BOOLEAN
		{
#ifndef _WIN64
			//push dword ptr ss:[ebp+eax]
			return
				*(addr) == 0xFF &&
				*(addr + 1) == 0x74 &&
				*(addr + 2) == 0x05 &&
				*(addr + 3) == NULL;
#else
			//push qword ptr ds:[rax+rbp]  
			return
				*(addr) == 0xFF &&
				*(addr + 1) == 0x34 &&
				*(addr + 2) == 0x28;
#endif // !_WIN64 

		}

		NO_INLINE static auto is_exit_instr
		(
			uint8_t* addr
		) -> BOOLEAN
		{
#ifndef _WIN64
			//push dword ptr fs:[0x00000000]
			return
				*(addr) == 0x64 &&
				*(addr + 1) == 0xFF &&
				*(addr + 2) == 0x35 &&
				*(addr + 3) == 0x00 &&
				*(addr + 4) == 0x00 &&
				*(addr + 5) == 0x00 &&
				*(addr + 6) == 0x00;
#else 

			return FALSE;
#endif // !_WIN64 

		}
		NO_INLINE static auto is_imp_loader
		(
			uint8_t* addr
		) -> BOOLEAN
		{
#ifndef _WIN64
			//rcl al,1
			return
				*(addr) == 0xD0 &&
				*(addr + 1) == 0xD0;
#else
			//rcl al,1 
			return
				*(addr) == 0xD0 &&
				*(addr + 1) == 0xD0;
#endif // !_WIN64 

		}

		static NO_INLINE auto is_inside_sec
		(
			CHAR* addr,
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sections
		) -> BOOLEAN
		{
			uint32_t rva_addr = NULL;
			rva_addr = reinterpret_cast<ULONGLONG>(addr) - reinterpret_cast<ULONGLONG>(mod_addr);
			if (
				sections->VirtualAddress <= rva_addr &&
				sections->VirtualAddress + sections->Misc.VirtualSize > rva_addr
				)
			{
				return TRUE;
			}
			return FALSE;
		}

		//jmp - Fish VM and pushf[x] - other VM
		static NO_INLINE auto is_vm_entry_instr
		(
			CHAR* addr_exit
		) -> BOOLEAN
		{
			ZydisDisassembledInstruction dis_instr = { NULL };
			if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, addr_exit)))
			{
#ifndef _WIN64
				return dis_instr.info.mnemonic == ZYDIS_MNEMONIC_JMP || dis_instr.info.mnemonic == ZYDIS_MNEMONIC_PUSHFD;
#else
				return dis_instr.info.mnemonic == ZYDIS_MNEMONIC_JMP || dis_instr.info.mnemonic == ZYDIS_MNEMONIC_PUSHFQ;
#endif // !_WIN64

			}
			return FALSE;
		}

		static NO_INLINE auto get_sec_info(PVOID addr,PVOID mod_addr, PIMAGE_SECTION_HEADER* themida_sec) -> BOOLEAN
		{
			uint32_t rva_mod = NULL;
			PIMAGE_NT_HEADERS headers = NULL;
			PIMAGE_SECTION_HEADER sections = NULL;

			rva_mod = reinterpret_cast<CHAR*>(addr) - mod_addr;
			if (static_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_lfanew != IMAGE_DOS_SIGNATURE)
				FALSE;
			headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(mod_addr) + static_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_lfanew);
			if (headers->Signature != IMAGE_NT_SIGNATURE)
			{
				return FALSE;
			}
			sections = IMAGE_FIRST_SECTION(headers);

			for (size_t sec_cur = NULL; sec_cur < headers->FileHeader.NumberOfSections; sec_cur++)
			{
				if 
				(
					rva_mod >= sections[sec_cur].VirtualAddress &&
					sections[sec_cur].VirtualAddress + sections[sec_cur].Misc.VirtualSize > rva_mod
					
				)
				{
					*themida_sec = &sections[sec_cur];
					return TRUE;
				}
			}
			return FALSE;

		}

		static NO_INLINE auto is_set_hook_obf_imp
		(
			PVOID addr,
			PVOID* mod_addr,
			uint32_t* id_obf_imp
		) -> BOOLEAN
		{
			PVOID protected_mod = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };

			if (!imp_obf_hook.imp.size())
			{
				return FALSE;
			}
			//Themida sec Characteristics 0xE0000060
			if (VirtualQuery(addr, &mbi, sizeof(mbi)) && mbi.Type == MEM_IMAGE && ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)))
			{
				for (size_t i = NULL; i < imp_obf_hook.imp.size(); i++)
				{

					if (!imp_obf_hook.imp[i].user_mod_addr)
					{
						protected_mod = GetModuleHandleW(imp_obf_hook.imp[i].user_name_mod);
						if (protected_mod)
						{
							imp_obf_hook.imp[i].user_mod_addr = protected_mod;
						}
					}
					else
					{
						protected_mod = imp_obf_hook.imp[i].user_mod_addr;
					}

					if (protected_mod && protected_mod == mbi.AllocationBase)
					{
						*mod_addr = mbi.AllocationBase;
						*id_obf_imp = i;

						return !imp_obf_hook.imp[i].is_init_hook;
					}
				}
			}
			return FALSE;
		}

		static NO_INLINE auto is_set_hook_loader_imp
		(
			PVOID addr,
			PVOID* mod_addr,
			uint32_t* id_obf_imp
		) -> BOOLEAN
		{
			PVOID protected_mod = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };

			if (!addr_ret_loader_api.size())
			{
				return FALSE;
			}

			//Themida sec Characteristics 0xE0000060
			if (VirtualQuery(addr, &mbi, sizeof(mbi)) && mbi.Type == MEM_IMAGE && ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)))
			{
				for (size_t i = NULL; i < addr_ret_loader_api.size(); i++)
				{
					 
					if (!addr_ret_loader_api[i].addr_mod)
					{
						protected_mod = GetModuleHandleW(addr_ret_loader_api[i].name_mod);
						if (protected_mod)
						{
							addr_ret_loader_api[i].addr_mod = protected_mod;
						}
					}
					else
					{
						protected_mod = addr_ret_loader_api[i].addr_mod;
					}

					if (protected_mod && protected_mod == mbi.AllocationBase)
					{
						*mod_addr = mbi.AllocationBase;
						*id_obf_imp = i;

						return !addr_ret_loader_api[i].is_init_hook;
					}
				}
			}
			return FALSE;
		}


		static NO_INLINE auto is_set_hook_vmware_instr
		(
			PVOID addr,
			PVOID* mod_addr,
			uint32_t* id_exit_instr
		) -> BOOLEAN
		{
			PVOID protected_mod = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };

#ifndef _WIN64 
			if (!anti_vm.exit_anti_vm.size())
			{
				return FALSE;
			} 
#else 
			return FALSE;
#endif
			//Themida sec Characteristics 0xE0000060
			if (VirtualQuery(addr, &mbi, sizeof(mbi)) && mbi.Type == MEM_IMAGE && ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)))
			{
				for (size_t i = NULL; i < anti_vm.exit_anti_vm.size(); i++)
				{ 
					if (!anti_vm.exit_anti_vm[i].mod_addr)
					{
						protected_mod = GetModuleHandleW(anti_vm.exit_anti_vm[i].mod_name);
						if (protected_mod)
						{
							anti_vm.exit_anti_vm[i].mod_addr = protected_mod;
						}
					}
					else
					{
						protected_mod = anti_vm.exit_anti_vm[i].mod_addr;
					}

					if (protected_mod && protected_mod == mbi.AllocationBase)
					{
						*mod_addr = mbi.AllocationBase;
						*id_exit_instr = i;

						return !anti_vm.exit_anti_vm[i].is_init;
					}
				}
			}
			return FALSE;
		}

		NO_INLINE static auto add_bp_obf_imp
		(
			PVOID mod_addr,
			PVOID addr_bp
		) -> VOID
		{
			PVOID cur_mod = NULL;
			for (size_t i = NULL; i < imp_obf_hook.imp.size(); i++)
			{
				if (imp_obf_hook.imp[i].user_mod_addr)
				{
					if (mod_addr == imp_obf_hook.imp[i].user_mod_addr)
					{
						imp_obf_hook.imp[i].addr_bp.push_back(addr_bp);
						return;
					}
				}
				else
				{
					cur_mod = GetModuleHandleW(imp_obf_hook.imp[i].user_name_mod);
					if (cur_mod)
					{
						imp_obf_hook.imp[i].user_mod_addr = cur_mod;
						if (mod_addr == imp_obf_hook.imp[i].user_mod_addr)
						{
							imp_obf_hook.imp[i].addr_bp.push_back(addr_bp);
							return;
						}
					}
				}
			}
		}


		NO_INLINE static auto add_bp_imp_ret_loader
		(
			PVOID mod_addr,
			PVOID addr_bp
		) -> VOID
		{
			PVOID cur_mod = NULL;
			for (size_t i = NULL; i < addr_ret_loader_api.size(); i++)
			{
				if (addr_ret_loader_api[i].addr_mod)
				{
					if (mod_addr == addr_ret_loader_api[i].addr_mod)
					{
						addr_ret_loader_api[i].addr_ret_loader_api = addr_bp;
						addr_ret_loader_api[i].rip_fixed = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

						memcpy(addr_ret_loader_api[i].rip_fixed, addr_bp, dis::get_len(reinterpret_cast<CHAR*>(addr_bp)));
						*reinterpret_cast<uint8_t*>(addr_bp) = OPCODE_INT3;

 						return;
					}
				}
				else
				{
					cur_mod = GetModuleHandleW(imp_obf_hook.imp[i].user_name_mod);
					if (cur_mod)
					{
						 imp_obf_hook.imp[i].user_mod_addr = cur_mod;
						if (mod_addr == addr_ret_loader_api[i].addr_mod)
						{

							addr_ret_loader_api[i].addr_ret_loader_api = addr_bp;
							addr_ret_loader_api[i].rip_fixed = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

							memcpy(addr_ret_loader_api[i].rip_fixed, addr_bp, dis::get_len(reinterpret_cast<CHAR*>(addr_bp)));
							*reinterpret_cast<uint8_t*>(addr_bp) = OPCODE_INT3;
							return;
						}
					}
				}
			}
		}

		NO_INLINE static auto get_patch_exit_obf_imp
		(
			uint8_t* mem,
			PVOID dis_api,
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sec,
			BOOLEAN patch_call_fake,
			uint32_t recurs = NULL,
			uint32_t jcc = NULL
		) -> BOOLEAN
		{

			CHAR* addr_call_dyn = NULL;
			CHAR* pos_addr = NULL;
#ifndef _WIN64
			DIS_INFO_API_OBF32 save_dis_info = { NULL };
#else
			DIS_INFO_API_OBF64 save_dis_info = { NULL };
#endif // !_WIN64

			ZydisDisassembledInstruction info_instr;

#ifndef _WIN64
			if (recurs >= 2 || jcc >= 2)
			{
				return FALSE;
			}

			for (size_t i = 0; i < HIGHT_DIS_OFFSET_OBF_API; i++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{

					switch (info_instr.info.mnemonic)
					{
					case ZYDIS_MNEMONIC_INT3:
					{
						return FALSE;
						break;
					}
					case ZYDIS_MNEMONIC_ADD:
					case ZYDIS_MNEMONIC_SUB:
					{
						if
							(
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								(
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_RAX ||
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EAX
									)
								)
						{
							reinterpret_cast<PDIS_INFO_API_OBF32>(dis_api)->count_sub_add++;
						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_XOR:
					{
						if
							(
								reinterpret_cast<PDIS_INFO_API_OBF32>(dis_api)->count_sub_add &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								(
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_RAX ||
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EAX
									)
								)
						{
							reinterpret_cast<PDIS_INFO_API_OBF32>(dis_api)->count_xor++;
						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_CALL:
					{
						if
							(
								reinterpret_cast<PDIS_INFO_API_OBF32>(dis_api)->count_sub_add &&
								reinterpret_cast<PDIS_INFO_API_OBF32>(dis_api)->count_xor &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY
								)
						{
							if (!addr_call_dyn)
							{
								addr_call_dyn = reinterpret_cast<CHAR*>(mem);
							}
							else
							{
								return FALSE; //2 or more
							}
						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_JMP:
					{
						if (info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
						{

							pos_addr = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(info_instr.runtime_address)));
							if (!is_inside_sec(pos_addr, mod_addr, sec))
							{
								return FALSE;
							}
							mem = reinterpret_cast<uint8_t*>(pos_addr);
						}
						else
						{
							return FALSE;
						}
						break;
					}

					case ZYDIS_MNEMONIC_JB:
					case ZYDIS_MNEMONIC_JBE:
					case ZYDIS_MNEMONIC_JCXZ:
					case ZYDIS_MNEMONIC_JECXZ:
					case ZYDIS_MNEMONIC_JKNZD:
					case ZYDIS_MNEMONIC_JKZD:
					case ZYDIS_MNEMONIC_JL:
					case ZYDIS_MNEMONIC_JLE:
					case ZYDIS_MNEMONIC_JNB:
					case ZYDIS_MNEMONIC_JNBE:
					case ZYDIS_MNEMONIC_JNL:
					case ZYDIS_MNEMONIC_JNLE:
					case ZYDIS_MNEMONIC_JNO:
					case ZYDIS_MNEMONIC_JNP:
					case ZYDIS_MNEMONIC_JNS:
					case ZYDIS_MNEMONIC_JNZ:
					case ZYDIS_MNEMONIC_JO:
					case ZYDIS_MNEMONIC_JP:
					case ZYDIS_MNEMONIC_JRCXZ:
					case ZYDIS_MNEMONIC_JS:
					case ZYDIS_MNEMONIC_JZ:
					{
						jcc++;

						//pos_addr;
						memcpy(&save_dis_info, dis_api, sizeof(save_dis_info));
						pos_addr = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(info_instr.runtime_address)));
						if (is_inside_sec(pos_addr, mod_addr, sec))
						{
							recurs++;
							get_patch_exit_obf_imp(reinterpret_cast<uint8_t*>(pos_addr), &save_dis_info, mod_addr, sec, patch_call_fake, recurs, jcc);
						}
						mem += info_instr.info.length; 
						break;

					}
					case ZYDIS_MNEMONIC_RET:
					{
						if
							(
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								(
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_RIP ||
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EIP
									)
								)
						{
							if (is_inside_sec(reinterpret_cast<CHAR*>(mem), mod_addr, sec))
							{
								if (addr_call_dyn) //not exist in 3.0.4.0 and other ???
								{
									memset(addr_call_dyn, OPCODE_NOP, dis::get_len(addr_call_dyn));
								}
								add_bp_obf_imp(mod_addr, mem);
								*mem = OPCODE_INT3;
								return TRUE;
							}
						}
						return FALSE;
					}

					default:
					{
						mem += info_instr.info.length;
						break;
					}

					}
				}
				else
				{
					return NULL;
				}
				if (!is_inside_sec(reinterpret_cast<CHAR*>(mem), mod_addr, sec) || jcc >= 2)
				{
					return FALSE;
				}


			}

#else
			if (recurs >= 2 || jcc >= 2)
			{
				return FALSE;
			}

			for (size_t i = 0; i < HIGHT_DIS_OFFSET_OBF_API; i++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{

					switch (info_instr.info.mnemonic)
					{
					case ZYDIS_MNEMONIC_INT3:
					{
						return FALSE;
						break;
					}
					case ZYDIS_MNEMONIC_ADD:
					case ZYDIS_MNEMONIC_SUB:
					{
						if
							(
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								(
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_RAX ||
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EAX
									)
								)
						{
							reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_sub_add++;

						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_XOR:
					{
						if
							(
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_sub_add &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								(
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_RAX ||
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EAX
									)
								)
						{
							reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_xor++;
						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_AND:
					{
						if
							(
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_sub_add &&
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_xor &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								(
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_RAX ||
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EAX
									)
								)
						{
							reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_and++;
						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_OR:
					{
						if
							(
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_sub_add &&
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_xor &&
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_and &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								(
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_RAX ||
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EAX
									)
								)
						{
							reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_or++;
						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_CALL:
					{
						if
							(
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_sub_add &&
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_xor &&
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_and &&
								reinterpret_cast<PDIS_INFO_API_OBF64>(dis_api)->count_or &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY
								)
						{
							if (!addr_call_dyn)
							{
								addr_call_dyn = reinterpret_cast<CHAR*>(mem);
							}
							else
							{
								return FALSE; //2 or more
							}
						}
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_JMP:
					{
						if (info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
						{

							pos_addr = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(info_instr.runtime_address)));
							if (!is_inside_sec(pos_addr, mod_addr, sec))
							{
								return FALSE;
							}
							mem = reinterpret_cast<uint8_t*>(pos_addr);
						}
						else
						{
							return FALSE;
						}
						break;
					}

					case ZYDIS_MNEMONIC_JB:
					case ZYDIS_MNEMONIC_JBE:
					case ZYDIS_MNEMONIC_JCXZ:
					case ZYDIS_MNEMONIC_JECXZ:
					case ZYDIS_MNEMONIC_JKNZD:
					case ZYDIS_MNEMONIC_JKZD:
					case ZYDIS_MNEMONIC_JL:
					case ZYDIS_MNEMONIC_JLE:
					case ZYDIS_MNEMONIC_JNB:
					case ZYDIS_MNEMONIC_JNBE:
					case ZYDIS_MNEMONIC_JNL:
					case ZYDIS_MNEMONIC_JNLE:
					case ZYDIS_MNEMONIC_JNO:
					case ZYDIS_MNEMONIC_JNP:
					case ZYDIS_MNEMONIC_JNS:
					case ZYDIS_MNEMONIC_JNZ:
					case ZYDIS_MNEMONIC_JO:
					case ZYDIS_MNEMONIC_JP:
					case ZYDIS_MNEMONIC_JRCXZ:
					case ZYDIS_MNEMONIC_JS:
					case ZYDIS_MNEMONIC_JZ:
					{
						//pos_addr;
						memcpy(&save_dis_info, &dis_api, sizeof(save_dis_info));
						pos_addr = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(info_instr.runtime_address)));
						if (is_inside_sec(pos_addr, mod_addr, sec))
						{
							recurs++;
							get_patch_exit_obf_imp(reinterpret_cast<uint8_t*>(pos_addr), &save_dis_info, mod_addr, sec, patch_call_fake, recurs, jcc);
						}
						mem += info_instr.info.length;
						jcc++;

						break;

					}
					case ZYDIS_MNEMONIC_RET:
					{
						if
							(
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								(
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_RIP ||
									info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EIP
									)
								)
						{
							if (is_inside_sec(reinterpret_cast<CHAR*>(mem), mod_addr, sec))
							{
								if (addr_call_dyn) //not exist in 3.0.4.0 and other ???
								{
									memset(addr_call_dyn, OPCODE_NOP, dis::get_len(addr_call_dyn));
								}
								add_bp_obf_imp(mod_addr, mem);
								*mem = OPCODE_INT3;
								return TRUE;
							}
						}
						return FALSE;
					}

					default:
					{
						mem += info_instr.info.length;
						break;
					}

					}
				}
				else
				{
					return NULL;
				}
				if (!is_inside_sec(reinterpret_cast<CHAR*>(mem), mod_addr, sec) || jcc >= 2)
				{
					return FALSE;
				}


			}



#endif // !_WIN64
			return FALSE;

		}
		 
		NO_INLINE static auto get_patch_imp_loader
		(
			uint8_t* mem,
			PDIS_LOADER_GET_API dis_ret_load,
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sec,
			uint32_t recurs = NULL,
			uint32_t jcc = NULL
		) -> BOOLEAN
		{

			CHAR* pos_addr = NULL;

			DIS_LOADER_GET_API save_dis_info = { NULL };
 			ZydisDisassembledInstruction info_instr;

			if (recurs >= 5 || jcc >= 5)
			{
				return FALSE;
			}

			for (size_t i = 0; i < HIGHT_DIS_OFFSET_OBF_API; i++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{

					switch (info_instr.info.mnemonic)
					{
					case ZYDIS_MNEMONIC_INT3:
					{
						return FALSE;
						break;
					}

					case ZYDIS_MNEMONIC_RCL:
					{
						if
							(
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_AL &&
								info_instr.operands[1].imm.value.u == 1
								)
						{
							dis_ret_load->count_rcl++;
						}
						mem += info_instr.info.length;
						break;
					}
					case ZYDIS_MNEMONIC_LEAVE:
					{
						if (
							dis_ret_load->count_rcl >= 2
							)
						{
							dis_ret_load->count_leave++;
						}
						mem += info_instr.info.length;
						break;
					}
					case ZYDIS_MNEMONIC_JMP:
					{
						if (info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
						{

							pos_addr = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(info_instr.runtime_address)));
							if (!is_inside_sec(pos_addr, mod_addr, sec))
							{
								return FALSE;
							}
							mem = reinterpret_cast<uint8_t*>(pos_addr);
						}
						else
						{
							return FALSE;
						}
						break;
					}

					case ZYDIS_MNEMONIC_JB:
					case ZYDIS_MNEMONIC_JBE:
					case ZYDIS_MNEMONIC_JCXZ:
					case ZYDIS_MNEMONIC_JECXZ:
					case ZYDIS_MNEMONIC_JKNZD:
					case ZYDIS_MNEMONIC_JKZD:
					case ZYDIS_MNEMONIC_JL:
					case ZYDIS_MNEMONIC_JLE:
					case ZYDIS_MNEMONIC_JNB:
					case ZYDIS_MNEMONIC_JNBE:
					case ZYDIS_MNEMONIC_JNL:
					case ZYDIS_MNEMONIC_JNLE:
					case ZYDIS_MNEMONIC_JNO:
					case ZYDIS_MNEMONIC_JNP:
					case ZYDIS_MNEMONIC_JNS:
					case ZYDIS_MNEMONIC_JNZ:
					case ZYDIS_MNEMONIC_JO:
					case ZYDIS_MNEMONIC_JP:
					case ZYDIS_MNEMONIC_JRCXZ:
					case ZYDIS_MNEMONIC_JS:
					case ZYDIS_MNEMONIC_JZ:
					{
						//pos_addr;
						memcpy(&save_dis_info, dis_ret_load, sizeof(save_dis_info));
						pos_addr = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(info_instr.runtime_address)));
						if (is_inside_sec(pos_addr, mod_addr, sec))
						{
							recurs++;
							if (get_patch_imp_loader(reinterpret_cast<uint8_t*>(pos_addr), &save_dis_info, mod_addr, sec, recurs, jcc))
							{
								return TRUE;
							}
						}
						mem += info_instr.info.length;
						jcc++;

						break;

					}

					case ZYDIS_MNEMONIC_RET:
					{
						if
							(
								dis_ret_load->count_rcl >= 3 &&
								dis_ret_load->count_leave &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
								)
						{
							if (is_inside_sec(reinterpret_cast<CHAR*>(mem), mod_addr, sec))
							{
								add_bp_imp_ret_loader(mod_addr,mem);
								return TRUE;
							}
						}
						return FALSE;
					}

					default:
					{
						mem += info_instr.info.length;
						break;
					}

					}
				}
				else
				{
					return NULL;
				}
				if (!is_inside_sec(reinterpret_cast<CHAR*>(mem), mod_addr, sec) || jcc >= 5)
				{
					return FALSE;
				}


			}

			return FALSE;
		}


		NO_INLINE static auto get_patch_exit_vm_instr
		(
			uint8_t* mem,
			PDIS_EXIT_PORT_INSTR dis_exit_vm_instr,
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sec,
			uint32_t recurs = NULL,
			uint32_t jcc = NULL
		) -> BOOLEAN
		{
			CHAR* pos_addr = NULL;

			uint8_t instr_cmp_self[] = { 0x38, 0xC0 };
			uint8_t instr_impossible[] = { 0x83, 0xFC, NULL };

			DIS_EXIT_PORT_INSTR save_dis_info = { NULL };
			ZydisDisassembledInstruction info_instr;


			if (recurs >= 5 || jcc >= 5)
			{
				return FALSE;
			}

			for (size_t i = 0; i < HIGHT_DIS_OFFSET_EXIT_PORT_INSTR; i++)
			{

				if (ZYAN_SUCCESS(dis::get_dis(&info_instr, reinterpret_cast<CHAR*>(mem))))
				{

					switch (info_instr.info.mnemonic)
					{
						case ZYDIS_MNEMONIC_INT3:
						{
							return FALSE;
							break;
						}
					 
					case ZYDIS_MNEMONIC_JMP:
					{
						if (info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
						{

							pos_addr = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(info_instr.runtime_address)));
							if (!is_inside_sec(pos_addr, mod_addr, sec))
							{
								return FALSE;
							}
							mem = reinterpret_cast<uint8_t*>(pos_addr);
						}
						else
						{
							return FALSE;
						}
						break;
					}

					case ZYDIS_MNEMONIC_JB:
					case ZYDIS_MNEMONIC_JBE:
					case ZYDIS_MNEMONIC_JCXZ:
					case ZYDIS_MNEMONIC_JECXZ:
					case ZYDIS_MNEMONIC_JKNZD:
					case ZYDIS_MNEMONIC_JKZD:
					case ZYDIS_MNEMONIC_JL:
					case ZYDIS_MNEMONIC_JLE:
					case ZYDIS_MNEMONIC_JNB:
					case ZYDIS_MNEMONIC_JNBE:
					case ZYDIS_MNEMONIC_JNL:
					case ZYDIS_MNEMONIC_JNLE:
					case ZYDIS_MNEMONIC_JNO:
					case ZYDIS_MNEMONIC_JNP:
					case ZYDIS_MNEMONIC_JNS:
					case ZYDIS_MNEMONIC_JNZ:
					case ZYDIS_MNEMONIC_JO:
					case ZYDIS_MNEMONIC_JP:
					case ZYDIS_MNEMONIC_JRCXZ:
					case ZYDIS_MNEMONIC_JS:
					case ZYDIS_MNEMONIC_JZ:
					{
						//pos_addr;
						memcpy(&save_dis_info, dis_exit_vm_instr, sizeof(save_dis_info));
						pos_addr = reinterpret_cast<CHAR*>(dis::get_absolute_address(&info_instr, reinterpret_cast<CHAR*>(info_instr.runtime_address)));
						if (is_inside_sec(pos_addr, mod_addr, sec))
						{
							recurs++;
							get_patch_exit_vm_instr(reinterpret_cast<uint8_t*>(pos_addr), &save_dis_info, mod_addr, sec, recurs, jcc);
							
						}
						mem += info_instr.info.length;
						jcc++;

						break;

					} 

					case ZYDIS_MNEMONIC_MOV:
					{
						if 
						(
							info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY &&
							info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
							info_instr.operands[NULL].mem.segment == ZYDIS_REGISTER_FS &&
							info_instr.operands[NULL].mem.base == ZYDIS_REGISTER_NONE &&
							info_instr.operands[NULL].mem.disp.has_displacement &&
							info_instr.operands[NULL].mem.disp.value == NULL &&
							info_instr.operands[1].reg.value == ZYDIS_REGISTER_ESP
						)
						{ 
							dis_exit_vm_instr->count_esp_seh++;
						}						
						mem += info_instr.info.length;
						break;
					}

					case ZYDIS_MNEMONIC_IN:
					{

						if
							(
								dis_exit_vm_instr->count_esp_seh &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && 
								info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EAX &&  
								info_instr.operands[1].reg.value == ZYDIS_REGISTER_DX
								)
						{

							dis_exit_vm_instr->count_in++;
						}
						mem += info_instr.info.length;
						break;
					}
					case ZYDIS_MNEMONIC_CMP:
					{
						if
							(
								dis_exit_vm_instr->count_esp_seh == 1 &&
								dis_exit_vm_instr->count_in == 1 &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && 
								info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EAX &&
								info_instr.operands[1].imm.value.u == NULL
								)
						{
							
							//cmp eax,0 -> cmp al,al
							//jbe	check_next
							//jmp	detect
							memset(mem, OPCODE_NOP, dis::get_len(reinterpret_cast<CHAR*>(mem)));
							memcpy(mem, instr_cmp_self, sizeof(instr_cmp_self));
							dis_exit_vm_instr->count_cmp++;
						}
						else if
						(
								dis_exit_vm_instr->count_esp_seh == 2 &&
								dis_exit_vm_instr->count_in == 2 &&
								dis_exit_vm_instr->count_cmp &&
								info_instr.operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								info_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								info_instr.operands[NULL].reg.value == ZYDIS_REGISTER_EBX &&
								info_instr.operands[1].imm.value.u ==  'VMXh'
						)
						{
							
							//cmp ebx,564D5868 -> cmp esp,NULL(never LOL)
							//jne vm_entry
							//jmp detect
							 
							memset(mem, OPCODE_NOP, dis::get_len(reinterpret_cast<CHAR*>(mem)));
							memcpy(mem, instr_impossible, sizeof(instr_impossible));
							return TRUE;
						}
						mem += info_instr.info.length;
						break;
					}
					default:
					{
						mem += info_instr.info.length;
						break;
					}

					}
				}
				else
				{
					return NULL;
				}
				if (!is_inside_sec(reinterpret_cast<CHAR*>(mem), mod_addr, sec) || jcc >= 5)
				{
					return FALSE;
				}


			}

			return FALSE;
		}


		NO_INLINE static auto scan_wrap_obf_imp
		(
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sec_themida
		) -> BOOLEAN
		{
			BOOLEAN is_patch = FALSE;
			uint32_t size_sec = NULL;
			CHAR* memory_sec = NULL;
  #ifndef _WIN64
			DIS_INFO_API_OBF32 dis_info = { NULL };
#else
			DIS_INFO_API_OBF64 dis_info = { NULL };
#endif // !_WIN64
			 
			if ((sec_themida->Characteristics & IMAGE_SCN_MEM_READ) && (sec_themida->Characteristics & IMAGE_SCN_MEM_WRITE) && (sec_themida->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			{
				memory_sec = static_cast<CHAR*>(mod_addr) + sec_themida->VirtualAddress;
				size_sec = sec_themida->SizeOfRawData ? sec_themida->SizeOfRawData : sec_themida->Misc.VirtualSize;

				size_sec -= PAGE_SIZE;

				for (size_t i = NULL; i < size_sec; i++)
				{
					if (is_obf_imp(reinterpret_cast<uint8_t*>(memory_sec) + i))
					{
						if (get_patch_exit_obf_imp(reinterpret_cast<uint8_t*>(memory_sec) + i, &dis_info, mod_addr, sec_themida, TRUE, NULL, NULL))
						{  
							is_patch = TRUE;
						}
						memset(&dis_info, NULL, sizeof(dis_info));
					}
				}
			} 
			return is_patch;
		}

		//Enable hook themida vector handler
		NO_INLINE static auto scan_imp_ret_loader
		(
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sec_themida
		) -> BOOLEAN
		{
			BOOLEAN is_patch = FALSE;
			uint32_t size_sec = NULL;
			CHAR* memory_sec = NULL;
  			DIS_LOADER_GET_API dis_info = { NULL }; 

			if ((sec_themida->Characteristics & IMAGE_SCN_MEM_READ) && (sec_themida->Characteristics & IMAGE_SCN_MEM_WRITE) && (sec_themida->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			{
				memory_sec = static_cast<CHAR*>(mod_addr) + sec_themida->VirtualAddress;
				size_sec = sec_themida->SizeOfRawData ? sec_themida->SizeOfRawData : sec_themida->Misc.VirtualSize;

				size_sec -= PAGE_SIZE;

				for (size_t i = NULL; i < size_sec; i++)
				{
					if (is_imp_loader(reinterpret_cast<uint8_t*>(memory_sec) + i))
					{
						if (get_patch_imp_loader(reinterpret_cast<uint8_t*>(memory_sec) + i, &dis_info, mod_addr, sec_themida, NULL, NULL))
						{ 
							return TRUE;
						}
						memset(&dis_info, NULL, sizeof(dis_info)); 
					}
				}
			} 

			return is_patch;
		}

		NO_INLINE static auto scan_exit_instr_vmware
		(
			PVOID mod_addr,
			PIMAGE_SECTION_HEADER sec_themida
		) -> BOOLEAN
		{
			BOOLEAN is_patch = FALSE;
			uint32_t size_sec = NULL;
			CHAR* memory_sec = NULL;
			DIS_EXIT_PORT_INSTR dis_info = { NULL };

			if ((sec_themida->Characteristics & IMAGE_SCN_MEM_READ) && (sec_themida->Characteristics & IMAGE_SCN_MEM_WRITE) && (sec_themida->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			{
				memory_sec = static_cast<CHAR*>(mod_addr) + sec_themida->VirtualAddress;
				size_sec = sec_themida->SizeOfRawData ? sec_themida->SizeOfRawData : sec_themida->Misc.VirtualSize;

				size_sec -= PAGE_SIZE;

				for (size_t i = NULL; i < size_sec; i++)
				{
					if (is_exit_instr(reinterpret_cast<uint8_t*>(memory_sec) + i))
					{
						if (get_patch_exit_vm_instr(reinterpret_cast<uint8_t*>(memory_sec) + i, &dis_info, mod_addr, sec_themida, NULL, NULL))
						{
							return TRUE;
 						}
						memset(&dis_info, NULL, sizeof(dis_info));
					}
				}
			}

			return is_patch;
		}

	public:

		static auto WINAPI query_value_exa 
		(
			HKEY    hKey,
			LPCSTR  lpValueName,
			LPDWORD lpReserved,
			LPDWORD lpType,
			LPBYTE  lpData,
			LPDWORD lpcbData
		) -> LSTATUS
		{ 
			LSTATUS res_api = NULL;

			res_api = reinterpret_cast<decltype(&RegQueryValueExA)>(anti_vm.orig_query_value_exa)(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
			if (res_api == ERROR_SUCCESS)
			{
				if (!stricmp(lpValueName, "DriverDesc") || 
					!stricmp(lpValueName, "SystemBiosVersion") ||
					!stricmp(lpValueName, "VideoBiosVersion")
				)
				{
					reg_remove_string(lpData, *lpcbData);
				}
			}
			return res_api;
		}
		static auto WINAPI reg_open_keyexa //kernelbase.dll
		(
			HKEY   hKey,
			LPCSTR lpSubKey,
			DWORD  ulOptions,
			REGSAM samDesired,
			PHKEY  phkResult

		)->LSTATUS
		{
			LSTATUS res_api = NULL;

			res_api = reinterpret_cast<decltype(&RegOpenKeyExA)>(anti_vm.orig_reg_open_keyexa)(hKey, lpSubKey, ulOptions, samDesired, phkResult);

			if (res_api == ERROR_SUCCESS &&  hKey == HKEY_LOCAL_MACHINE && !stricmp(lpSubKey,"HARDWARE\\ACPI\\DSDT\\VBOX__"))
			{
				if (phkResult)
				{
					RegCloseKey(*phkResult);
				}
				return ERROR_FILE_NOT_FOUND;
			}
			return res_api;
		}

		static auto WINAPI  get_mod_handlea
		(
			LPCSTR lpModuleName
		) -> HMODULE
		{
			PVOID ret_addr = NULL;
			HMODULE res_api = NULL;
			PVOID mod_addr = NULL;
			uint32_t id_ret_loader = NULL;
			uint32_t id_obf_imp = NULL;
			uint32_t id_exit_instr = NULL; 
			PIMAGE_SECTION_HEADER themida_sec = NULL;
			CONST CHAR* bad_mod_namep[] = { "cmdvrt32.dll","SbieDll.dll","dateinj01.dll" };

			ret_addr = _ReturnAddress();
			res_api = reinterpret_cast<decltype(&GetModuleHandleA)>(anti_vm.orig_getmodule_handlea)(lpModuleName);

			if (res_api)
			{
				for (size_t i = NULL; i < _countof(bad_mod_namep); i++)
				{
					if (!stricmp(lpModuleName, bad_mod_namep[i]))
					{
						return NULL;
					}
				}

				if (is_vm_entry_instr(reinterpret_cast<CHAR*>(ret_addr)))
				{
					if(is_set_hook_obf_imp(ret_addr, &mod_addr, &id_obf_imp) && get_sec_info(ret_addr, mod_addr, &themida_sec))
					{
						if (scan_wrap_obf_imp(mod_addr, themida_sec))
						{
							imp_obf_hook.imp[id_obf_imp].is_init_hook = TRUE;
						}
					} 
					//not else if...
					if (is_set_hook_loader_imp(ret_addr, &mod_addr, &id_ret_loader) && get_sec_info(ret_addr, mod_addr, &themida_sec))
					{
						if (scan_imp_ret_loader(mod_addr, themida_sec))
						{
							addr_ret_loader_api[id_ret_loader].is_init_hook = TRUE;
						}
					}
					if (is_set_hook_vmware_instr(ret_addr, &mod_addr, &id_exit_instr) && get_sec_info(ret_addr, mod_addr, &themida_sec))
					{
						if (scan_exit_instr_vmware(mod_addr, themida_sec))
						{
							anti_vm.exit_anti_vm[id_exit_instr].is_init = TRUE; 
						}
					}
				} 

			}
			return res_api;
		}
	

		static auto WINAPI  get_system_firmware_tab
		(
			DWORD FirmwareTableProviderSignature,
			DWORD FirmwareTableID,
			PVOID pFirmwareTableBuffer,
			DWORD BufferSize
		) -> UINT
		{ 
			UINT res_api = NULL;
			res_api = reinterpret_cast<decltype(&GetSystemFirmwareTable)>(anti_vm.orig_get_system_firmware_tab)(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);

			if (FirmwareTableProviderSignature == 'RSMB' && BufferSize && pFirmwareTableBuffer &&  BufferSize && res_api >= BufferSize)
			{
				remove_firmware_bad_string(pFirmwareTableBuffer, BufferSize);
			}
			return res_api;
		}
	};

	class anti_debug_util
	{
	private:
 		
		NO_INLINE static auto toupper
		(
			INT c
		) -> INT
		{
			if (c >= 'a' && c <= 'z')
				return c - 'a' + 'A';
			return c;
		}

		NO_INLINE static auto memcpy
		(
			PVOID dest,
			CONST VOID* src,
			uint64_t count
		) -> PVOID
		{
			char* char_dest = (char*)dest;
			char* char_src = (char*)src;
			if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
			{
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest++;
					char_src++;
					count--;
				}
			}
			else
			{
				char_dest = (char*)dest + count - 1;
				char_src = (char*)src + count - 1;
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest--;
					char_src--;
					count--;
				}
			}
			return dest;
		}
		
		NO_INLINE static auto  memicmp
		(
			CONST VOID* s1,
			CONST VOID* s2,
			unsigned __int64 n
		) -> INT
		{
			if (n != NULL)
			{
				const uint8_t* p1 = (uint8_t*)s1, * p2 = (uint8_t*)s2;
				do
				{
					if (toupper(*p1) != toupper(*p2))
						return (*p1 - *p2);
					p1++;
					p2++;
				} while (--n != NULL);
			}
			return NULL;
		}
		NO_INLINE static auto strstr( CHAR* _Str,  CHAR*   _SubStr) ->  CHAR*
		{
			 CHAR* bp = (CHAR*) _SubStr;
			 CHAR* back_pos;
			while (*_Str != 0 && _Str != 0 && _SubStr != 0)
			{
				back_pos = (CHAR*)_Str;
				while (tolower(*back_pos++) == tolower(*_SubStr++))
				{
					if (*_SubStr == NULL)
					{
						return (CHAR*)(back_pos - strlen(bp));
					}
				}
				++_Str;
				_SubStr = bp;
			}
			return NULL;
		}

		 NO_INLINE static auto remove_bad_name_window
		( 
			PVOID buffer,
			uint32_t buf_size
		) -> VOID
		{  
#ifndef _WIN64
			 CONST CHAR* bad_string[] = { "OllyDbg", "PhantOm","x32d","Shadow", "[CPU", "[*C."};
			 CONST INT bad_string_len[] = { sizeof("OllyDbg") - 1, sizeof("PhantOm") - 1,sizeof("x32d") - 1,sizeof("Shadow") - 1, sizeof("[CPU") - 1,sizeof("[*C.") - 1 };
			 CONST INT max_len_bad_str = sizeof("PhantOm") - 1;
#else		
			 CONST CHAR* bad_string[] = { "x64d" };
			 CONST INT bad_string_len[] = { sizeof("x64d") - 1};
			 CONST INT max_len_bad_str = sizeof("x64d") - 1;

#endif // !_WIN64

			 
			CONST CHAR* good_str = { "Meh" };

			for (size_t i = NULL; i < buf_size - max_len_bad_str; i++)
			{
				for (size_t j = NULL; j < _countof(bad_string); j++)
				{
					if (!memicmp(reinterpret_cast<CHAR*>(buffer) + i, bad_string[j], bad_string_len[j]))
					{
						memset(reinterpret_cast<CHAR*>(buffer) + i, NULL, bad_string_len[j]);
						memcpy(reinterpret_cast<CHAR*>(buffer) + i, "meh", sizeof("meh") - 1);
					}
				}
			}
		} 
	 
		 //https://github.com/x64dbg/ScyllaHide/blob/baa5c8e853ace2bee752631f27fdfe5b271d92f6/Scylla/Util.cpp#L160
		 NO_INLINE static auto wow64_read_mem
		 (
			 HANDLE hProcess,
			 PVOID64 address,
			 PVOID buffer,
			 ULONGLONG buffer_size,
			 PULONGLONG bytes_read
		 ) -> BOOLEAN
		 {
			 BOOLEAN is_read = FALSE;
			 SIZE_T bytes_read32 = NULL;
			 PVOID wow64_read_virt_mem = NULL;
#ifndef _WIN64
			 wow64_read_virt_mem = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64ReadVirtualMemory64");
			 if (wow64_read_virt_mem)
			 {
				 return NT_SUCCESS(reinterpret_cast<decltype(&NtWow64ReadVirtualMemory64)>(wow64_read_virt_mem)(hProcess, address, buffer, buffer_size, bytes_read));
			 }
			 else if ((((DWORD64)address + buffer_size) < (DWORD)(-1)) && (buffer_size <= (DWORD)(-1)))
			 {
				 is_read = ReadProcessMemory(hProcess, (PVOID)(ULONG)(ULONG64)address, buffer, (SIZE_T)buffer_size, &bytes_read32);
				 if (bytes_read)
					 *bytes_read = bytes_read32;
				 return is_read == TRUE;
			 }
#endif 
			 return FALSE;
		 }

		 //https://github.com/x64dbg/ScyllaHide/blob/baa5c8e853ace2bee752631f27fdfe5b271d92f6/Scylla/Util.cpp#L181
		 NO_INLINE static auto wow64_write_mem
		 (
			 HANDLE hProcess, 
			 PVOID64 address, 
			 LPCVOID buffer, 
			 ULONGLONG buffer_size, 
			 PULONGLONG bytes_written
		 ) -> BOOLEAN
		 {
			 BOOLEAN is_read = FALSE;
			 SIZE_T bytes_written32 = NULL;
			 PVOID wow64_write_virt_mem = NULL;
#ifndef _WIN64
			 wow64_write_virt_mem = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64WriteVirtualMemory64");
			 if (wow64_write_virt_mem)
			 {
				 return NT_SUCCESS(reinterpret_cast<decltype(&NtWow64WriteVirtualMemory64)>(wow64_write_virt_mem)(hProcess, address, buffer, buffer_size, bytes_written));
			 }
			 else if ((((DWORD64)address + buffer_size) < (DWORD)(-1)) && (buffer_size <= (DWORD)(-1)))
			 {
				 is_read = WriteProcessMemory(hProcess, (PVOID)(ULONG)(ULONG64)(address), buffer, (SIZE_T)buffer_size, &bytes_written32);
				 if (bytes_written)
					 *bytes_written = bytes_written32;
				 return is_read == TRUE;
			 }
#endif 
			 return FALSE;
		 }

		 //https://github.com/x64dbg/ScyllaHide/blob/baa5c8e853ace2bee752631f27fdfe5b271d92f6/Scylla/Peb.cpp#L47
		 NO_INLINE static auto fix_peb_wow64
		 (

		 )  -> VOID
		 {
			 bool success = FALSE; 
			 NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			 PVOID wow_proc_info = NULL;
			 PVOID peb_addr = NULL;	
			 HANDLE access = NULL;

			 wow_ponos::PEB64 peb64 = { NULL };

			 PROCESS_BASIC_INFORMATION64 pbi = { NULL };
 
			 access = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,FALSE, reinterpret_cast<DWORD>(NtCurrentProcessId()));
			 if (!access)
			 {
				 return;
			 }

			 wow_proc_info = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64QueryInformationProcess64");
			 if (wow_proc_info)
			 {
				 nt_status = reinterpret_cast<decltype(&Wow64QueryInformationProcess64)>(wow_proc_info)(access, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
			 } 
			 if (NT_SUCCESS(nt_status))
			 {
				 if (wow64_read_mem(access, (PVOID64)pbi.PebBaseAddress, &peb64, sizeof(peb64), NULL))
				 {
					 peb64.BeingDebugged = FALSE;
					 peb64.NtGlobalFlag &= ~(FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);
					 wow64_write_mem(access, (PVOID64)pbi.PebBaseAddress, &peb64, sizeof(peb64), NULL);

				 }
			 }

			 if (access)
			 {
				 CloseHandle(access);
			 }

			 return;
			  
		 }
	public: 

		NO_INLINE static auto WINAPI clean_peb
		(

		) -> VOID
		{ 
			BOOL is_wow64 = FALSE; 
 			PPEB peb = NULL; 			
			uint32_t cs_tatus = NULL;

#ifndef _WIN64
			peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
			peb->BeingDebugged = FALSE; //Themida don't check this
			peb->NtGlobalFlag &= ~(FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);//Themida don't check this
 			if (IsWow64Process(NtCurrentProcess, &is_wow64) && (is_wow64 == TRUE))
			{
				fix_peb_wow64();
			}

#else
			peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
			peb->BeingDebugged = FALSE; //Themida don't check this
			peb->NtGlobalFlag &= ~(FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);//only in x32
#endif
			//only in x32
			//https://github.com/x64dbg/ScyllaHide/blob/baa5c8e853ace2bee752631f27fdfe5b271d92f6/Scylla/PebHider.cpp#L110
			 
		}

		static auto WINAPI compare_stringa
		(
			LCID   Locale,
			DWORD  dwCmpFlags,
			PCNZCH lpString1,
			INT    cchCount1,
			PCNZCH lpString2,
			INT    cchCount2
		) -> INT
		{
			INT res_api = NULL;

			CONST CHAR* bad_string[] = {"ntice.sys","iceext.sys","Syser.sys","HanOlly.sys","extrem.sys","FRDTSC.SYS","fengyue.sys" };
			CONST INT bad_string_len[] = { sizeof("ntice.sys")-1,sizeof("iceext.sys") - 1,sizeof("Syser.sys") - 1,sizeof("HanOlly.sys") - 1,sizeof("extrem.sys") - 1,sizeof("FRDTSC.SYS") - 1,sizeof("fengyue.sys") - 1 };

			res_api = reinterpret_cast<decltype(&CompareStringA)>(anti_deb.orig_compare_stringa)(Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);

			if (res_api == CSTR_EQUAL && lpString1 != lpString2)
			{
				if (lpString1 && cchCount1)
				{
					for (size_t i = NULL; i < _countof(bad_string); i++)
					{
						if (!memicmp(lpString1, bad_string[i], bad_string_len[i]))
						{
							return CSTR_GREATER_THAN;
						}
					}
				}

				if (lpString2 && cchCount2)
				{
					for (size_t i = NULL; i < _countof(bad_string); i++)
					{
						if (!memicmp(lpString1, bad_string[i], bad_string_len[i]))
						{
							return CSTR_GREATER_THAN;
						}
					}
				}
			}
			return res_api;
		}

		static auto NTAPI query_proc
		(
			HANDLE               ProcessHandle,
			PROCESSINFOCLASS	 ProcessInformationClass,
			PVOID                ProcessInformation,
			ULONG                ProcessInformationLength,
			PULONG               ReturnLength
		) -> NTSTATUS
		{
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			if (ProcessInformationLength == sizeof(HANDLE) && (ProcessInformationClass == ProcessDebugPort || ProcessInformationClass == ProcessDebugObjectHandle))
			{
				if (ProcessHandle == NtCurrentProcess)
				{
					nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(anti_deb.orig_query_proc)(ProcessHandle, ProcessDebugPort, ProcessInformation, ProcessInformationLength, ReturnLength);
					if(NT_SUCCESS(nt_status))
					{
						*reinterpret_cast<PHANDLE>(ProcessInformation) = NULL;
						if (ReturnLength)
							*ReturnLength = sizeof(HANDLE);

						if (ProcessInformationClass == ProcessDebugObjectHandle)
						{
							nt_status =  STATUS_PORT_NOT_SET;
						} 
					}
					return nt_status;
				}
			}
			return reinterpret_cast<decltype(&NtQueryInformationProcess)>(anti_deb.orig_query_proc)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

		}

		static auto NTAPI set_thread
		(
			HANDLE ThreadHandle,
			THREADINFOCLASS ThreadInformationClass,
			PVOID ThreadInformation,
			ULONG ThreadInformationLength
		) -> NTSTATUS
		{
			if (ThreadInformationClass == ThreadHideFromDebugger && !ThreadInformationLength)
			{
				if (ThreadHandle == NtCurrentThread)
				{
					return STATUS_SUCCESS;
				}
			} 
			return  reinterpret_cast<decltype(&NtSetInformationThread)>(anti_deb.orig_set_thread)(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
		}

		static auto NTAPI get_context
		(
			HANDLE ThreadHandle, 
			PCONTEXT ThreadContext
		) -> NTSTATUS
		{
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

			nt_status = reinterpret_cast<decltype(&NtGetContextThread)>(anti_deb.orig_get_context)(ThreadHandle, ThreadContext);
			if (NT_SUCCESS(nt_status))
			{
				if (ThreadHandle == NtCurrentThread )
				{ 
					ThreadContext->Dr0 = NULL;
					ThreadContext->Dr1 = NULL;
					ThreadContext->Dr2 = NULL;
					ThreadContext->Dr3 = NULL;     

				}
			}
			return nt_status;

		}

		static auto WINAPI get_windows_texta
		(
			HWND  hWnd,
			LPSTR lpString,
			INT   nMaxCount
		) -> INT
		{
 			INT res_api = NULL;
			CHAR* addr_bad_string = NULL;

			res_api = reinterpret_cast<decltype(&GetWindowTextA)>(anti_deb.orig_windows_texta)(hWnd, lpString, nMaxCount);
			if (res_api)
			{ 
				remove_bad_name_window(lpString, nMaxCount); 
			}
			return res_api;
		}
	};

	class util_list_hook
	{

	private:

		NO_INLINE static auto wtolower(INT c) -> INT
		{
			if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
			if (c >= L'À' && c <= L'ß') return c - L'À' + L'à';
			if (c == L'¨') return L'¸';
			return c;
		}

		NO_INLINE static auto tolower
		(
			INT c
		) -> INT
		{
			if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
			return c;
		}

		NO_INLINE static auto stricmp
		(
			CONST CHAR* cs, 
			CONST CHAR* ct
		) -> INT
		{
			if (cs && ct)
			{
				while (tolower(*cs) == tolower(*ct))
				{
					if (*cs == 0 && *ct == 0) return 0;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return tolower(*cs) - tolower(*ct);
			}
			return -1;
		}

		NO_INLINE static auto wstricmp
		(
			CONST WCHAR* cs, 
			CONST WCHAR* ct
		) -> INT
		{
			if (cs && ct)
			{
				while (wtolower(*cs) == wtolower(*ct))
				{
					if (*cs == 0 && *ct == 0) return NULL;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return wtolower(*cs) - wtolower(*ct);
			}
			return -1;
		}

		NO_INLINE static auto wstrlen
		(
			CONST WCHAR* s
		) -> INT
		{
			INT cnt = NULL;
			if (!s)
				return NULL;
			for (; *s != NULL; ++s)
				++cnt;
			return cnt * sizeof(WCHAR);
		}

		NO_INLINE static auto memcpy
		(
			PVOID dest,
			CONST VOID* src,
			uint64_t count
		) -> PVOID
		{
			char* char_dest = (char*)dest;
			char* char_src = (char*)src;
			if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
			{
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest++;
					char_src++;
					count--;
				}
			}
			else
			{
				char_dest = (char*)dest + count - 1;
				char_src = (char*)src + count - 1;
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest--;
					char_src--;
					count--;
				}
			}
			return dest;
		}

		 

		NO_INLINE static auto memset
		(
			void* src,
			int val,
			unsigned __int64 count
		) -> PVOID
		{
			__stosb((unsigned char*)((unsigned long long)(volatile char*)src), val, count);
			return src;
		}

 

	public:
		 
		NO_INLINE static auto add_exit_instr_patch
		(
			WCHAR* mod_name
		) -> VOID
		{
			ANTI_VM_EXIT_INSTR_PATCH exit_patch = { NULL };

#ifndef _WIN64
			//Only in x32 can execute in eax,dx && in eax,dx 
			if (mod_name)
			{
				memcpy(exit_patch.mod_name, mod_name, wstrlen(mod_name));
			}
			exit_patch.mod_addr = GetModuleHandleW(mod_name); 
			anti_vm.exit_anti_vm.push_back(exit_patch);

#endif // !_WIN64

		}


		NO_INLINE static auto add_crc_run_list
		(
			WCHAR* mod_name
		) -> VOID
		{
			CRC_RUN_INFO crc_inf = { NULL };
			if (mod_name)
			{
				memcpy(crc_inf.name_mod, mod_name, wstrlen(mod_name));
			}
			crc_inf.protected_mod = GetModuleHandleW(mod_name);
			
			hooked_fun::crc_run.crc_inf.push_back(crc_inf);
		}


		NO_INLINE static auto add_crc_file_list
		(
			WCHAR* mod_name
		) -> VOID
		{
			MOD_CRC_FILE_INFO crc_file_prot = { NULL };
			if (mod_name)
			{
				memcpy(crc_file_prot.name_mod, mod_name, wstrlen(mod_name));
			}
			crc_file_prot.addr = GetModuleHandleW(mod_name);
			
			crc_file.mod_info.push_back(crc_file_prot);
		}

		NO_INLINE static auto add_hook_loader_imp
		( 
			WCHAR* mod_name 
		) -> VOID
		{
			LOADER_GET_API_RET user_load_api = { NULL }; 
			if (mod_name)
			{
				memcpy(user_load_api.name_mod, mod_name, wstrlen(mod_name));
			} 
			user_load_api.addr_mod = GetModuleHandleW(mod_name);
			addr_ret_loader_api.push_back(user_load_api);

			return;
		}

		NO_INLINE static auto add_hook_obf_imp
		(
			PVOID detour,
			WCHAR* mod_name,
			CONST WCHAR* api_mod_name,
			CONST CHAR* api_name

		) -> VOID
		{
			INFO_USER_API_HOOKED use_api_hooked = { NULL };
			MOD_USER_API_HOOKED api_info = { NULL };
			//Check in init mod
			for (size_t i = NULL; i < hooked_fun::imp_obf_hook.imp.size(); i++)
			{
				if (!wstricmp(mod_name, hooked_fun::imp_obf_hook.imp[i].user_name_mod))
				{
					for (size_t j = NULL; j < hooked_fun::imp_obf_hook.imp[i].api_info.size(); j++)
					{
						if (
							hooked_fun::imp_obf_hook.imp[i].api_info[j].detour == detour &&
							!wstricmp(api_mod_name, hooked_fun::imp_obf_hook.imp[i].api_info[j].name_mod) &&
							!stricmp(api_name, hooked_fun::imp_obf_hook.imp[i].api_info[j].name_api)
							)
						{
							//Exist
							return;
						}
					}

					use_api_hooked.user_mod_addr = GetModuleHandleW(mod_name);

					memcpy(use_api_hooked.user_name_mod, mod_name, wstrlen(mod_name));
					api_info.detour = detour;

					memcpy(api_info.name_mod, api_mod_name, wstrlen(api_mod_name));
					memcpy(api_info.name_api, api_name, wstrlen(api_mod_name));
					hooked_fun::imp_obf_hook.imp[i].api_info.push_back(api_info);
					return;

				}
			}

			//No exist module
			use_api_hooked.user_mod_addr = GetModuleHandleW(mod_name);
			memcpy(use_api_hooked.user_name_mod, mod_name, wstrlen(mod_name));
			api_info.detour = detour;

			memcpy(api_info.name_mod, api_mod_name, wstrlen(api_mod_name));
			memcpy(api_info.name_api, api_name, wstrlen(api_mod_name));
			use_api_hooked.api_info.push_back(api_info);
			hooked_fun::imp_obf_hook.imp.push_back(use_api_hooked);
			 
			return;

		}
	};
}

#endif // !HOOKED_FUN
