#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <array>

namespace memory {
	DWORD get_process_id(const char* name) noexcept {
		PROCESSENTRY32 pe{};
		pe.dwSize = sizeof(PROCESSENTRY32);

		const HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0U);

		if (!ss)
		{
			return DWORD{};
		}

		DWORD pid{};

		do {
			if (!_stricmp(name, pe.szExeFile)) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(ss, &pe));

		CloseHandle(ss);

		return pid;
	}

	DWORD get_module_address(const DWORD pid, const char* name) {
		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);

		const HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

		if (!ss) return DWORD{};

		DWORD address{};

		do {
			if (!_stricmp(name, me.szModule)) {
				address = reinterpret_cast<DWORD>(me.modBaseAddr);
				break;
			}
		} while (Module32Next(ss, &me));

		CloseHandle(ss);

		return address;
	}

	// stolen from burgerindividual
	template <size_t LEN>
	uintptr_t FastPatternScan(HANDLE handle, uintptr_t module, const std::array<uint8_t, LEN> pattern)
	{
		IMAGE_DOS_HEADER dosHeader;
		ReadProcessMemory(handle, (LPCVOID) module, reinterpret_cast<LPVOID>(&dosHeader), sizeof(IMAGE_DOS_HEADER), NULL);

		IMAGE_NT_HEADERS ntHeaders;
		ReadProcessMemory(handle, (LPCVOID) (module + dosHeader.e_lfanew), reinterpret_cast<LPVOID>(&ntHeaders), sizeof(IMAGE_NT_HEADERS), NULL);

		auto sizeOfModuleCode = ntHeaders.OptionalHeader.SizeOfCode;
		auto moduleCodeEnd = module + sizeOfModuleCode - LEN;

		for (auto curModPtr = module + ntHeaders.OptionalHeader.BaseOfCode; curModPtr < moduleCodeEnd; curModPtr++) {
			auto moduleSection = reinterpret_cast<const std::array<uint8_t, LEN>*>(curModPtr);
			std::array<uint8_t, LEN> buffer;
			
			ReadProcessMemory(handle, (LPCVOID) curModPtr, &buffer, LEN, NULL);

			if (std::equal(buffer.begin(), buffer.end(), pattern.begin())) {
				return curModPtr;
			}
		}

		return NULL;
	}


	/*std::uint8_t* PatternScan(void* module, const char* signature)
	{
		static auto pattern_to_byte = [](const char* pattern) {
			auto bytes = std::vector<int>{};
			auto start = const_cast<char*>(pattern);
			auto end = const_cast<char*>(pattern) + strlen(pattern);

			for (auto current = start; current < end; ++current) {
				if (*current == '?') {
					++current;
					if (*current == '?')
						++current;
					bytes.push_back(-1);
				}
				else {
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
		};

		auto dosHeader = (PIMAGE_DOS_HEADER)module;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

		auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
		auto patternBytes = pattern_to_byte(signature);
		auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

		auto s = patternBytes.size();
		auto d = patternBytes.data();

		for (auto i = 0ul; i < sizeOfImage - s; ++i) {
			bool found = true;
			for (auto j = 0ul; j < s; ++j) {
				if (scanBytes[i + j] != d[j] && d[j] != -1) {
					found = false;
					break;
				}
			}
			if (found) {
				return &scanBytes[i];
			}
		}
		return nullptr;
	}*/

	template <class T>
	T read(const HANDLE process, const uintptr_t address) noexcept {
		T value{};
		ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), nullptr);
		return value;
	}

	template <class T>
	void write(const HANDLE process, const uintptr_t address, const T& value) noexcept {
		WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), &value, sizeof(T), nullptr);
	}
}