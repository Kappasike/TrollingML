#include "memory.hpp"
#include <iostream>
//#include <cstdio>
#include <d3d11.h>
#include <imgui/imgui.h>
#include <imgui/imgui_impl_dx11.h>
#include <imgui/imgui_impl_win32.h>
#include <format>
#include <array>

uint32_t windowIndex = 0;

HWND mlWindow;

uintptr_t GetModuleBaseAddress(DWORD dwProcID, const char* szModuleName)
{
	uintptr_t ModuleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcID);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 ModuleEntry32;
		ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &ModuleEntry32))
		{
			do
			{
				if (strcmp(ModuleEntry32.szModule, szModuleName) == 0)
				{
					ModuleBaseAddress = (uintptr_t)ModuleEntry32.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnapshot, &ModuleEntry32));
		}
		CloseHandle(hSnapshot);
	}
	return ModuleBaseAddress;
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	DWORD targetPID = (DWORD)lParam;
	DWORD windowPid = 0;

	GetWindowThreadProcessId(hWnd, &windowPid);

	if (windowPid == targetPID)
	{
		char windowName[256];
		GetWindowText(hWnd, windowName, sizeof(windowName));

		std::cout << windowName << " index is: "<< windowIndex << std::endl;

		//if (windowIndex == 11) {
		//	mlWindow = hWnd;
		//	return FALSE;
		//}
		windowIndex++;
		// C:\Users\kappa\Documents\College\ENGR 1181\Matlab\demo1.m
		// MATLAB R2023b - academic use
		if (strcmp(windowName, "Editor - C:\\Users\\kappa\\Documents\\College\\ENGR 1181\\Matlab\\demo1.m") == 0)
		{
			mlWindow = hWnd;
			return FALSE;
		}
	}

	return TRUE; // keep enumerating
}

// entry
int main()
{
	DWORD pid = memory::get_process_id("MATLAB.exe");
	if (!pid) {
		do {
			pid = memory::get_process_id("MATLAB.exe");
			Sleep(200UL);
		} while (!pid);
	}

	std::cout << "MATLAB Process Id: " << pid << std::endl;

	EnumWindows(EnumWindowsProc, pid);

	//PROCESSENTRY32 pe{};
	//pe.dwSize = sizeof(PROCESSENTRY32);

	//const HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0U);

	//do {
	//	if (!_stricmp("MATLABWebUI.exe", pe.szExeFile)) {
	//		auto pid = pe.th32ProcessID;
	//		std::cout << "MATLAB Web UI Process Id: " << pid << std::endl;
	//		EnumWindows(EnumWindowsProc, pid);
	//	}
	//} while (Process32Next(ss, &pe));

	//CloseHandle(ss);

	if (!mlWindow) return 0;

	std::cout << "Window Handle Found: " << mlWindow << std::endl;

	const HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (!handle) return 0;
	
	uintptr_t moduleBase = GetModuleBaseAddress(pid, "jmi.dll");

	if (!moduleBase) return 0;

	std::cout << "Module Found at: " << "0x" << std::hex << moduleBase << std::endl;

	// public: static class JreInstallation* JreInstallation::m_pInstance
	uintptr_t m_pInstance = moduleBase + 0x1D0E88;

	uintptr_t createWindowAddr = moduleBase + 0x1000 + 0x76E70;

	uintptr_t ptrAddr1;
	ReadProcessMemory(handle, (LPVOID)m_pInstance, &ptrAddr1, sizeof(ptrAddr1), NULL);
	ptrAddr1 += 0x78;

	uintptr_t ptrAddr2;
	ReadProcessMemory(handle, (LPVOID)ptrAddr1, &ptrAddr2, sizeof(ptrAddr1), NULL);
	ptrAddr2 += 0x30;

	uintptr_t ptrAddr3;
	ReadProcessMemory(handle, (LPVOID)ptrAddr2, &ptrAddr3, sizeof(ptrAddr1), NULL);
	ptrAddr3 += 0x30;

	uintptr_t ptrAddr4;
	ReadProcessMemory(handle, (LPVOID)ptrAddr3, &ptrAddr4, sizeof(ptrAddr1), NULL);
	ptrAddr4 += 0x18;

	uintptr_t ptrAddr5;
	ReadProcessMemory(handle, (LPVOID)ptrAddr4, &ptrAddr5, sizeof(ptrAddr1), NULL);
	ptrAddr5 += 0x0;

	uintptr_t ptrAddr6;
	ReadProcessMemory(handle, (LPVOID)ptrAddr5, &ptrAddr6, sizeof(ptrAddr1), NULL);
	ptrAddr6 += 0x40;

	uintptr_t ptrAddr7;
	ReadProcessMemory(handle, (LPVOID)ptrAddr6, &ptrAddr7, sizeof(ptrAddr1), NULL);
	ptrAddr7 += 0x0;

	//finally read the double value from the memory holy shit
	double answer;
	ReadProcessMemory(handle, (LPVOID)ptrAddr7, &answer, sizeof(answer), NULL);

	std::cout << "Answer is address: 0x" << std::hex << ptrAddr7 << std::endl;
	std::cout << "Answer is: " << answer << std::endl;

	// tryna get create window

	/*const std::array<uint8_t, 35> pattern = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x56, 0x48, 0x83, 0xEC, 0x20,
		0x48, 0x8B, 0xF1, 0x33, 0xDB, 0xFF, 0x15, 0xAB, 0x12, 0x0C, 0x00, 0x84, 0xC0, 0x74, 0x60,
		0x48, 0x8D, 0x0D, 0x30, 0x76, 0x0C, 0x00
	};*/

	const std::array<uint8_t, 3> pattern = { 0x48, 0x8B, 0xC3 };

	// Scan the local player (we will need to offset by 2 and dereference)
	uintptr_t createWindowFunc = memory::FastPatternScan(handle, moduleBase, pattern); // We are scanning in the client module
	//uintptr_t createWindowFuncAddr = reinterpret_cast<uintptr_t>(memory::PatternScan((void*)moduleBase, pattern));

	std::cout << "Create Window function is at: 0x" << std::hex << createWindowAddr << std::endl;

	std::cout << "Current bytescan: 0x" << std::hex << createWindowFunc;

	//return 0;
	// we're gangsta at this point

	DXGI_SWAP_CHAIN_DESC sd{};
	sd.BufferDesc.RefreshRate.Numerator = 240U;
	sd.BufferDesc.RefreshRate.Denominator = 1U;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.SampleDesc.Count = 1U;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.BufferCount = 2U;
	sd.OutputWindow = mlWindow;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

	constexpr D3D_FEATURE_LEVEL levels[2]{
		D3D_FEATURE_LEVEL_11_0,
		D3D_FEATURE_LEVEL_10_0
	};

	ID3D11Device* device{ nullptr };
	ID3D11DeviceContext* device_context{ nullptr };
	IDXGISwapChain* swap_chain{ nullptr };
	ID3D11RenderTargetView* render_target_view{ nullptr };
	D3D_FEATURE_LEVEL level{};

	D3D11CreateDeviceAndSwapChain(
		nullptr,
		D3D_DRIVER_TYPE_HARDWARE,
		nullptr,
		0U,
		levels,
		2U,
		D3D11_SDK_VERSION,
		&sd,
		&swap_chain,
		&device,
		&level,
		&device_context
	);

	ID3D11Texture2D* back_buffer{ nullptr };
	swap_chain->GetBuffer(0U, IID_PPV_ARGS(&back_buffer));

	if (back_buffer)
	{
		device->CreateRenderTargetView(back_buffer, nullptr, &render_target_view);
		back_buffer->Release();
	}
	else {
		return 1;
	}
	D3D11_BLEND_DESC blendDesc;
	ZeroMemory(&blendDesc, sizeof(blendDesc));

	blendDesc.RenderTarget[0].BlendEnable = TRUE;
	blendDesc.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
	blendDesc.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
	blendDesc.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
	blendDesc.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
	blendDesc.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ZERO;
	blendDesc.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
	blendDesc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;

	ID3D11BlendState* blendState = nullptr;
	device->CreateBlendState(&blendDesc, &blendState);
	device_context->OMSetBlendState(blendState, nullptr, 0);

	ImGui::CreateContext();
	ImGui::StyleColorsDark();

	ImGui_ImplWin32_Init(mlWindow);
	ImGui_ImplDX11_Init(device, device_context);

	bool running = true;
	while (running)
	{
		MSG message;
		while (PeekMessage(&message, nullptr, 0U, 0U, PM_REMOVE))
		{
			TranslateMessage(&message);
			DispatchMessage(&message);

			if (message.message == WM_QUIT)
			{
				running = 0;
			}
		}
		if (!running)
		{
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();
		
		
		ImGui::SetNextWindowSize(ImVec2(600, 600));
		if (ImGui::Begin("Hi", 0, ImGuiWindowFlags_NoResize))
		{
			ImGui::Button("Press me");
			ImGui::End();
		}
		ImGui::Render();

		constexpr float color[4]{ 0.f,0.f,0.f,0.f };
		device_context->OMSetRenderTargets(1U, &render_target_view, nullptr);
		device_context->ClearRenderTargetView(render_target_view, color);

		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		swap_chain->Present(0U, 0U); // render with no v sync
	}

	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();

	ImGui::DestroyContext();

	if (swap_chain) swap_chain->Release();

	if (device_context) device_context->Release();

	if (device) device->Release();

	if (render_target_view) render_target_view->Release();

	return 0;
}