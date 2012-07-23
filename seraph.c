/**
 *
 * Seraph
 *
 * local samba scanner
 *
 *@author  Techi
 *@license GPL
 *
 */
 
#define ENCODING 852

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "netapi32.lib")

#ifndef INTERNET_CONNECTION_CONFIGURED
#define INTERNET_CONNECTION_CONFIGURED 0x40
#endif

#ifndef INTERNET_CONNECTION_OFFLINE
#define INTERNET_CONNECTION_OFFLINE 0x20
#endif

#ifndef INTERNET_RAS_INSTALLED
#define INTERNET_RAS_INSTALLED 0x10
#endif

#include <windows.h>
#include <mmsystem.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <shlobj.h>
#include <commctrl.h>
#include <wininet.h>

HOSTENT *hostent;
IN_ADDR addr;
char str[256];
int i, j;
int iState;
HANDLE hThread;
BOOL g_nbtscan = FALSE;

DWORD WINAPI WaitThreadProc(LPVOID lpParam)
{
	const int max = 10;
	static int pos = 0;
	static char direction = 1;
	int i;
	
	while(1)
	{
		putchar('\r');
		putchar('[');
		
		for(i = 0; i < max; i++)
			putchar(i == pos ? '*' : '-');
		
		putchar(']');
		
		if(direction)
			pos++;
		else
			pos--;

		if(pos == max - 1 || pos == 0)
			direction = !direction;
		
		Sleep(50);
	}

	return 0;	
}

LPSTR GetConnectionType(LPSTR lpBuffer)
{
	DWORD flags;
	
	strcpy(lpBuffer, "");
	if(InternetGetConnectedState(&flags, 0))
	{
		if((flags & INTERNET_CONNECTION_MODEM) || (flags & INTERNET_CONNECTION_MODEM_BUSY))
			strcat(lpBuffer, "MODEM ");

		if(flags & INTERNET_CONNECTION_LAN)
			strcat(lpBuffer, "LAN ");

		if(flags & INTERNET_CONNECTION_PROXY)
			strcat(lpBuffer, "PROXY ");

		if(flags & INTERNET_CONNECTION_CONFIGURED)
			strcat(lpBuffer, "CONFIGURED ");

		if(flags & INTERNET_RAS_INSTALLED)
			strcat(lpBuffer, "RAS ");

		if(flags & INTERNET_CONNECTION_OFFLINE)
			strcat(lpBuffer, "OFFLINE");

	}
	
	return lpBuffer;
}

BOOL EnumerateFunc(LPNETRESOURCE lpnr)
{ 
	DWORD dwResult, dwResultEnum;
	HANDLE hEnum;
	DWORD cbBuffer = 16384;      // 16K is a good size
	DWORD cEntries = -1;         // enumerate all possible entries
	LPNETRESOURCE lpnrLocal;     // pointer to enumerated structures
	DWORD i;
	CHAR systemBuffer[MAX_PATH];
	
	//
	// Call the WNetOpenEnum function to begin the enumeration.
	//
	
	ResumeThread(hThread);
	
	dwResult = WNetOpenEnum(RESOURCE_GLOBALNET, // all connected resources
                            RESOURCETYPE_ANY,   // all resources
                            0,        // enumerate all resources
                            lpnr,     // NULL first time the function is called
                            &hEnum);  // handle to the resource

	if (dwResult != NO_ERROR)
	{  
		//
		// Process errors with an application-defined error handler.
		//
		//   NetErrorHandler(hwnd, dwResult, (LPSTR)"WNetOpenEnum");
		return FALSE;
	}
	//
	// Call the GlobalAlloc function to allocate resources.
	//
	lpnrLocal = (LPNETRESOURCE) GlobalAlloc(GPTR, cbBuffer);
	if (lpnrLocal == NULL) 
		return FALSE;
  
	do
	{
		// Initialize the buffer.
		ZeroMemory(lpnrLocal, cbBuffer);
		//
		// Call the WNetEnumResource function to continue
		//  the enumeration.
		//
		dwResultEnum = WNetEnumResource(hEnum,      // resource handle
        	                            &cEntries,  // defined locally as -1
            	                        lpnrLocal,  // LPNETRESOURCE
                	                    &cbBuffer); // buffer size
		//
    	// If the call succeeds, loop through the structures.
    	//
		if (dwResultEnum == NO_ERROR)
		{
			for(i = 0; i < cEntries; i++)
			{
				// Call an application-defined function to
				//  display the contents of the NETRESOURCE structures.
				//
				if(lpnrLocal[i].dwDisplayType == RESOURCEDISPLAYTYPE_SERVER && lpnrLocal[i].lpRemoteName != NULL)
				{
					for(j = 0; j < (int)strlen(lpnrLocal[i].lpRemoteName); j++)
						str[j] = lpnrLocal[i].lpRemoteName[j + 2];

					hostent = gethostbyname(str);
					if(hostent)
					{
						addr.S_un.S_un_b.s_b1 = hostent->h_addr[0];
						addr.S_un.S_un_b.s_b2 = hostent->h_addr[1];
						addr.S_un.S_un_b.s_b3 = hostent->h_addr[2];
						addr.S_un.S_un_b.s_b4 = hostent->h_addr[3];
					}
			  
					SuspendThread(hThread);
					putchar('\r');
              
					CharToOem(str, str);
              
					printf("\\%s %s ", str, inet_ntoa(addr));
					if(lpnrLocal[i].lpComment)
					{
						CharToOem(lpnrLocal[i].lpComment, lpnrLocal[i].lpComment);
						printf("[%s]", lpnrLocal[i].lpComment);
					}
				  
					printf("             ");

					putchar('\n');
					if(g_nbtscan)
					{
						sprintf(systemBuffer, "nbtscan -f %s", inet_ntoa(addr));
						system(systemBuffer);
					}

					ResumeThread(hThread);
				}
				else
				{
					SuspendThread(hThread);
					putchar('\r');
					CharToOem(lpnrLocal[i].lpRemoteName, lpnrLocal[i].lpRemoteName);
					printf("%s %s ", lpnrLocal[i].lpRemoteName, "");
					if(lpnrLocal[i].lpComment)
						if(strlen(lpnrLocal[i].lpComment))
						{
							CharToOem(lpnrLocal[i].lpComment, lpnrLocal[i].lpComment);
							printf("[%s] %s", lpnrLocal[i].lpComment);
						}
					
					printf("                  ");

					putchar('\n');
					ResumeThread(hThread);
				}

				// If the NETRESOURCE structure represents a container resource, 
				//  call the EnumerateFunc function recursively.

				if(RESOURCEUSAGE_CONTAINER == (lpnrLocal[i].dwUsage & RESOURCEUSAGE_CONTAINER))
                {
					if(!EnumerateFunc(&lpnrLocal[i]))
					{
						SuspendThread(hThread);
						putchar('\r');
						puts("*** ENUMERATION FAILED ***");
						ResumeThread(hThread);
					}
				}
			}
		}

		else if (dwResultEnum != ERROR_NO_MORE_ITEMS)
		{
			break;
		}
	}
 	while(dwResultEnum != ERROR_NO_MORE_ITEMS);
 	
	GlobalFree((HGLOBAL)lpnrLocal);
 	
	dwResult = WNetCloseEnum(hEnum);
  
	if(dwResult != NO_ERROR)
	{
		return FALSE;
	}
	
	SuspendThread(hThread);
	putchar('\r');
	
	return TRUE;
}

int main(int argc, char *argv[])
{
	DWORD size = 0;
	char buffer[255] = {0};
	char user[255] = {0};
	char computer[255] = {0}; 
	char connectionBuffer[255] = {0};
	WSADATA wsa;
	OSVERSIONINFO osvi;
	NCB ncb, ncb_temp;
	LANA_ENUM le;
	DWORD dwThreadId;
	
	if (GetConsoleOutputCP() != ENCODING) {
  		SetConsoleOutputCP(ENCODING);
	};   
	
	if(argc == 2)
	{
		//if(
	}

	printf("%c%c%c Seraph %c%c%c\n", 219, 178, 177, 177, 178, 219);
	puts("Local samba network scanner by Techi\n");
	printf("Initalizing Winsock...");

	WSAStartup(MAKEWORD(1,1), &wsa);

	printf("\rVersion:         %s  %d.%d initialized \n", wsa.szDescription, LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));
	printf("Status:          %s\n", wsa.szSystemStatus);

	ZeroMemory(&osvi, sizeof(osvi));
	osvi.dwOSVersionInfoSize = sizeof(osvi);
	if(GetVersionEx(&osvi))
		printf("System:          Windows %s %d.%d.%d %s\n", osvi.dwPlatformId == VER_PLATFORM_WIN32_NT ? "NT" : "9x", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber, osvi.szCSDVersion); 
	

	size = 255;
	if(GetUserName(user, &size))
		printf("Current user:    %s\n", user);
	size = 255;
	if(GetComputerName(computer, &size))
		printf("Computer name:   %s\n", computer);
	

	printf("Connection:      %s\n", GetConnectionType(connectionBuffer));
	
	hThread = CreateThread(NULL, 0, WaitThreadProc, NULL, CREATE_SUSPENDED, &dwThreadId);
	
	puts("\nScanning local network in progress... [this may take few minutes]");
	puts("__________________________________________");
	puts("");
	EnumerateFunc(NULL);
	puts("__________________________________________");
	puts("");

	puts("Scan complete");
//	puts("\nNetBIOS");

	ZeroMemory(&ncb, sizeof(ncb));
	ncb.ncb_command = NCBENUM;
	ncb.ncb_buffer = (PBYTE) &le;
	ncb.ncb_length = sizeof(le);

//	iState = Netbios(&ncb);


	system("pause");

	WSACleanup();

	return 0;
}
