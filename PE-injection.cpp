#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include<stdio.h>



/**

* Normal starting point of any program in windows. It is declared in runtime
library and will call
main() or wmain() function

*/

extern "C" void mainCRTStartup();

/**

* Injected program entry point after Runtime library is initialized

* Can call any runtime and system routines.

*/

DWORD main()

{

	MessageBoxA(NULL, "Close this window too stop hooks.", "Testing", MB_OK);

	return 0;

}

/**

* Thread which will be called in remote process after injection

*/

DWORD WINAPI entryThread(LPVOID param)

{

	//MessageBox(NULL, "Injection success. Now initializing runtime library.", NULL, 0);


	printf("Injection success\n");

	/* Mandatory sleep so injector knows thread was successfully injected (injector
	is waiting 100ms)*/
	Sleep(500);

	main();
	return 0;

}

BOOL patchRelocationTable(LPVOID module, LPVOID NewBase, PBYTE CodeBuffer)

{

	DWORD_PTR delta = NULL;
	DWORD_PTR olddelta = NULL;
	DWORD   i = 0;

	PIMAGE_DATA_DIRECTORY datadir;

	/* Get module PE headers */

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((LPBYTE)module +
		((PIMAGE_DOS_HEADER)module)->e_lfanew);

	/* delta is offset of allocated memory in target process */

	delta = (DWORD_PTR)((LPBYTE)NewBase - headers->OptionalHeader.ImageBase);

	/* olddelta is offset of image in current process */

	olddelta = (DWORD_PTR)((LPBYTE)module - headers->OptionalHeader.ImageBase);

	/* Get data of .reloc section */

	datadir = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (datadir->Size > 0 && datadir->VirtualAddress > 0)

	{

		/* Point to first relocation block copied in temporary buffer */

		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(CodeBuffer +
			datadir->VirtualAddress);

		/* Browse all relocation blocks */
		while (reloc->VirtualAddress != 0)

		{

			/* We check if the current block contains relocation descriptors, if not we
			skip to the
			next block */

			if (reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))

			{


				sizeof(WORD);

				/* We count the number of relocation descriptors */

				DWORD relocDescNb = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

				/* relocDescList is a pointer to first relocation descriptor */

				LPWORD relocDescList = (LPWORD)((LPBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

				/* For each descriptor */

				for (i = 0; i < relocDescNb; i++)

				{


					if (relocDescList[i] > 0)
					{
						DWORD_PTR* p = (DWORD_PTR*)(CodeBuffer + (reloc->VirtualAddress + (0x0FFF & (relocDescList[i]))));
						/* Change the offset to adapt to injected module base address */
						*p -= olddelta;
						*p += delta;

					}


				}



			}
			/* Set reloc pointer to the next relocation block */

			reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);

			
		}
		return TRUE;
	}
	else
		return FALSE;

}


/**

* Inject a PE module in the target process memory

* @param targetProcess Handle to target process

* @param module PE we want to inject

* @return Handle to injected module in target process

*/

HMODULE injectModule(HANDLE targetProcess, LPVOID module)

{

	/* Get module PE headers */

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((LPBYTE)module +
		((PIMAGE_DOS_HEADER)module)->e_lfanew);

	/* Get the size of the code we want to inject */

	DWORD moduleSize = headers->OptionalHeader.SizeOfImage;
	LPVOID distantModuleMemorySpace = NULL;

	LPBYTE tmpBuffer = NULL;
	BOOL ok = FALSE;

	if (headers->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	/* Check if calculated size really corresponds to module size */
	if (IsBadReadPtr(module, moduleSize))
		return NULL;

	/* Allocate memory in the target process to contain the injected module image */
	printf(" [-] Allocate memory in remote process\n");

	distantModuleMemorySpace = VirtualAllocEx(targetProcess, NULL, moduleSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (distantModuleMemorySpace != NULL)

	{

		/* Now we need to modify the current module before we inject it */

		/* Allocate some space to process the current PE image in an temporary buffer */
		printf("   [-] Allocate memory in current process\n");

		tmpBuffer = (LPBYTE)VirtualAlloc(NULL, moduleSize, MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);

		if (tmpBuffer != NULL)

		{

			printf("   [-] Duplicate module memory in current process\n");
			RtlCopyMemory(tmpBuffer, module, moduleSize);

			printf("   [-] Patch relocation table in copied module\n");

			if (patchRelocationTable(module, distantModuleMemorySpace, tmpBuffer))

			{

				/* Write processed module image in target process memory */
				printf("   [-] Copy modified module in remote process\n");

				ok = WriteProcessMemory(targetProcess, distantModuleMemorySpace, tmpBuffer,
					moduleSize, NULL);

				VirtualFree(tmpBuffer, 0, MEM_RELEASE);

			}
		}

		if (!ok)

		{

			VirtualFreeEx(targetProcess, distantModuleMemorySpace, 0, MEM_RELEASE);
			distantModuleMemorySpace = NULL;

		}

	}

	/* Return base address of copied image in target process */
	return (HMODULE)distantModuleMemorySpace;

}

/**

* Inject and start current module in the target process

* @param pid target process ID

* @param start callRoutine Function we want to call in distant process

*/

BOOL injectThenCreateRemoteThread(DWORD pid, LPTHREAD_START_ROUTINE
	callRoutine)

{

	HANDLE proc, thread;

	HMODULE module, injectedModule;
	BOOL result = FALSE;


	/* Open distant process. This will fail if UAC activated and proces running
	with higher integrity
	control level */

	printf(" [+] Open remote process with PID %d\n", pid);
	proc = OpenProcess(PROCESS_CREATE_THREAD |

		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ,

		FALSE,

		pid);

	if (proc != NULL)

	{

		/* Get image of current process modules memory*/
		module = GetModuleHandle(NULL);

		/* Insert module image in target process*/
		printf(" [+] Injecting module...\n");
		injectedModule = (HMODULE)injectModule(proc, module);

		/* injectedModule is the base address of the injected module in the target
		process */
		if (injectedModule != NULL)

		{

			/* Calculate the address of routine we want to call in the target process */

			/* The new address is:

			Start address of copied image in target process + Offset of routine in copied
			image */
			LPTHREAD_START_ROUTINE remoteRoutine =
				(LPTHREAD_START_ROUTINE)((LPBYTE)injectedModule +

					(DWORD_PTR)((LPBYTE)callRoutine - (LPBYTE)module));


			thread = CreateRemoteThread(proc, NULL, 0, remoteRoutine, NULL, 0, NULL);
			if (thread != NULL)

			{

				// Wait and check if thread was not killed immediately by some protection
				Sleep(300);

				DWORD exitCode = 0;
				GetExitCodeThread(thread, &exitCode);
				if (exitCode == STILL_ACTIVE)

					result = TRUE;


				else

				{

				}

				printf("   [!] Remote thread was killed shortly after creation :(\n");
				result = FALSE;

				CloseHandle(thread);

			}

			else

			{

				/* If failed, release memory */

				printf("   [!] Remote thread creation failed\n");
				VirtualFreeEx(proc, module, 0, MEM_RELEASE);

			}

		}

		CloseHandle(proc);

	}

	return result;

}

/**

* Inject and start current module in the target process

* @param pid Target process ID

* @param callRoutine callRoutine Function we want to call in distant process

* @param remoteExecMethod method used to trigger remote execution

*/

BOOL peInjection(DWORD targetPid, LPTHREAD_START_ROUTINE
	callRoutine)
{

	BOOL is32bit = FALSE;


	HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
	if (proc != NULL)

	{

		IsWow64Process(proc, &is32bit);

#ifdef _WIN64

		if (is32bit == TRUE)

		{
			printf("   [!] 32 bit process, injection not possible!\n");
			return FALSE;

		}
#else
		if (is32bit == FALSE)

		{
			printf("   [!] 64 bit process, injection not possible!\n");
			return FALSE;

		}

#endif

		CloseHandle(proc);


	}

	else

	{
		printf("   [!] Could not open process.\n");
		return FALSE;

	}


	return injectThenCreateRemoteThread(targetPid, callRoutine);

}

/**

* Module entry point when started by system.

* Do not use any runtime library function before injection is complete.

*/

void entryPoint()

{

	DWORD targetPid;
	PROCESS_INFORMATION targetProcess;
	//char* target = "notepad.exe";

	//change the pid here
	targetPid = 7548;

	if (peInjection(targetPid, entryThread))
		printf(" [+] Success :) \n");

	else

		printf(" [+] Failure :( \n");

	Sleep(1000);

	printf(" [+] ^('O')^ < Bye! \n\n");

}