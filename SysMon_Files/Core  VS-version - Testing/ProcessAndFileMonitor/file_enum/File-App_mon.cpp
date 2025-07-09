// written and tested by havox

// code to find the File behaviour monitoring  (Creation, deletion,modification and renaming)

#include "File-App_mon.h"
#include "HeaderAnalysis.h"
#include <stdbool.h>

using json = nlohmann::json;

std::unordered_set<std::string> loggedFiles;

void logToFile(const std::string& event, const std::string& filePath, DWORD ProcessID,const std::string& processname) {

	if (loggedFiles.find(filePath) != loggedFiles.end()) {
		return;
	}

	json logEntry;
	logEntry["event"] = event;
	logEntry["filePath"] = filePath;
	logEntry["timestamp"] = GetTickCount64();
	logEntry["Process ID - Involved"] = ProcessID;
	logEntry["Process Name"] = processname;

	// Log the entry
	std::ofstream logFile("file_monitor.json", std::ios::app);
	logFile << logEntry.dump(4) << std::endl;
	logFile.close();

	loggedFiles.insert(filePath);
}

// export file info from Process ID
std::wstring getProcessName(DWORD ProcessID) {

	TCHAR Process_name[MAX_PATH] = TEXT("");
	std::wstring Processname = Process_name;
	//char Process_name[MAX_PATH] = "undefined";
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessID);
	if (hProcess) {
		HMODULE hMod;
		DWORD cNeeded;
		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cNeeded)) {
			GetModuleBaseName(hProcess, hMod, Process_name, MAX_PATH);
		}
		CloseHandle(hProcess);
	}
	return Processname;
}

// find Process ID from the fileworking on in Process
DWORD findProcessFromFile(const std::string& filePath) {

	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	
	// take the first process for the snapshot and matche's with the file path if true rretunr the process id and info
	if (Process32First(hsnapshot, &pe)) {
		do {
			HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
			if (hprocess) {
				TCHAR processfilepath[MAX_PATH] = TEXT("undefined");
				std::wstring filepathcompare = processfilepath;
				if (GetModuleFileNameEx(hprocess, NULL, processfilepath, MAX_PATH)) {
					if (filepathcompare == processfilepath) {
						CloseHandle(hprocess);
						CloseHandle(hsnapshot);
						return pe.th32ProcessID;
					}
				}
				CloseHandle(hprocess);
			}
		} while (Process32Next(hsnapshot, &pe));
	}
	CloseHandle(hsnapshot);
}

void monitorDirectory(const std::string& directory) {

	std::wstring wDirectory(directory.begin(), directory.end());

	HANDLE hDir = CreateFile(
		wDirectory.c_str(),
		FILE_LIST_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		NULL);

	if (hDir == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open directory: " << directory << std::endl;
		return;
	}

	char buffer[1024];
	DWORD bytesReturned;
	FILE_NOTIFY_INFORMATION* notification;

	while (true) {
		if (ReadDirectoryChangesW(
			hDir, buffer, sizeof(buffer), TRUE,
			FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE |
			FILE_NOTIFY_CHANGE_LAST_WRITE,
			&bytesReturned, NULL, NULL)) {
			notification = (FILE_NOTIFY_INFORMATION*)buffer;
			do {
				std::wstring fileName(notification->FileName,notification->FileNameLength / sizeof(WCHAR));
				std::string filePath(fileName.begin(), fileName.end());

				DWORD processID = findProcessFromFile(filePath);
				std::wstring processname = (processID != 0) ? getProcessName(processID) : L"Undefined || No Process";
				
				std::string ProcessName(processname.begin(), processname.end());

				switch (notification->Action) {
				case FILE_ACTION_ADDED:
					logToFile("File Created", filePath, processID, ProcessName);
					break;
				case FILE_ACTION_REMOVED:
					logToFile("File Deleted", filePath, processID, ProcessName);
					break;
				case FILE_ACTION_MODIFIED:
					logToFile("File Modified", filePath, processID, ProcessName);
					break;
				case FILE_ACTION_RENAMED_OLD_NAME:
					logToFile("File Renamed (Old)", filePath, processID, ProcessName);
					break;
				case FILE_ACTION_RENAMED_NEW_NAME:
					logToFile("File Renamed (New)", filePath, processID, ProcessName);
					break;
				}
				notification = notification->NextEntryOffset
					? (FILE_NOTIFY_INFORMATION*)((BYTE*)notification +
						notification->NextEntryOffset)
					: nullptr;
			} while (notification);
		}
	}

	CloseHandle(hDir);
}

// testing the function using main functions
// testing code 

//int main() {
//	std::string directory = "C:\\Users";
//	monitorDirectory(directory);
//	return 0;
//}

