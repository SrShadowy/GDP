#include "Processos.hpp"
#include <iostream>


int main()
{

	BOOL isOK;
	HANDLE hToken;
	HANDLE hCurrentProcess;
	hCurrentProcess = GetCurrentProcess();
	isOK = OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);

	using namespace std;
	SetConsoleTitle("GDP :D");
	DWORD PID = GetProcessID("game.exe");

	
	ListThreads(PID);
	cout << "Sao essas as thread do processo: " << endl;


	suspend(PID);
	cout << "Processo supenso :o de PID " << PID << "\nagora vamos fazer volta ao normal\n" ;

	Resum(PID);
	cout << "Terminamos " << endl;

	getchar();

	return 0;
}