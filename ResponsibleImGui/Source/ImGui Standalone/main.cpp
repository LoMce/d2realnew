#include "UI.h"

#ifdef _WINDLL

HANDLE hCurrentUIThread = nullptr;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
   if (fdwReason == DLL_PROCESS_ATTACH)
   {
       DisableThreadLibraryCalls(hinstDLL);
       UI::hCurrentModule = hinstDLL;
       hCurrentUIThread = CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)UI::Render, nullptr, NULL, nullptr);
   }

   if (fdwReason == DLL_PROCESS_DETACH)
       TerminateThread(hCurrentUIThread, 0);

   return TRUE;
}

#else

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
   try {
       //AllocConsole();       // Redirect stdout and stderr to console
       //FILE* stream;
       //freopen_s(&stream, "CONOUT$", "w", stdout);
       //freopen_s(&stream, "CONOUT$", "w", stderr);

       UI::Render();

       return 0;
   }
   catch (const std::exception& e) {
       MessageBoxA(nullptr, e.what(), "Application Error", MB_OK | MB_ICONERROR);
       return -1;
   }
   catch (...) {
       MessageBoxA(nullptr, "An unknown error occurred during application startup", "Application Error", MB_OK | MB_ICONERROR);
       return -1;
   }
}

#endif