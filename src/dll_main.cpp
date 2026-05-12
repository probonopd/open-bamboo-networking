// Windows-only DLL entry point. Pulled into bambu_networking.dll AND
// BambuSource.dll at link time (see CMakeLists.txt). Both libraries
// open sockets through obn::net::*, which assumes WSAStartup has run
// once per process — DllMain is the natural place for that.
//
// The reference counter inside obn::net::wsa_startup_once / cleanup_once
// keeps things sane when the two DLLs (and any future ones) are loaded
// and unloaded independently by Studio's plugin loader.

#ifdef _WIN32

#include "obn/net_compat.hpp"

extern "C" BOOL APIENTRY DllMain(HMODULE /*hModule*/,
                                 DWORD   reason,
                                 LPVOID  /*lpReserved*/)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        obn::net::wsa_startup_once();
        break;
    case DLL_PROCESS_DETACH:
        obn::net::wsa_cleanup_once();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    default:
        break;
    }
    return TRUE;
}

#endif // _WIN32
