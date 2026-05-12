#include "obn/net_compat.hpp"

#include <atomic>

namespace obn::net {

#ifdef _WIN32

// WSAStartup / WSACleanup are reference-counted by Windows itself, but
// only per-call: every WSAStartup call needs a matching WSACleanup, and
// the count survives across DLL boundaries. We keep our own counter so
// that bambu_networking.dll and BambuSource.dll can both call
// wsa_startup_once() in DllMain(DLL_PROCESS_ATTACH) without one
// over-cleaning up after the other on detach.
namespace {
std::atomic<int> g_refs{0};
} // namespace

void wsa_startup_once()
{
    if (g_refs.fetch_add(1, std::memory_order_acq_rel) == 0) {
        WSADATA d{};
        ::WSAStartup(MAKEWORD(2, 2), &d);
    }
}

void wsa_cleanup_once()
{
    int prev = g_refs.fetch_sub(1, std::memory_order_acq_rel);
    if (prev == 1) {
        ::WSACleanup();
    } else if (prev <= 0) {
        // Underflow: someone called cleanup more times than startup.
        // Restore the count so subsequent startup/cleanup pairs stay
        // balanced; do nothing else (we already issued one too many
        // WSACleanups). Signed overflow is fine because we keep the
        // ceiling well below INT_MAX in any realistic process.
        g_refs.fetch_add(1, std::memory_order_acq_rel);
    }
}

const char* error_string(int e)
{
    switch (e) {
    case 0:                    return "OK";
    case WSAEINTR:             return "WSAEINTR";
    case WSAEBADF:             return "WSAEBADF";
    case WSAEACCES:            return "WSAEACCES";
    case WSAEFAULT:            return "WSAEFAULT";
    case WSAEINVAL:            return "WSAEINVAL";
    case WSAEMFILE:            return "WSAEMFILE";
    case WSAEWOULDBLOCK:       return "WSAEWOULDBLOCK";
    case WSAEINPROGRESS:       return "WSAEINPROGRESS";
    case WSAEALREADY:          return "WSAEALREADY";
    case WSAENOTSOCK:          return "WSAENOTSOCK";
    case WSAEDESTADDRREQ:      return "WSAEDESTADDRREQ";
    case WSAEMSGSIZE:          return "WSAEMSGSIZE";
    case WSAEPROTOTYPE:        return "WSAEPROTOTYPE";
    case WSAENOPROTOOPT:       return "WSAENOPROTOOPT";
    case WSAEPROTONOSUPPORT:   return "WSAEPROTONOSUPPORT";
    case WSAESOCKTNOSUPPORT:   return "WSAESOCKTNOSUPPORT";
    case WSAEOPNOTSUPP:        return "WSAEOPNOTSUPP";
    case WSAEPFNOSUPPORT:      return "WSAEPFNOSUPPORT";
    case WSAEAFNOSUPPORT:      return "WSAEAFNOSUPPORT";
    case WSAEADDRINUSE:        return "WSAEADDRINUSE";
    case WSAEADDRNOTAVAIL:     return "WSAEADDRNOTAVAIL";
    case WSAENETDOWN:          return "WSAENETDOWN";
    case WSAENETUNREACH:       return "WSAENETUNREACH";
    case WSAENETRESET:         return "WSAENETRESET";
    case WSAECONNABORTED:      return "WSAECONNABORTED";
    case WSAECONNRESET:        return "WSAECONNRESET";
    case WSAENOBUFS:           return "WSAENOBUFS";
    case WSAEISCONN:           return "WSAEISCONN";
    case WSAENOTCONN:          return "WSAENOTCONN";
    case WSAESHUTDOWN:         return "WSAESHUTDOWN";
    case WSAETIMEDOUT:         return "WSAETIMEDOUT";
    case WSAECONNREFUSED:      return "WSAECONNREFUSED";
    case WSAEHOSTDOWN:         return "WSAEHOSTDOWN";
    case WSAEHOSTUNREACH:      return "WSAEHOSTUNREACH";
    case WSAHOST_NOT_FOUND:    return "WSAHOST_NOT_FOUND";
    case WSATRY_AGAIN:         return "WSATRY_AGAIN";
    case WSANO_RECOVERY:       return "WSANO_RECOVERY";
    case WSANO_DATA:           return "WSANO_DATA";
    case WSAEPROCLIM:          return "WSAEPROCLIM";
    case WSASYSNOTREADY:       return "WSASYSNOTREADY";
    case WSAVERNOTSUPPORTED:   return "WSAVERNOTSUPPORTED";
    case WSANOTINITIALISED:    return "WSANOTINITIALISED";
    default:                   return "WSA error";
    }
}

int poll_one(socket_t fd, short events, int timeout_ms)
{
    WSAPOLLFD pfd{};
    pfd.fd      = fd;
    pfd.events  = events;
    pfd.revents = 0;
    return ::WSAPoll(&pfd, 1, timeout_ms);
}

bool is_open(socket_t fd)
{
    if (fd == kInvalid) return false;
    int       type = 0;
    int       len  = sizeof(type);
    int       rc   = ::getsockopt(fd, SOL_SOCKET, SO_TYPE,
                                  reinterpret_cast<char*>(&type), &len);
    return rc == 0;
}

#else // POSIX

int poll_one(socket_t fd, short events, int timeout_ms)
{
    pollfd pfd{};
    pfd.fd      = fd;
    pfd.events  = events;
    pfd.revents = 0;
    return ::poll(&pfd, 1, timeout_ms);
}

bool is_open(socket_t fd)
{
    if (fd < 0) return false;
    int       type = 0;
    socklen_t len  = sizeof(type);
    return ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0;
}

#endif

} // namespace obn::net
