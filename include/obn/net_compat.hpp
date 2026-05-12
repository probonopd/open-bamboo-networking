// Thin BSD-sockets-vs-WinSock shim. Pulled in by every translation unit
// that talks to a TCP/UDP socket so the rest of the plugin can stay
// free of #ifdef _WIN32 noise around socket types, fd close, errno,
// and the per-fd "set non-blocking" knob.
//
// Order rules:
//   * On Windows winsock2.h MUST be the first network header pulled
//     in (otherwise the legacy <winsock.h> piggy-backed on <windows.h>
//     wins and you get redefinition errors). The macro guards below
//     enforce that — if a translation unit has already included
//     <windows.h> with WIN32_LEAN_AND_MEAN unset, it will fail to
//     compile here, which is the desired behaviour.
//   * Always include "obn/net_compat.hpp" before any other obn header
//     (and before <windows.h>) in DLLs that touch sockets.

#pragma once

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <mswsock.h>
#  include <windows.h>

namespace obn::net {

using socket_t = SOCKET;
inline constexpr socket_t kInvalid = INVALID_SOCKET;

// Bring the BSD-style names into our namespace so call sites can write
// poll_event::in / poll_event::out instead of remembering POLLIN /
// POLLRDNORM / WSAPOLLFD bit semantics. The values match POLLIN /
// POLLOUT exactly on Windows because WSAPoll uses the same bits.
namespace poll_event {
inline constexpr short in  = POLLRDNORM;
inline constexpr short out = POLLWRNORM;
} // namespace poll_event

inline int close_socket(socket_t s)            { return ::closesocket(s); }
inline int set_nonblocking(socket_t s)         { u_long m = 1; return ::ioctlsocket(s, FIONBIO, &m); }
inline int last_error()                        { return ::WSAGetLastError(); }
inline bool would_block(int e)
{
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY;
}
inline bool intr(int /*e*/)                    { return false; }
inline bool bad_fd(int e)                      { return e == WSAENOTSOCK || e == WSAEBADF; }
inline bool in_progress(int e)                 { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }

void wsa_startup_once();
void wsa_cleanup_once();

// Tiny error-to-string helper that returns a short, allocation-free
// message for the WinSock errno. Falls back to a numeric form for
// codes we do not have a label for. Mirrors strerror() on POSIX.
const char* error_string(int e);

} // namespace obn::net

#else // POSIX

#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <cerrno>
#  include <cstring>

namespace obn::net {

using socket_t = int;
inline constexpr socket_t kInvalid = -1;

namespace poll_event {
inline constexpr short in  = POLLIN;
inline constexpr short out = POLLOUT;
} // namespace poll_event

inline int close_socket(socket_t s)            { return ::close(s); }
inline int set_nonblocking(socket_t s)
{
    int f = ::fcntl(s, F_GETFL, 0);
    if (f < 0) return -1;
    return ::fcntl(s, F_SETFL, f | O_NONBLOCK);
}
inline int last_error()                        { return errno; }
inline bool would_block(int e)
{
    return e == EAGAIN || e == EWOULDBLOCK || e == EINPROGRESS;
}
inline bool intr(int e)                        { return e == EINTR; }
inline bool bad_fd(int e)                      { return e == EBADF; }
inline bool in_progress(int e)                 { return e == EINPROGRESS; }
inline void wsa_startup_once()                 {}
inline void wsa_cleanup_once()                 {}
inline const char* error_string(int e)         { return std::strerror(e); }

} // namespace obn::net

#endif

namespace obn::net {

// Wait for `events` (poll_event::in / poll_event::out, OR-able) to fire
// on `fd` for up to `timeout_ms`. Returns >0 on ready, 0 on timeout, -1
// on error (last_error() carries the code). Implemented over
// WSAPoll on Windows and ::poll on POSIX -- both have the same
// pollfd layout for our purposes.
int poll_one(socket_t fd, short events, int timeout_ms);

// Returns true if `fd` looks like a connected stream socket. Used by a
// handful of "is this still alive?" checks where we'd otherwise have
// to thread an extra error code back. Cheap.
bool is_open(socket_t fd);

} // namespace obn::net
