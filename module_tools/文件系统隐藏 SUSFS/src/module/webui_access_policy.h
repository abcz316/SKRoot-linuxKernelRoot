#pragma once

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

namespace webui_access {

inline bool isIpv4Loopback(const in_addr& address) {
    const uint32_t host_order = ntohl(address.s_addr);
    return (host_order & 0xff000000U) == 0x7f000000U;
}

inline bool isIpv4MappedLoopback(const in6_addr& address) {
    if (!IN6_IS_ADDR_V4MAPPED(&address)) return false;
    in_addr mapped{};
    std::memcpy(&mapped.s_addr, &address.s6_addr[12], sizeof(mapped.s_addr));
    return isIpv4Loopback(mapped);
}

inline std::string normalizeNumericAddress(std::string address) {
    if (address.empty()) return {};

    // getnameinfo(NI_NUMERICHOST) normally returns a bare numeric address.
    // Tolerate brackets and an IPv6 scope suffix as used by some Android
    // networking stacks and wrappers.
    if (address.size() >= 2 && address.front() == '[' && address.back() == ']') {
        address = address.substr(1, address.size() - 2);
    }
    const size_t scope = address.find('%');
    if (scope != std::string::npos) address.erase(scope);
    return address;
}

inline bool isLoopbackAddress(std::string address) {
    address = normalizeNumericAddress(std::move(address));
    if (address.empty()) return false;

    in_addr ipv4{};
    if (::inet_pton(AF_INET, address.c_str(), &ipv4) == 1) {
        return isIpv4Loopback(ipv4);
    }

    in6_addr ipv6{};
    if (::inet_pton(AF_INET6, address.c_str(), &ipv6) == 1) {
        return IN6_IS_ADDR_LOOPBACK(&ipv6) || isIpv4MappedLoopback(ipv6);
    }
    return false;
}

inline uint16_t socketAddressPort(const sockaddr_storage& address) {
    if (address.ss_family == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
    }
    if (address.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    }
    return 0;
}

inline bool isLoopbackSocketAddress(const sockaddr_storage& address) {
    if (address.ss_family == AF_INET) {
        return isIpv4Loopback(reinterpret_cast<const sockaddr_in*>(&address)->sin_addr);
    }
    if (address.ss_family == AF_INET6) {
        const in6_addr& ipv6 = reinterpret_cast<const sockaddr_in6*>(&address)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(&ipv6) || isIpv4MappedLoopback(ipv6);
    }
    return false;
}

inline bool numericAddressMatchesSocket(std::string address, const sockaddr_storage& socket_address) {
    address = normalizeNumericAddress(std::move(address));
    if (address.empty()) return false;

    in_addr parsed_v4{};
    const bool has_v4 = ::inet_pton(AF_INET, address.c_str(), &parsed_v4) == 1;
    in6_addr parsed_v6{};
    const bool has_v6 = ::inet_pton(AF_INET6, address.c_str(), &parsed_v6) == 1;

    if (socket_address.ss_family == AF_INET) {
        const in_addr& socket_v4 = reinterpret_cast<const sockaddr_in*>(&socket_address)->sin_addr;
        if (has_v4) return std::memcmp(&parsed_v4, &socket_v4, sizeof(parsed_v4)) == 0;
        if (has_v6 && IN6_IS_ADDR_V4MAPPED(&parsed_v6)) {
            return std::memcmp(&parsed_v6.s6_addr[12], &socket_v4.s_addr, sizeof(socket_v4.s_addr)) == 0;
        }
        return false;
    }

    if (socket_address.ss_family == AF_INET6) {
        const in6_addr& socket_v6 = reinterpret_cast<const sockaddr_in6*>(&socket_address)->sin6_addr;
        if (has_v6) return std::memcmp(&parsed_v6, &socket_v6, sizeof(parsed_v6)) == 0;
        if (has_v4 && IN6_IS_ADDR_V4MAPPED(&socket_v6)) {
            return std::memcmp(&socket_v6.s6_addr[12], &parsed_v4.s_addr, sizeof(parsed_v4.s_addr)) == 0;
        }
    }
    return false;
}

inline bool isLoopbackDestination(int server_port, int remote_port, const std::string& remote_address) {
    if (server_port <= 0 || server_port > 65535 || remote_port <= 0 || remote_port > 65535) return false;

    DIR* directory = ::opendir("/proc/self/fd");
    if (!directory) return false;

    bool found = false;
    bool all_matching_destinations_are_loopback = true;
    while (dirent* entry = ::readdir(directory)) {
        if (!entry->d_name[0]) continue;
        char* end = nullptr;
        errno = 0;
        const long parsed_fd = std::strtol(entry->d_name, &end, 10);
        if (errno != 0 || !end || *end != '\0' || parsed_fd < 0 || parsed_fd > INT_MAX) continue;
        const int fd = static_cast<int>(parsed_fd);
        if (fd == ::dirfd(directory)) continue;

        sockaddr_storage local{};
        socklen_t local_size = sizeof(local);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_size) != 0) continue;
        sockaddr_storage peer{};
        socklen_t peer_size = sizeof(peer);
        if (::getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &peer_size) != 0) continue;

        if (socketAddressPort(local) != static_cast<uint16_t>(server_port)
            || socketAddressPort(peer) != static_cast<uint16_t>(remote_port)
            || !numericAddressMatchesSocket(remote_address, peer)) {
            continue;
        }
        found = true;
        if (!isLoopbackSocketAddress(local)) all_matching_destinations_are_loopback = false;
    }
    ::closedir(directory);
    return found && all_matching_destinations_are_loopback;
}

} // namespace webui_access
