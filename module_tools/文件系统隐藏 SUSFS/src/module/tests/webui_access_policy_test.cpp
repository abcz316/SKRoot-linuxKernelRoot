#include "../webui_access_policy.h"

#include <cassert>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

struct TcpPair {
    int listener = -1;
    int client = -1;
    int accepted = -1;
    uint16_t server_port = 0;
    uint16_t client_port = 0;
    std::string server_address;

    ~TcpPair() {
        if (accepted >= 0) ::close(accepted);
        if (client >= 0) ::close(client);
        if (listener >= 0) ::close(listener);
    }
};

bool openTcpPair(const std::string& address, TcpPair& pair) {
    pair.listener = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (pair.listener < 0) return false;

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = 0;
    if (::inet_pton(AF_INET, address.c_str(), &server.sin_addr) != 1
        || ::bind(pair.listener, reinterpret_cast<sockaddr*>(&server), sizeof(server)) != 0
        || ::listen(pair.listener, 1) != 0) {
        return false;
    }
    socklen_t size = sizeof(server);
    if (::getsockname(pair.listener, reinterpret_cast<sockaddr*>(&server), &size) != 0) return false;
    pair.server_port = ntohs(server.sin_port);

    pair.client = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (pair.client < 0
        || ::connect(pair.client, reinterpret_cast<sockaddr*>(&server), sizeof(server)) != 0) {
        return false;
    }
    sockaddr_in client{};
    size = sizeof(client);
    if (::getsockname(pair.client, reinterpret_cast<sockaddr*>(&client), &size) != 0) return false;
    pair.client_port = ntohs(client.sin_port);
    pair.accepted = ::accept(pair.listener, nullptr, nullptr);
    pair.server_address = address;
    return pair.accepted >= 0;
}

std::string firstNonLoopbackIpv4() {
    ifaddrs* interfaces = nullptr;
    if (::getifaddrs(&interfaces) != 0) return {};
    std::string result;
    for (ifaddrs* item = interfaces; item; item = item->ifa_next) {
        if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET
            || (item->ifa_flags & IFF_LOOPBACK) != 0) continue;
        char buffer[INET_ADDRSTRLEN]{};
        const auto* value = reinterpret_cast<const sockaddr_in*>(item->ifa_addr);
        if (::inet_ntop(AF_INET, &value->sin_addr, buffer, sizeof(buffer))) {
            result = buffer;
            break;
        }
    }
    ::freeifaddrs(interfaces);
    return result;
}

} // namespace

int main() {
    const std::vector<std::string> accepted{
        "127.0.0.1",
        "127.0.0.2",
        "127.255.255.254",
        "::1",
        "0:0:0:0:0:0:0:1",
        "::1%lo",
        "[::1]",
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "0:0:0:0:0:ffff:7f00:1",
    };
    for (const auto& address : accepted) {
        assert(webui_access::isLoopbackAddress(address));
    }

    const std::vector<std::string> rejected{
        "",
        "localhost",
        "0.0.0.0",
        "126.255.255.255",
        "128.0.0.1",
        "192.168.1.2",
        "::",
        "::2",
        "::ffff:192.168.1.2",
        "64:ff9b::127.0.0.1",
        "[::1]:8080",
        "not-an-address",
    };
    for (const auto& address : rejected) {
        assert(!webui_access::isLoopbackAddress(address));
    }

    TcpPair loopback;
    assert(openTcpPair("127.0.0.1", loopback));
    assert(webui_access::isLoopbackDestination(
        loopback.server_port, loopback.client_port, "127.0.0.1"));
    assert(webui_access::isLoopbackDestination(
        loopback.server_port, loopback.client_port, "::ffff:7f00:1"));
    assert(!webui_access::isLoopbackDestination(
        loopback.server_port, loopback.client_port, "192.0.2.1"));

    const std::string non_loopback = firstNonLoopbackIpv4();
    if (!non_loopback.empty()) {
        TcpPair lan;
        assert(openTcpPair(non_loopback, lan));
        assert(!webui_access::isLoopbackDestination(
            lan.server_port, lan.client_port, non_loopback));
    }

    std::cout << "webui access policy tests passed\n";
    return 0;
}
