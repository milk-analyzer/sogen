#pragma once

#include "socket_factory.hpp"

namespace sogen
{

    namespace network
    {
        // A socket factory with no route to anywhere. Sockets can be created, bound and put into the
        // listening state, but nothing ever connects, arrives or leaves, and no socket is created on the
        // host for any of it. The guest sees a machine whose network is down: a routed address is
        // unreachable, a loopback port is closed. Traffic between two guest sockets is not carried.
        std::unique_ptr<socket_factory> create_offline_socket_factory();
    }

} // namespace sogen
