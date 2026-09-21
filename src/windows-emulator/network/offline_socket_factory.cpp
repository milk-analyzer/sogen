#include "offline_socket_factory.hpp"

#include <network/socket.hpp>

#ifndef POLLWRNORM
#define POLLWRNORM 0x0100
#endif

namespace sogen
{

    namespace network
    {
        namespace
        {
            // 127.0.0.0/8, ::1 and the v4-mapped form of the former. A machine with no network still has
            // these, so they must not fail the way a routed address does.
            bool is_loopback(const address& addr)
            {
                if (addr.is_ipv4())
                {
                    return (ntohl(addr.get_in_addr().sin_addr.s_addr) >> 24) == 127;
                }

                if (addr.is_ipv6())
                {
                    const auto* bytes = addr.get_in6_addr().sin6_addr.s6_addr;

                    bool leading_zero = true;
                    for (size_t i = 0; i < 10; ++i)
                    {
                        leading_zero = leading_zero && bytes[i] == 0;
                    }

                    if (!leading_zero)
                    {
                        return false;
                    }

                    const bool is_v6_loopback = bytes[10] == 0 && bytes[11] == 0 && bytes[12] == 0 && bytes[13] == 0 && //
                                                bytes[14] == 0 && bytes[15] == 1;
                    const bool is_mapped_v4_loopback = bytes[10] == 0xFF && bytes[11] == 0xFF && bytes[12] == 127;
                    return is_v6_loopback || is_mapped_v4_loopback;
                }

                return false;
            }

            struct offline_socket_factory;

            struct offline_socket : i_socket
            {
                offline_socket_factory* factory{};
                int family{};
                bool datagram{false};
                bool listening{false};
                int error{0};
                std::optional<address> local{};
                std::optional<address> peer{};

                offline_socket(offline_socket_factory& f, const int af, const bool is_datagram)
                    : factory(&f),
                      family(af),
                      datagram(is_datagram)
                {
                }

                void set_blocking(const bool /*blocking*/) override
                {
                }

                int get_last_error() override
                {
                    return this->error;
                }

                bool is_ready(const bool in_poll) override
                {
                    // Nothing is ever readable. A datagram socket is writable; where the datagram goes
                    // is decided when it is sent.
                    return !in_poll && this->datagram;
                }

                bool is_listening() override
                {
                    return this->listening;
                }

                std::optional<address> get_local_address() override
                {
                    return this->local;
                }

                bool bind(const address& addr) override;
                void bind_implicitly();

                bool connect(const address& addr) override
                {
                    if (this->datagram)
                    {
                        // Only records where send() goes. It needs no network, and succeeds without one.
                        this->bind_implicitly();
                        this->peer = addr;
                        return true;
                    }

                    // Nothing in the guest can be reached this way either: no connection is ever carried,
                    // so a loopback port looks closed and everything else looks unrouted.
                    this->error = is_loopback(addr) ? SERR(ECONNREFUSED) : SERR(ENETUNREACH);
                    return false;
                }

                bool listen(const int /*backlog*/) override
                {
                    this->listening = true;
                    return true;
                }

                std::unique_ptr<i_socket> accept(address& /*address*/) override
                {
                    this->error = SERR(EWOULDBLOCK);
                    return nullptr;
                }

                sent_size send(const std::span<const std::byte> data) override
                {
                    if (this->datagram && this->peer)
                    {
                        return this->sendto(*this->peer, data);
                    }

                    // A stream socket here is never connected, and neither is a datagram one without a peer.
                    this->error = SERR(ENOTCONN);
                    return -1;
                }

                sent_size sendto(const address& destination, const std::span<const std::byte> data) override
                {
                    if (!this->datagram)
                    {
                        this->error = SERR(ENOTCONN);
                        return -1;
                    }

                    this->bind_implicitly();

                    if (is_loopback(destination))
                    {
                        // Accepted and dropped, which is what a datagram to a loopback port nobody
                        // listens on amounts to.
                        return static_cast<sent_size>(data.size());
                    }

                    this->error = SERR(ENETUNREACH);
                    return -1;
                }

                sent_size recv(const std::span<std::byte> /*data*/) override
                {
                    this->error = this->datagram ? SERR(EWOULDBLOCK) : SERR(ENOTCONN);
                    return -1;
                }

                sent_size recvfrom(address& /*source*/, const std::span<std::byte> /*data*/) override
                {
                    this->error = this->datagram ? SERR(EWOULDBLOCK) : SERR(ENOTCONN);
                    return -1;
                }
            };

            struct offline_socket_factory : socket_factory
            {
                uint16_t next_port{49152};

                // The dynamic range, handed out in order: a guest that binds to port 0 and asks what it
                // got expects a number, not 0.
                uint16_t allocate_port()
                {
                    const auto port = this->next_port;
                    this->next_port = this->next_port == 65535 ? uint16_t{49152} : static_cast<uint16_t>(this->next_port + 1);
                    return port;
                }

                std::unique_ptr<i_socket> create_socket(const int af, const int type, const int /*protocol*/) override
                {
                    // Never nullptr: the AFD endpoint treats that as fatal and the run ends, where a
                    // machine without a network still hands out sockets.
                    return std::make_unique<offline_socket>(*this, af, type != SOCK_STREAM);
                }

                // The base implementation polls host sockets and rejects anything that is not one.
                int poll_sockets(const std::span<poll_entry> entries) override
                {
                    // POLLOUT and POLLWRNORM are one bit on Windows and two on glibc; the AFD endpoint asks
                    // with either.
                    constexpr auto write_mask = static_cast<int16_t>(POLLOUT | POLLWRNORM);

                    int ready_count = 0;
                    for (auto& entry : entries)
                    {
                        entry.revents = 0;

                        const auto* s = dynamic_cast<offline_socket*>(entry.s);
                        if (!s || !s->datagram)
                        {
                            continue;
                        }

                        entry.revents = static_cast<int16_t>(entry.events & write_mask);
                        if (entry.revents != 0)
                        {
                            ++ready_count;
                        }
                    }

                    return ready_count;
                }
            };

            bool offline_socket::bind(const address& addr)
            {
                this->local = addr;

                if (this->local->is_supported() && this->local->get_port() == 0)
                {
                    this->local->set_port(this->factory->allocate_port());
                }

                return true;
            }

            // What the first send or connect does to an unbound datagram socket.
            void offline_socket::bind_implicitly()
            {
                if (this->local)
                {
                    return;
                }

                address any{};
                if (this->family == AF_INET)
                {
                    any.set_ipv4(uint32_t{0});
                }
                else if (this->family == AF_INET6)
                {
                    any.set_ipv6(in6_addr{});
                }
                else
                {
                    return;
                }

                any.set_port(this->factory->allocate_port());
                this->local = any;
            }
        }

        std::unique_ptr<socket_factory> create_offline_socket_factory()
        {
            return std::make_unique<offline_socket_factory>();
        }
    }

} // namespace sogen
