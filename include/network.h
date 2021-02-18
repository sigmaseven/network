//
// Created by sigma on 1/7/2021.
//

#ifndef NETWORK_H
#define NETWORK_H

#include <array>
#include <bit>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

extern "C" {
#ifdef LINUX
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif // LINUX
#ifdef WINDOWS
#include <winsock2.h>
#include <mstcpip.h>
#include <ws2tcpip.h>
#endif

}
namespace network {
    class payload;

    enum endian {
        BIG,
        LITTLE,
    };

    enum address {
        IPV4 [[maybe_unused]] = AF_INET,
        IPV6 [[maybe_unused]] = AF_INET6,
    };

    enum protocol {
        ICMP   [[maybe_unused]] = IPPROTO_ICMP,
        ICMPV6 [[maybe_unused]] = IPPROTO_ICMPV6,
        IGMP   [[maybe_unused]] = IPPROTO_IGMP,
        TCP    [[maybe_unused]] = IPPROTO_TCP,
        UDP    [[maybe_unused]] = IPPROTO_UDP,
    };

    enum ssl_context_type {
        SSL_CLIENT [[maybe_unused]],
        SSL_SERVER [[maybe_unused]],
    };

    enum ssl_version {
        SSLV2  [[maybe_unused]],
        SSLV3  [[maybe_unused]],
        TLS1_1 [[maybe_unused]],
        TLS1_2 [[maybe_unused]],
        TLS1_3 [[maybe_unused]],
    };

    constexpr endian platform_endianness() {
        return std::endian::native == std::endian::big ? BIG : LITTLE;
    }

    inline void init() {
#ifdef WINDOWS
        WSAData output{};
        WSAStartup(MAKEWORD(2,2), &output);
#endif
    }

    inline void shutdown() {
#ifdef WINDOWS
        WSACleanup();
#endif
    }

    class error {
        std::string msg;

    public:
        explicit error(std::string message) :
                msg(std::move(message)){};
        void display() const {
            std::cerr << msg << std::endl;
        }

        std::string& message() { return msg; }
    };

    [[maybe_unused]] inline error make_error(const int& e) {
#ifdef WINDOWS
        std::string buffer;
        buffer.resize(1024);
        strerror_s(buffer.data(), buffer.size(), e);
        return error(buffer);
#endif
#ifdef LINUX
        return network::error(strerror(errno));
#endif
    }

    class serializable {
    public:
        virtual std::optional<network::error> deserialize(payload& p) = 0;
        virtual std::optional<network::error> serialize(payload& p) = 0;
        virtual std::size_t size() = 0;
    };

    class address_record {
        struct addrinfo *i;

    public:
        explicit address_record(struct addrinfo *info) : i(info) {}

        std::optional<int> family() {
            if(!this->i) {
                return std::nullopt;
            }

            return this->i->ai_family;
        }

        [[nodiscard]] struct addrinfo *info() const {
            return this->i;
        }

        std::optional<std::string> name() {
            if(!this->i) {
                return std::nullopt;
            }

            char buffer[INET6_ADDRSTRLEN];
            memset(&buffer, 0, sizeof(buffer));

            switch(*this->family()) {
                case AF_INET:
                    if (inet_ntop(*this->family(), ((struct sockaddr_in *) &this->i->ai_addr),
                                  reinterpret_cast<char *>(&buffer), sizeof(buffer)) == nullptr) {
                        return std::nullopt;
                    }
                    break;

                case AF_INET6:
                    if (inet_ntop(*this->family(), ((struct sockaddr_in6 *) &this->i->ai_addr),
                                  reinterpret_cast<char *>(&buffer), sizeof(buffer)) == nullptr) {
                        return std::nullopt;
                    }
                    break;
                default:
                    return std::nullopt;
            }

            return std::string(buffer);
        }

        [[maybe_unused]] address_record next() {
            return address_record(this->i->ai_next);
        }

        [[maybe_unused]] std::optional<int> protocol() {
            if(!this->i) {
                return std::nullopt;
            }

            return this->i->ai_protocol;
        }

        [[maybe_unused]] std::optional<int> socket_type() {
            if(!this->i) {
                return std::nullopt;
            }

            return this->i->ai_socktype;
        }
    };

    class address_info {
        struct addrinfo hint;
        struct addrinfo *result;

    public:
        address_info() :
                hint(),
                result(nullptr) {
            memset(&hint, 0, sizeof(hint));

            hint.ai_family = AF_UNSPEC;
            hint.ai_socktype = SOCK_STREAM;
            hint.ai_flags = AI_PASSIVE;
        }

        [[maybe_unused]] explicit address_info(struct addrinfo *address) :
                hint(),
                result(address) {
            memset(&hint, 0, sizeof(hint));

            hint.ai_family = AF_UNSPEC;
            hint.ai_socktype = SOCK_STREAM;
            hint.ai_flags = AI_PASSIVE;
        }

        [[maybe_unused]] explicit address_info(const int family) :
                hint(),
                result(nullptr) {
            memset(&hint, 0, sizeof(hint));

            hint.ai_family = family;
            hint.ai_socktype = SOCK_STREAM;
            hint.ai_flags = AI_PASSIVE;
        }

        address_info(const int family, const int socktype) :
                hint(),
                result(nullptr) {
            memset(&hint, 0, sizeof(hint));

            hint.ai_family = family;
            hint.ai_socktype = socktype;
            hint.ai_flags = AI_PASSIVE;
        }

        [[maybe_unused]] address_info(const int family, const int socktype, const int protocol, const int flags) :
                hint(),
                result(nullptr) {
            memset(&hint, 0, sizeof(hint));

            hint.ai_family = family;
            hint.ai_socktype = socktype;
            hint.ai_protocol = protocol;
            hint.ai_flags = flags;
        }

        ~address_info() {
            if (this->result) {
                freeaddrinfo(this->result);
            }
        }

        address_info &operator=(const address_info &copy) {
            if(this != &copy) {
                this->hint = copy.hint;
                this->result = copy.result;
            }

            return *this;
        }

        address_info(address_info&& src) noexcept: hint(src.hint), result(src.result){ src.result = nullptr; }

        std::vector<address_record> records() {
            std::vector<address_record> output;

            for(auto entry = this->result; entry != nullptr; entry = entry->ai_next) {
                output.emplace_back(entry);
            }

            return output;
        }

        struct addrinfo *results() { return result; }

        std::optional<network::error>resolve(const std::string& node) {
            if(this->result) {
                freeaddrinfo(this->result);
                this->result = nullptr;
            }

            if(int e = getaddrinfo(node.c_str(), nullptr, &this->hint, &this->result)) {
                return network::error(std::string(gai_strerror(e)));
            }

            return std::nullopt;
        }

        std::optional<network::error> resolve(const std::string& node, const std::string& port) {
            if(this->result) {
                freeaddrinfo(this->result);
                this->result = nullptr;
            }

            if(int e = getaddrinfo(node.c_str(), port.c_str(), &this->hint, &this->result); e != 0) {
                return network::error(std::string(gai_strerror(e)));
            }

            return std::nullopt;
        }
    };

    class payload {
        std::vector<std::uint8_t> data;
        std::size_t position;

    public:
        payload() :
        data(std::vector<std::uint8_t>()),
        position(0) {
        }

        explicit payload(const std::size_t &size) :
        data(std::vector<std::uint8_t>(size)),
        position(0) {
        }

        explicit payload(const std::string& input) {
            for(const auto& c : input) {
                data.push_back(c);
                position = 0;
            }
        }

        friend payload operator+(payload& a, payload& b) {
            auto p = payload();
            p.write(a);
            p.write(b);
            return p;
        }

        std::vector<std::uint8_t>& contents(){ return data; }
        [[nodiscard]] std::size_t index() const { return position; }
        std::size_t remaining() { return (data.size() - position) + 1;}
        void reset() { contents().clear(); position = 0; }

        std::optional<network::error> write(std::string& input) {
            for(const auto& c : input) {
                data.push_back(c);
            }
            return std::nullopt;
        }

        template<std::size_t Count>
        std::optional<network::error> write(std::array<std::uint8_t, Count>& value) {
            for(int i = 0; i < Count; ++i) {
                data.push_back(value[i]);
            }

            return {};
        }

        std::optional<network::error> write(std::vector<std::uint8_t>& value) {
            for(const auto& v : value) {
                data.push_back(v);
            }

            return {};
        }

        std::optional<network::error> write(payload& value) {
            for(const auto& c : value.contents()) {
                data.push_back(c);
            }

            return {};
        }

        std::optional<network::error> write(serializable& value) {
            auto p = payload();

            if(auto e = value.serialize(p)) {
                return e;
            }

            for(const auto& b : p.data) {
                data.push_back(b);
            }

            return std::nullopt;
        }

        template <typename T>
        std::optional<network::error> write(const T& value, endian e) {
            switch(sizeof(T)) {
                case 1:
                    data.push_back(value);
                    break;

                case 2:
                    if(platform_endianness() != e) {
                        data.push_back((value & 0xFF00) >> 8);
                        data.push_back((value & 0x00FF) >> 0);
                    } else {
                        data.push_back((value & 0x00FF) >> 0);
                        data.push_back((value & 0xFF00) >> 8);
                    }
                    break;

                case 4:
                    if(e != platform_endianness()) {
                        data.push_back((value & 0xFF000000) >> 24);
                        data.push_back((value & 0x00FF0000) >> 16);
                        data.push_back((value & 0x0000FF00) >> 8);
                        data.push_back((value & 0x000000FF) >> 0);
                    } else {
                        data.push_back((value & 0x000000FF) >> 0);
                        data.push_back((value & 0x0000FF00) >> 8);
                        data.push_back((value & 0x00FF0000) >> 16);
                        data.push_back((value & 0xFF000000) >> 24);
                    }
                    break;

                case 8:
                    if(e != platform_endianness()) {
                        data.push_back((value & 0xFF00000000000000) >> 56);
                        data.push_back((value & 0x00FF000000000000) >> 48);
                        data.push_back((value & 0x0000FF0000000000) >> 40);
                        data.push_back((value & 0x000000FF00000000) >> 32);
                        data.push_back((value & 0x00000000FF000000) >> 24);
                        data.push_back((value & 0x0000000000FF0000) >> 16);
                        data.push_back((value & 0x000000000000FF00) >> 8);
                        data.push_back((value & 0x00000000000000FF) << 0);
                    } else {
                        data.push_back((value & 0x00000000000000FF) >> 0);
                        data.push_back((value & 0x000000000000FF00) >> 8);
                        data.push_back((value & 0x0000000000FF0000) >> 16);
                        data.push_back((value & 0x00000000FF000000) >> 24);
                        data.push_back((value & 0x000000FF00000000) >> 32);
                        data.push_back((value & 0x0000FF0000000000) >> 40);
                        data.push_back((value & 0x00FF000000000000) >> 48);
                        data.push_back((value & 0xFF00000000000000) >> 56);
                    }
                    break;
            }

            return {};
        }

        template <typename T>
        std::optional<network::error> insert(T value, const std::size_t pos, const endian e) {
            if(sizeof(T) + pos > data.size()) {
                return network::error("type size exceeds payload data size");
            }

            switch(sizeof(T)) {
                case 1:
                    data[pos] = value;
                    break;

                case 2:
                    if(e != platform_endianness()) {
                        data[pos]     = ((value & 0xFF00) >> 8);
                        data[pos + 1] = ((value & 0x00FF) >> 0);
                    } else {
                        data[pos]     = ((value & 0x00FF) >> 0);
                        data[pos + 1] = ((value & 0xFF00) >> 8);
                    }
                    break;

                case 4:
                    if(e != platform_endianness()) {
                        data[pos]     = ((value & 0xFF000000) >> 24);
                        data[pos + 1] = ((value & 0x00FF0000) >> 16);
                        data[pos + 2] = ((value & 0x0000FF00) >> 8);
                        data[pos + 3] = ((value & 0x000000FF) >> 0);
                    } else {
                        data[pos]     = ((value & 0x000000FF) >> 0);
                        data[pos + 1] = ((value & 0x0000FF00) >> 8);
                        data[pos + 2] = ((value & 0x00FF0000) >> 16);
                        data[pos + 3] = ((value & 0xFF000000) >> 24);
                    }
                    break;

                case 8:
                    if(e != platform_endianness()) {
                        data[pos]     = ((value & 0xFF00000000000000) >> 56);
                        data[pos + 1] = ((value & 0x00FF000000000000) >> 48);
                        data[pos + 2] = ((value & 0x0000FF0000000000) >> 40);
                        data[pos + 3] = ((value & 0x000000FF00000000) >> 32);
                        data[pos + 4] = ((value & 0x00000000FF000000) >> 24);
                        data[pos + 5] = ((value & 0x0000000000FF0000) >> 16);
                        data[pos + 6] = ((value & 0x000000000000FF00) >> 8);
                        data[pos + 7] = ((value & 0x00000000000000FF) << 0);
                    } else {
                        data[pos]     = ((value & 0x00000000000000FF) >> 0);
                        data[pos + 1] = ((value & 0x000000000000FF00) >> 8);
                        data[pos + 2] = ((value & 0x0000000000FF0000) >> 16);
                        data[pos + 3] = ((value & 0x00000000FF000000) >> 24);
                        data[pos + 4] = ((value & 0x000000FF00000000) >> 32);
                        data[pos + 5] = ((value & 0x0000FF0000000000) >> 40);
                        data[pos + 6] = ((value & 0x00FF000000000000) >> 48);
                        data[pos + 7] = ((value & 0xFF00000000000000) >> 56);
                    }
                    break;
                default:
                    return network::error("invalid type width");
            }
            return {};
        }

        template <typename T>
        std::optional<network::error> read(T& value, endian e) {
            if(position + sizeof(T) > data.size()) {
                return network::error("type width exceeds remaining payload size");
            }

            switch(sizeof(T)) {
                case 1:
                    value = data[position];
                    position++;
                    break;

                case 2:
                    if(platform_endianness() != e) {
                        value = data[position + 1] << 0 |
                                data[position]     << 8;
                    } else {
                        value = data[position]   << 0 |
                                data[position+1] << 8;
                    }
                    position += 2;
                    break;

                case 4:
                    if(platform_endianness() != e) {
                        value = data[position + 3] << 0  |
                                data[position + 2] << 8  |
                                data[position + 1] << 16 |
                                data[position] << 24;
                    } else {
                        value = data[position]   << 0  |
                                data[position+1] << 8  |
                                data[position+2] << 16 |
                                data[position+3] << 24;
                    }
                    position += 4;
                    break;

                case 8:
                    if(platform_endianness() != e) {
                        value = (std::uint64_t)data[position+7] << 0  |
                                (std::uint64_t)data[position+6] << 8  |
                                (std::uint64_t)data[position+5] << 16 |
                                (std::uint64_t)data[position+4] << 24 |
                                (std::uint64_t)data[position+3] << 32 |
                                (std::uint64_t)data[position+2] << 40 |
                                (std::uint64_t)data[position+1] << 48 |
                                (std::uint64_t)data[position]   << 56;
                    } else {
                        value = (std::uint64_t)data[position]   << 0  |
                                (std::uint64_t)data[position+1] << 8  |
                                (std::uint64_t)data[position+2] << 16 |
                                (std::uint64_t)data[position+3] << 24 |
                                (std::uint64_t)data[position+4] << 32 |
                                (std::uint64_t)data[position+5] << 40 |
                                (std::uint64_t)data[position+6] << 48 |
                                (std::uint64_t)data[position+7] << 56;
                    }
                    position += 8;
                    break;
            }

            return {};
        }

        std::optional<network::error> read(std::string& value, std::size_t count) {
            if(position + count > data.size()) {
                return network::error("end of payload");
            }

            value = std::string(data.begin()+position, data.begin()+position+count);
            return std::nullopt;
        }

        std::optional<network::error> read(std::vector<std::uint8_t>& value) {
            if(position + value.size() > data.size()) {
                return network::error("end of payload");
            }

            value = std::vector<std::uint8_t>(data.begin()+position, data.begin()+position+value.size());
            position += value.size();
            return std::nullopt;
        }

        template<std::size_t Count>
        std::optional<network::error> read(std::array<std::uint8_t, Count>& value){
            if(position + value.size() > data.size()) {
                return network::error("end of payload");
            }

            for(int i = 0; i < value.size(); i++) {
                value[0] = data[position];
                ++position;
            }

            return std::nullopt;
        }

        std::optional<network::error> read(serializable& value) {
            if(position + value.size() > data.size()) {
                return network::error("end of payload");
            }

            if(auto e = value.deserialize(*this)) {
                return e;
            }

            position += value.size();
            return std::nullopt;
        }
    };

    class generic_socket {
    public:
        int d;
        address_info i;

        generic_socket(int family, int socket_type) : d(-1), i(family, socket_type) {}
        ~generic_socket() {
            if(d >= 0) {
#ifdef WINDOWS
                ::closesocket(d);
#else
                ::close(d);
#endif
            }
        }

        virtual std::optional<network::error> send(payload& p) = 0;
        virtual std::pair<int,std::optional<network::error>> receive(payload& p, const std::size_t& size) = 0;

        address_info& info() { return i; }
        void set_descriptor(const int& n) { d = n; }
        int& descriptor() { return d; }

        virtual std::optional<network::error> connect(const std::string& hostname, const std::string& port) {
            if(auto e = i.resolve(hostname, port)) {
                return e;
            }

            auto record = i.results();
            if(auto s = socket(record->ai_family, record->ai_socktype, record->ai_protocol); s < 0) {
                return network::make_error(errno);
            } else {
                set_descriptor(s);
            }

            if(auto e = ::connect(descriptor(), record->ai_addr, record->ai_addrlen); e < 0) {
                return network::make_error(errno);
            }

            return std::nullopt;
        }

        [[nodiscard]] std::optional<network::error> bind(const address_record& record) {
            if(auto s = socket(record.info()->ai_family, record.info()->ai_socktype, record.info()->ai_protocol); s < 0) {
                return network::make_error(errno);
            } else {
                set_descriptor(s);
            }

            if(const auto e = ::bind(d, record.info()->ai_addr, record.info()->ai_addrlen); e < 0) {
                return network::make_error(errno);
            }

            return std::nullopt;
        }

        [[maybe_unused]] [[nodiscard]] std::optional<network::error> listen(const int& backlog) const  {
            if(auto e = ::listen(d, backlog); e < 0) {
                return network::make_error(errno);
            }
            return std::nullopt;
        }
    };

    class [[maybe_unused]] tcp_socket : public generic_socket {
    public:
        tcp_socket() : generic_socket(AF_UNSPEC, SOCK_STREAM) {}

        [[maybe_unused]] explicit tcp_socket(int family) : generic_socket(family, SOCK_STREAM) {}

        std::optional<network::error> send(payload& p) override {
            if(int e = ::send(descriptor(), (char *)p.contents().data(), p.contents().size(), 0); e < 0) {
                return network::make_error(errno);
            }
            return std::nullopt;
        }

        std::pair<int,std::optional<network::error>> receive(payload& p, const std::size_t& size) override {
            int count;
            p.contents().resize(size);

            if(count = ::recv(descriptor(), (char *)p.contents().data(), size, 0); count < 0) {
                return {count, network::make_error(errno)};
            }

            return {count, std::nullopt};
        }
    };

    class [[maybe_unused]] udp_socket : public generic_socket {
    public:
        udp_socket() : generic_socket(AF_UNSPEC, SOCK_DGRAM) {}

        [[maybe_unused]] explicit udp_socket(int family) : generic_socket(family, SOCK_DGRAM) {}

        std::optional<network::error> send(payload& p) override {
            if(int e = ::send(descriptor(), (char *)p.contents().data(), p.contents().size(), 0); e < 0) {
                return network::make_error(errno);
            }
            return std::nullopt;
        }

        std::optional<network::error> send(payload& p, std::string& host, std::string& port) {
            auto i = address_info(AF_UNSPEC, SOCK_DGRAM);

            if(auto e = i.resolve(host, port)) {
                return e;
            }

            if(int e = ::sendto(descriptor(), (char *)p.contents().data(), p.contents().size(), 0,
                                i.results()->ai_addr, i.results()->ai_addrlen); e < 0) {
                return network::make_error(errno);
            }

            return std::nullopt;
        }

        std::pair<int,std::optional<network::error>> receive(payload& p, const std::size_t &size) override {
            int count;
            p.contents().resize(size);

            if(count = ::recv(descriptor(), (char *)p.contents().data(), size, 0); count < 0) {
                return {count, network::make_error(errno)};
            }

            return {count, std::nullopt};
        }
    };

    class [[maybe_unused]] raw_socket : public generic_socket {
    public:
        [[maybe_unused]] explicit raw_socket(const int& family) : generic_socket(family, SOCK_RAW) {}
    };
}

#endif //NETWORK_H
