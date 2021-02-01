//
// Created by sigma on 1/7/2021.
//

#ifndef NETWORK_H
#define NETWORK_H

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
        IPV4 = AF_INET,
        IPV6 = AF_INET6,
    };

    enum protocol {
        ICMP   = IPPROTO_ICMP,
        ICMPV6 = IPPROTO_ICMPV6,
        IGMP   = IPPROTO_IGMP,
        TCP    = IPPROTO_TCP,
        UDP    = IPPROTO_UDP,
    };

    enum ssl_context_type {
        SSL_CLIENT,
        SSL_SERVER,
    };

    enum ssl_version {
        SSLV2,
        SSLV3,
        TLS1_1,
        TLS1_2,
        TLS1_3,
    };

    constexpr endian platform_endianness() {
        return std::endian::native == std::endian::big ? BIG : LITTLE;
    }

    inline void init() {
#ifdef WINDOWS
        WSAData output;
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

        std::optional<int> protocol() {
            if(!this->i) {
                return std::nullopt;
            }

            return this->i->ai_protocol;
        }

        std::optional<int> socket_type() {
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

        explicit address_info(struct addrinfo *address) :
                hint(),
                result(address) {
            memset(&hint, 0, sizeof(hint));

            hint.ai_family = AF_UNSPEC;
            hint.ai_socktype = SOCK_STREAM;
            hint.ai_flags = AI_PASSIVE;
        }

        explicit address_info(const int family) :
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

        address_info(const int family, const int socktype, const int protocol, const int flags) :
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

        explicit payload(endian e) :
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
            }
        }

        friend payload operator+(payload& a, payload& b) {
            auto p = payload();
            p.write(a);
            p.write(b);
            return p;
        }

        std::vector<std::uint8_t>& contents(){ return data; }
        std::size_t index() { return position; }
        std::size_t remaining() { return (data.size() - position) + 1;}
        void reset() { contents().clear(); position = 0; }

        std::optional<network::error> write(std::string& input) {
            for(const auto& c : input) {
                data.push_back(c);
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::vector<std::uint8_t>& input) {
            for(const auto& c : input) {
                data.push_back(c);
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::uint8_t& byte) {
            data.push_back(byte);
            return std::nullopt;
        }

        std::optional<network::error> write(std::int8_t& byte) {
            data.push_back(byte);
            return std::nullopt;
        }
        std::optional<network::error> write(std::uint16_t value, const endian e) {
            if(platform_endianness() != e) {
                data.push_back((value & 0xFF00) >> 8);
                data.push_back((value & 0x00FF) >> 0);
            } else {
                data.push_back((value & 0x00FF) >> 0);
                data.push_back((value & 0xFF00) >> 8);
            }

            return std::nullopt;
        }

        std::optional<network::error> write(std::uint16_t& value) {
            if(auto e = write(value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::int16_t& value, const endian endianness) {
            if(auto e = write((std::uint16_t)value, endianness)) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::int16_t& value) {
            if(auto e = write(value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::uint32_t& value, const endian e) {
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
            return std::nullopt;
        }

        std::optional<network::error> write(std::uint32_t& value) {
            if(auto e = write(value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::int32_t& value, const endian endianness) {
            if(auto e = write((std::uint32_t&)value, endianness)) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::int32_t& value) {
            if(auto e = write(value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::uint64_t& value, const endian e) {
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
            return std::nullopt;
        }

        std::optional<network::error> write(std::uint64_t& value) {
            if(auto e = write((std::uint64_t&)value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::int64_t& value, const endian endianness) {
            if(auto e = write((std::uint64_t)value, endianness)) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(std::int64_t& value) {
            if(auto e = write(value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> write(payload& value) {
            for(const auto& c : value.contents()) {
                data.push_back(c);
            }
            return std::nullopt;
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

        std::optional<network::error> read(std::uint8_t& value) {
            if(position + 1 > data.size()) {
                return network::error("end of payload");
            }

            value = data[position];
            position++;

            return std::nullopt;
        }

        std::optional<network::error> read(std::int8_t& value) {
            if(auto e = read((std::uint8_t&)value)) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> read(std::uint16_t& value, const endian endianness) {
            if(position + 2 > data.size()) {
                return network::error("end of payload");
            }

            value = 0;

            if(platform_endianness() != endianness) {
                value = data[position + 1] << 0 |
                        data[position]     << 8;
            } else {
                    value = data[position]   << 0 |
                            data[position+1] << 8;
            }

            position += 2;
            return std::nullopt;
        }

        std::optional<network::error> read(std::int16_t& value, const endian endianness) {
            if(auto e = read((std::uint16_t&)value, endianness)) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> read(std::uint16_t& value) {
            if(auto e = read(value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> read(std::uint32_t& value, const endian endianness) {
            if(position + 4  > data.size()) {
                return network::error("end of payload");
            }

            value = 0;

            if(platform_endianness() != endianness) {
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
            return std::nullopt;
        }

        std::optional<network::error> read(std::int32_t& value, const endian endianness) {
            if(auto e = read((std::uint32_t&)value, endianness)) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> read(std::uint32_t& value) {
            if(auto e = read(value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> read(std::uint64_t& value, const endian endianness) {
            if(position + 8  > data.size()) {
                return network::error("end of payload");
            }

            value = (unsigned long)0;

            if(platform_endianness() != endianness) {
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

            return std::nullopt;
        }

        std::optional<network::error> read(std::int64_t& value, const endian endianness) {
            if(auto e = read((std::uint64_t&)value, endianness)) {
                return e;
            }
            return std::nullopt;
        }

        std::optional<network::error> read(std::uint64_t& value) {
            if(auto e = read(value, platform_endianness())) {
                return e;
            }
            return std::nullopt;
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
    private:
        int d;
        address_info i;

        std::optional<network::error> read_buffer() { return std::nullopt; }

    public:
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

        std::optional<network::error> connect(const std::string& hostname, const std::string& port) {
            if(auto e = i.resolve(hostname, port)) {
                return e;
            }

            auto record = i.results();
            if(auto s = socket(record->ai_family, record->ai_socktype, record->ai_protocol); s < 0) {
                return network::error(strerror(errno));
            } else {
                set_descriptor(s);
            }

            if(auto e = ::connect(descriptor(), record->ai_addr, record->ai_addrlen); e < 0) {
                return network::error(strerror(errno));
            }

            return std::nullopt;
        }

        std::optional<network::error> bind() {
            if(auto e = ::bind(d, i.results()->ai_addr, i.results()->ai_addrlen); e < 0) {
                return network::error(strerror(errno));
            }
            return std::nullopt;
        }

        std::optional<network::error> listen(const int& backlog)  {
            if(auto e = ::listen(d, backlog); e < 0) {
                return network::error(strerror(errno));
            }
            return std::nullopt;
        }
    };

    class tcp_socket : public generic_socket {
    public:
        tcp_socket() : generic_socket(AF_UNSPEC, SOCK_STREAM) {}
        explicit tcp_socket(int family) : generic_socket(family, SOCK_STREAM) {}

        std::optional<network::error> send(payload& p) override {
            if(int e = ::send(descriptor(), (char *)p.contents().data(), p.contents().size(), 0); e < 0) {
                return network::error(strerror(errno));
            }
            return std::nullopt;
        }

        std::pair<int,std::optional<network::error>> receive(payload& p, const std::size_t& size) override {
            int count = 0;
            p.contents().resize(size);

            if(count = ::recv(descriptor(), (char *)p.contents().data(), size, 0); count < 0) {
                return {count, network::error(strerror(errno)) };
            }

            return {count, std::nullopt};
        }
    };

    class udp_socket : public generic_socket {
    public:
        udp_socket() : generic_socket(AF_UNSPEC, SOCK_DGRAM) {}
        explicit udp_socket(int family) : generic_socket(family, SOCK_DGRAM) {}

        std::optional<network::error> send(payload& p) override {
            if(int e = ::send(descriptor(), (char *)p.contents().data(), p.contents().size(), 0); e < 0) {
                return network::error(strerror(errno));
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
                return network::error(strerror(errno));
            }

            return std::nullopt;
        }

        std::pair<int,std::optional<network::error>> receive(payload& p, const std::size_t &size) override {
            int count = 0;
            p.contents().resize(size);

            if(count = ::recv(descriptor(), (char *)p.contents().data(), size, 0); count < 0) {
                return {count, network::error(strerror(errno))};
            }

            return {count, std::nullopt};
        }
    };

    class raw_socket : public generic_socket {
    public:
        explicit raw_socket(int family) : generic_socket(family, SOCK_RAW) {}
    };
}

#endif //NETWORK_H
