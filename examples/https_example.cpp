//
// Created by sigma on 1/14/2021.
//

#include <iostream>
#include <network.h>

int main() {
    network::tls_socket client;
    network::payload request("OPTIONS / HTTP/1.0\r\n\r\n");
    network::payload response;
    network::payload buffer;
    std::string body;

    if(auto e = client.connect("www.google.com", "80")) {
        e->display();
        return 1;
    }

    if(auto e = client.send(request)) {
        e->display();
        return 1;
    }

    for(;;) {
        const auto& [count, e] = client.receive(buffer, 1024);

        if(e) {
            e->display();
            return 1;
        }

        if(count == 0) {
            break;
        }

        if(auto e = response.write(buffer)) {
            e->display();
            return 1;
        }
    }

    if(auto e = response.read(body, response.contents().size())) {
        e->display();
        return 1;
    }

    std::cout << body << std::endl;
}