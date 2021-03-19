#include "dns.h"
#include "utils.h"
#include <iostream>
#include <string>
#include <sys/socket.h>

constexpr size_t DNS_REQ_MAX_SIZE = 0;

void dns::server(std::string bind_address, unsigned short port) {
  int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_socket == -1) {
    perror("Failed to create a UDP socket");
    return;
  }
  sockaddr_in addr;
  memset(&addr, 0, sizeof(sockaddr_in));
  addr.sin_port = htons(port);
  addr.sin_family = AF_INET;
  inet_pton(AF_INET, bind_address.c_str(), &addr.sin_addr.s_addr);
  if (bind(udp_socket, (sockaddr*)&addr, sizeof(addr)) == -1) {
    auto err_str = "Failed to bind to " + bind_address + ":" + std::to_string(port);
    perror(err_str.c_str());
    return;
  }
  socklen_t addrlen;
  sockaddr_in src_addr;
  constexpr size_t DNS_REQ_MAX_SIZE = 65535;
  char req_buf[DNS_REQ_MAX_SIZE];
  constexpr size_t dns_response_len = 512;
  char dns_response[dns_response_len];
  while (recvfrom(udp_socket, req_buf, DNS_REQ_MAX_SIZE, 0, (sockaddr*)&src_addr,
                  &addrlen)) {
    char *addr_str = inet_ntoa(src_addr.sin_addr);
    unsigned short src_port = ntohs(src_addr.sin_port);
    std::cout << "Receiving DNS packet from " << addr_str << ":" << src_port << std::endl;
    sendto(udp_socket, dns_response, dns_response_len, 0, (sockaddr*)&src_addr, sizeof(src_addr));
  }
}
