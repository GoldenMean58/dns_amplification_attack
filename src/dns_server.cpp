#include <iostream>
#include <sys/socket.h>
#include "my_utils.h"
#include "dns.h"

int main(int argc, char *argv[])
{
  std::string bind_address;
  unsigned short port = 53;
  std::cout << "DNS server bind address: ";
  do{
    std::cin >> bind_address;
  }while(utils::is_bad_ipv4_addr(bind_address) && std::cout << "Bad IPv4 address, please retry:");

  std::cout << "DNS server bind port:";
  do{
    std::cin >> port;
  }while(utils::is_bad_ipv4_port(port) && std::cout <<"Bad IPv4 port, please retry:");

  dns::server(bind_address, port);

  return 0;
}
