#ifndef UTILS_H
#define UTILS_H
#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <tuple>

#include <arpa/inet.h> // inet_ntoa, inet_addr
#include <cstdlib>
#include <cstring>      // For memcpy()
#include <netinet/in.h> // IPPROTO_UDP
#include <netinet/ip.h> // struct ip
#include <netinet/udp.h>
#include <sys/socket.h>

namespace utils {
unsigned short checksum(void *addr, int len);
class IP {
  struct ip ip;

public:
  IP();
  IP(const char *src_addr, const char *dst_addr);
  void set_header_len(int hl);
  void set_len(int len);
  unsigned short get_len();
  struct ip *get_addr();
  void set_id(int id);
  void set_offset(int offset);
  void set_ttl(int ttl);
  void set_proto(int p);
  void set_sum(unsigned short sum);
};

struct PseudoIPHeader {
  int32_t src_ipv4_address;
  int32_t dst_ipv4_address;
  char zeroes;
  char protocol;
  int16_t udp_length;
  PseudoIPHeader(std::string src_addr, std::string dst_addr, int16_t udp_length)
      : zeroes(0), protocol(IPPROTO_UDP), udp_length(udp_length) {
    inet_pton(AF_INET, src_addr.c_str(), &src_ipv4_address);
    inet_pton(AF_INET, dst_addr.c_str(), &dst_ipv4_address);
  }
};
class UDP {
  struct udphdr header;
  void *data;
  uint16_t data_len;

public:
  void set_port(unsigned short src_port, unsigned short dst_port);
  void set_data(void *data, uint16_t data_len);
  std::tuple<char*, size_t> gen_udp_packet(std::string src_addr, std::string dst_addr);
};

struct DNSReqHeader {
  uint16_t identification;
  uint16_t header_flags;
  uint16_t questions_num;
  uint16_t answers_num;
  uint16_t autho_answers_num;
  uint16_t additional_num;
  DNSReqHeader(uint16_t identification, uint16_t header_flags, uint16_t questions_num):identification(htons(identification)), header_flags(htons(header_flags)), questions_num(htons(questions_num)), answers_num(0), autho_answers_num(0), additional_num(0) {}
};

enum class DNSQueryType : int16_t { A = 1, NS = 2, CNAME = 5, MX = 15, TXT = 16 , AAAA = 28};

const bool is_bad_ipv4_addr(std::string address);
const bool is_bad_ipv4_port(unsigned short port);
std::tuple<char*, size_t> gen_question_from_domain_names(std::vector<std::string> domain_str, std::vector<DNSQueryType> query_type);
void spoof_dns(std::string source_spoof_ip_str, std::string dns_server_ip_str,
               unsigned short dns_server_port, std::vector<std::string> domain_strings,
               std::vector<DNSQueryType> query_types);
std::tuple<char*, size_t> gen_answer();
} // namespace utils

#endif
