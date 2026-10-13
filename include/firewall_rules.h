#ifndef FIREWALL_RULES
#define FIREWALL_RULES
#include "libraries.h"

// action needs to be specific either Block Allow Pass
#define RuleTableSize 1024
typedef enum firewall_action { Action_Allow, Action_Block } Firewall_Action;

typedef enum firewall_protocols {
  Proto_Tcp = 1 << 0,
  Proto_Udp = 1 << 1
} Firewall_Protocol;

typedef enum packet_direction {
  INCOMMING = 1 << 0,
  OUTGONNING = 1 << 1
} Direction;
typedef uint32_t Firewall_Ipv4_Addr;
typedef uint16_t Firewall_Ipv4_Port;

typedef struct firewall_rule {
  uint64_t id;
  bool enabled;
  Firewall_Action action;
  Firewall_Protocol proto;
  Firewall_Ipv4_Addr src;
  Firewall_Ipv4_Addr dest;
  Firewall_Ipv4_Port src_port;
  Firewall_Ipv4_Port dest_port;
} Rule;

typedef struct firewall_packet {
  Direction direct;
  Firewall_Protocol proto;
  Firewall_Ipv4_Addr src;
  Firewall_Ipv4_Addr dest;
  Firewall_Ipv4_Port src_port;
  Firewall_Ipv4_Port dest_port;

} Packet;

typedef struct firewall_decision {
  Firewall_Action action;
  uint64_t rule_id;
  Rule rule;

} Decision;

extern Rule rule_table[RuleTableSize];
extern int rule_table_index;

bool match_rule(const Packet *packets, const Rule *rules);
Decision evaluate_rule(const Packet *packets, const Rule *rules, int rule_count,
                       Firewall_Action *default_action);

#endif
