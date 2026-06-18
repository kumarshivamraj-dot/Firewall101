#include "libraries.h"

// action needs to be specific either Block Allow Pass
#define RuleTableSize 1024
typedef enum firewall_action {
  Action_Allow,
  Action_Block,
  Action_Pass
} Firewall_Action;

typedef enum firewall_protocols { Proto_Tcp, Proto_Udp } Firewall_Protocol;

typedef enum packet_direction { INCOMMING, OUTGONNING } Direction;
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

// Functions

bool match_rule(Packet *, Rule *);
Decision evaluate_rule(Packet *, Rule[RuleTableSize]);
