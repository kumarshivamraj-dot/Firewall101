#include "firewall_rules.h"

Firewall_Protocol TcpProtocol = Proto_Tcp;

Firewall_Protocol UdpProtocol = Proto_Udp;

bool match_rule(const Packet *packets, const Rule *rules) {

  bool match = false;
  if (packets == NULL || rules == NULL) {
    return false;
  }
  if (rules->enabled == false) {
    return false;
  }
  if (packets->proto & rules->proto) {
    if (packets->src == rules->src) {
      if (packets->src_port == rules->src_port) {
        if (packets->dest == rules->dest) {
          if (packets->dest_port == rules->dest_port) {
            match = true;
          }
        }
      }
    }
  }

  return match;
}

Decision evaluate_rule(const Packet *packets, const Rule *rules, int rule_count,
                       Firewall_Action *default_action) {
  bool is_default = false;

  Rule default_rule = {
      .id = 0,
      .enabled = false,
      .action = *default_action,
      .proto = TcpProtocol | UdpProtocol,
      .src = 0,
      .dest = 0,
      .src_port = 0,
      .dest_port = 0,
  };

  Decision Default_Decisions = {
      .action = *default_action, .rule_id = 0, .rule = default_rule};
  Decision des = {0}; // Returning by value from the stack and is safe
  for (int i = 0; i < rule_count; i++) {
    bool match = match_rule(packets, &rules[i]);
    if (match == true) {
      des.action = rules[i].action;
      des.rule_id = rules[i].id;
      des.rule = rules[i];
      is_default = true;
      break;
    }
  }

  if (is_default == false) {
    return Default_Decisions;
  } else {
    return des;
  }
}
