#include "firewall_rules.h"
#include <assert.h>
#include <stdio.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RESET "\033[0m"

typedef void (*Test_Function)(void);

static void run_test(const char *name, Test_Function test) {
  test();
  printf(COLOR_GREEN "✓ %s passed" COLOR_RESET "\n", name);
}

static Packet make_packet(void) {
  return (Packet){
      .direct = INCOMMING,
      .proto = Proto_Tcp,
      .src = 0x0a000001u,
      .dest = 0x0a000002u,
      .src_port = 50000,
      .dest_port = 443,
  };
}

static Rule make_rule(uint64_t id, bool enabled) {
  return (Rule){

      .id = id,
      .enabled = enabled,
      .action = Action_Allow,
      .proto = Proto_Tcp,
      .src = 0x0a000001u,
      .dest = 0x0a000002u,
      .src_port = 50000,
      .dest_port = 443,
  };
}
static void test_matching_rule_matches(void) {
  Packet packet = make_packet();

  Rule rule = make_rule(999, true);

  bool match = match_rule(&packet, &rule);
  assert(match == true);
}
static void test_disabled_rule_does_not_match(void) {

  Packet packet = make_packet();
  Rule rule = make_rule(998, false);
  assert(match_rule(&packet, &rule) == false);
}
static void test_different_port_does_not_match(void) {

  Packet packet = make_packet();
  packet.src_port = 999;
  Rule rule = make_rule(999, true);
  assert(match_rule(&packet, &rule) == false);
}
static void test_protocol_mask_matches_tcp(void) {
  Packet packet = make_packet();
  Rule rule = make_rule(999, true);
  packet.proto = Proto_Tcp;
  rule.proto = Proto_Tcp | Proto_Udp;
  assert(match_rule(&packet, &rule) == true);
}
static void test_later_rule_can_match(void) {
  Packet packet = make_packet();
  Rule rules[] = {
      make_rule(1, true),
      make_rule(2, true),
  };

  rules[0].dest_port = 80;
  rules[1].action = Action_Allow;

  Firewall_Action default_action = Action_Block;
  Decision decision = evaluate_rule(&packet, rules, 2, &default_action);

  assert(decision.rule_id == 2);
  assert(decision.action == Action_Allow);
}

static void test_first_matching_rule_wins(void) {
  Packet packet = make_packet();
  Rule rules[] = {
      make_rule(1, true),
      make_rule(2, true),
  };

  rules[0].action = Action_Block;
  rules[1].action = Action_Allow;

  Firewall_Action default_action = Action_Allow;
  Decision decision = evaluate_rule(&packet, rules, 2, &default_action);

  assert(decision.rule_id == 1);
  assert(decision.action == Action_Block);
}

static void test_default_action_when_nothing_matches(void) {
  Packet packet = make_packet();
  Rule rule = make_rule(1, true);
  rule.dest_port = 80;

  Firewall_Action default_action = Action_Block;
  Decision decision = evaluate_rule(&packet, &rule, 1, &default_action);

  assert(decision.rule_id == 0);
  assert(decision.action == Action_Block);
  assert(decision.rule.enabled == false);
}

int main(void) {
  run_test("matching rule matches", test_matching_rule_matches);
  run_test("disabled rule does not match",
           test_disabled_rule_does_not_match);
  run_test("different port does not match",
           test_different_port_does_not_match);
  run_test("protocol mask matches TCP", test_protocol_mask_matches_tcp);
  run_test("later rule can match", test_later_rule_can_match);
  run_test("first matching rule wins", test_first_matching_rule_wins);
  run_test("default action when nothing matches",
           test_default_action_when_nothing_matches);

  printf(COLOR_GREEN "✓ All firewall rule tests passed." COLOR_RESET "\n");

  return 0;
}
