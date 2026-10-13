#include "cli.h"

bool validate_parameter() {}

char *list_rules() {}

Decision check(FILE *file, Firewall_Protocol proto, Firewall_Ipv4_Addr src_ip,
               Firewall_Ipv4_Port src_port, Firewall_Ipv4_Addr dest_ip,
               Firewall_Ipv4_Port dest_port) {
  /*
   *firewall check \
      --rules rules.conf \
      --protocol tcp \
      --src-ip 10.0.0.1 \
      --src-port 50000 \
      --dest-ip 10.0.0.2 \
      --dest-port 443
      Returns Allow or Block
   */
  Decision decision;
  if (file == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }

  Rule rule_table[RuleTableSize];
  int rule_table_index = 0;

  char rule_line_buffer[256];
  char *line = NULL;

  Rule rule;
  while ((line = fgets(rule_line_buffer, 256, file)) != NULL) {
    // Parse the rule.conf file into rules struct

    char *seperator = " \t\n";
    char *token = strtok(line, seperator);

    int token_index = 0;
    if (token == NULL) {
      continue;
    }

    if (!strcmp(token, "#")) {
      continue;
    }

    while (token != NULL) {

      if (token_index == 0) {
        char *end;
        long value = strtol(token, &end, 10);
        if (*end == '\0' && value >= 1 && value <= 99) {
          printf("Valid: %ld\n", value);
        } else {
          printf("Invalid input\n");
        }

        rule.id = value;
      }

      else if (token_index == 1) {
        if (!strcmp(token, "enabled"))
          rule.enabled = true;
        else if (!strcmp(token, "disabled"))
          rule.enabled = false;
      }

      else if (token_index == 2) {
        Firewall_Action allow_action = Action_Allow;
        Firewall_Action block_action = Action_Block;
        if (!strcmp(token, "allow"))
          rule.action = allow_action;
        else if (!strcmp(token, "block"))
          rule.action = block_action;
      }

      else if (token_index == 3) {
        Firewall_Protocol Tcp_proto = Proto_Tcp;
        Firewall_Protocol Udp_proto = Proto_Udp;
        if (!strcmp(token, "tcp"))
          rule.proto = Tcp_proto;
        else if (!strcmp(token, "udp"))
          rule.enabled = Udp_proto;
      } else if (token_index == 4) {
        struct in_addr addr;
        if (inet_pton(AF_INET, token, &addr) < 0) {

          perror("inet_pton");
          exit(EXIT_FAILURE);
        }

        uint32_t src_addr = ntohl(addr.s_addr);
        rule.src = src_addr;
      }

      else if (token_index == 5) {
        // src port
        char *end;
        long value = strtol(token, &end, 10);
        if (*end == '\0' && value >= 0 && value <= 65535) {
          rule.src_port = (Firewall_Ipv4_Port)value;
        } else {
          printf("Invalid source port\n");
        }
      } else if (token_index == 6) {

        struct in_addr addr;
        if (inet_pton(AF_INET, token, &addr) < 0) {

          perror("inet_pton");
          exit(EXIT_FAILURE);
        }

        uint32_t dest_addr = ntohl(addr.s_addr);
        rule.dest = dest_addr;
      } else if (token_index == 7) {
        // dest port
        char *end;
        long value = strtol(token, &end, 10);
        if (*end == '\0' && value >= 0 && value <= 65535) {
          rule.dest_port = (Firewall_Ipv4_Port)value;
        } else {
          printf("Invalid destination port\n");
        }

        // Dynamically store these rules
      }
      rule_table_index++;
      token_index++;

      token = strtok(NULL, " \t\n");
    }
  }

  /* decision.action = rule.action;
  decision.rule = rule;
  decision.rule_id = rule.id; */

  return decision;
}

void print_version(bool hex) {

  if (hex) {
    int version = FIREWALL_VERSION;
    printf("%x", version);
  }

  printf("%d", FIREWALL_VERSION);
}

void print_help() {

  printf("%s",
         "Usage:-firewall check [packet options] [configuration options] \n"
         "firewall rules list \n"
         "firewall rules validate FILE \n"
         "firewall help \n"
         "firewall version \n");
}

int main(int argc, char **argv) {
  /*
    *firewall check [packet options] [configuration options]
    firewall rules list
    firewall rules validate FILE
    firewall help
    firewall version
  */

  Rule rule_table[RuleTableSize];

  if (argc < 2) {
    printf("%s",
           "Usage:-  firewall check [packet options] [configuration options] \n"
           "firewall rules list \n"
           "firewall rules validate FILE \n"
           "firewall help \n"
           "firewall version \n");

    return 1;
  }

  if (strcmp(argv[1], "version")) {
    print_version(true);
  } else if (strcmp(argv[1], "help")) {
    print_help();
  }
  return 0;
}
