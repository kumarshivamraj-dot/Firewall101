#include "cli.h"

bool validate_parameter() {}

char *list_rules() {}

char *check(FILE *file, Firewall_Protocol proto, Firewall_Ipv4_Addr src_ip,
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
   */
  if ((file = fopen("rules.conf", "r")) == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }

  char rule_line_buffer[256];
  while (fgets(rule_line_buffer, 256, file) != NULL) {
  }
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
