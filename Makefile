CC ?= cc
FLAGS = -std=c11 -Wall -Wextra -Wpedantic -Iinclude
VERSION:=1.1.1
FLAGS+=-DFIREWALL_VERSION=\"$(VERSION)\"
HEADERS = include/firewall_rules.h include/libraries.h

FIREWALL_RULES = src/core/firewall_rules.c
FIREWALL_TEST_SOURCE = tests/tests_firewall_rules.c
FIREWALL_TESTS = build/tests_firewall_rules


.PHONY: all test clean

all: build/firewall_rule.o


build:
	mkdir -p build


build/firewall_rule.o: $(FIREWALL_RULES) $(HEADERS) | build
	$(CC) $(FLAGS) -c $(FIREWALL_RULES) -o $@


$(FIREWALL_TESTS): $(FIREWALL_TEST_SOURCE) $(FIREWALL_RULES) $(HEADERS) | build
	$(CC) $(FLAGS) $(FIREWALL_TEST_SOURCE) $(FIREWALL_RULES) -o $@


test: $(FIREWALL_TESTS)
	./$(FIREWALL_TESTS)


clean:
	rm -rf build
