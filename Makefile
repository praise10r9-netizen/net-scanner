CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -O2

SOURCES = src/main.cpp src/scanner.cpp

netscan: $(SOURCES)
	$(CXX) $(CXXFLAGS) -Isrc $(SOURCES) -o $@

clean:
	rm -f netscan

.PHONY: clean
