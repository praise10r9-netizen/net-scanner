#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include "scanner.h"

static std::vector<int> parse_ports(const std::string& input)
{
  std::vector<int> ports;
  std::stringstream values(input);
  std::string item;
  while (std::getline(values, item, ','))
  {
    if (item.empty())
      throw std::invalid_argument("port list contains an empty item");
    const auto separator = item.find('-');
    const int first = std::stoi(item.substr(0, separator));
    const int last = separator == std::string::npos ? first : std::stoi(item.substr(separator + 1));
    if (first < 1 || last > 65535 || first > last)
      throw std::invalid_argument("ports must be between 1 and 65535");
    for (int port = first; port <= last; ++port)
      ports.push_back(port);
  }
  if (ports.empty())
    throw std::invalid_argument("at least one port is required");
  return ports;
}

static void print_json(const std::string& target, const std::vector<ScanResult>& results)
{
  std::cout << "{\"target\":\"" << target << "\",\"results\":[";
  for (size_t index = 0; index < results.size(); ++index)
  {
    const auto& result = results[index];
    if (index > 0) std::cout << ',';
    std::cout << "{\"port\":" << result.port << ",\"state\":\"" << result.state
      << "\",\"detail\":\"" << result.detail << "\"}";
  }
  std::cout << "]}\n";
}

int main(int argc, char* argv[])
{
  if (argc < 3 || argc > 5)
  {
    std::cerr << "Usage: ./netscan <target> <port[,port]|start-end> [timeout_ms] [--json]\n";
    return 2;
  }
  try
  {
    const std::string target = argv[1];
    const std::vector<int> ports = parse_ports(argv[2]);
    const int timeout_ms = argc >= 4 && std::string(argv[3]) != "--json" ? std::stoi(argv[3]) : 1000;
    const bool json = std::string(argv[argc - 1]) == "--json";
    if (timeout_ms < 50 || timeout_ms > 60000)
      throw std::invalid_argument("timeout must be between 50 and 60000 ms");
    Scanner scanner(target);
    const auto results = scanner.scan(ports, timeout_ms);
    if (json)
      print_json(target, results);
    else
    {
      for (const auto& result : results)
        std::cout << target << ':' << result.port << ' ' << result.state << " - " << result.detail << '\n';
    }
    return 0;
  }
  catch (const std::exception& error)
  {
    std::cerr << "Input error: " << error.what() << '\n';
    return 2;
  }
}
