#include "scanner.h"
#include "scan_types/syn_scan.h"

Scanner::Scanner(std::string ip)
{
  target_ip = ip;
}

void Scanner::syn_scan(int port)
{
  SynScanner scanner(target_ip);
  scanner.scan(port);
}
