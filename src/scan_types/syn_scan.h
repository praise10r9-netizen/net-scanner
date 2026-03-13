#ifndef SYS_SCAN_H
#define SYS_SCAN_H

#include <string>

class SynScanner
{
  private:
  	std::string target_ip;
  	
  public:
  	SynScanner(std::string ip);
  	void scan(int port);
};

#endif
