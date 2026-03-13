#ifndef SCANNER_H
#define SCANNER_H

#include <string>

class Scanner
{
private:
	std::string target_ip;
	
public:
	Scanner(std::string ip);
	
	void syn_scan(int port);
};

#endif
