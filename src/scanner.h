#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>

struct ScanResult
{
	int port;
	std::string state;
	std::string detail;
};

class Scanner
{
private:
	std::string target_ip;
	
public:
	 explicit Scanner(std::string ip);
	
	std::vector<ScanResult> scan(const std::vector<int>& ports, int timeout_ms) const;
};

#endif
