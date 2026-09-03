#include "scanner.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

Scanner::Scanner(std::string ip) : target_ip(std::move(ip)) {}

std::vector<ScanResult> Scanner::scan(const std::vector<int>& ports, int timeout_ms) const
{
  std::vector<ScanResult> results;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* addresses = nullptr;
  const int lookup = getaddrinfo(target_ip.c_str(), nullptr, &hints, &addresses);
  if (lookup != 0)
  {
    for (int port : ports)
      results.push_back({port, "error", gai_strerror(lookup)});
    return results;
  }

  for (int port : ports)
  {
    sockaddr_in destination = *reinterpret_cast<sockaddr_in*>(addresses->ai_addr);
    destination.sin_port = htons(static_cast<uint16_t>(port));
    const int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
      results.push_back({port, "error", std::strerror(errno)});
      continue;
    }

    const int flags = fcntl(socket_fd, F_GETFL, 0);
    fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
    const int connection = connect(socket_fd, reinterpret_cast<sockaddr*>(&destination), sizeof(destination));
    if (connection == 0)
    {
      results.push_back({port, "open", "connection accepted"});
    }
    else if (errno == ECONNREFUSED)
    {
      results.push_back({port, "closed", "connection refused"});
    }
    else if (errno == EINPROGRESS)
    {
      pollfd descriptor{socket_fd, POLLOUT, 0};
      const int ready = poll(&descriptor, 1, timeout_ms);
      if (ready == 0)
        results.push_back({port, "filtered", "connection timed out"});
      else if (ready < 0)
        results.push_back({port, "error", std::strerror(errno)});
      else
      {
        int error = 0;
        socklen_t length = sizeof(error);
        getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &length);
        if (error == 0)
          results.push_back({port, "open", "connection accepted"});
        else if (error == ECONNREFUSED)
          results.push_back({port, "closed", "connection refused"});
        else
          results.push_back({port, "filtered", std::strerror(error)});
      }
    }
    else
    {
      results.push_back({port, "error", std::strerror(errno)});
    }
    close(socket_fd);
  }

  freeaddrinfo(addresses);
  return results;
}
