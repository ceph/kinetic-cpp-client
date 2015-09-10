/*
 * kinetic-cpp-client
 * Copyright (C) 2014 Seagate Technology.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string>
#include <exception>
#include <stdexcept>
#include "glog/logging.h"
#include "socket_wrapper.h"
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>

#define MAXHOSTLEN 256
#define UNIX_PATH "/etc/kvdaemon/unix_socket"

namespace kinetic {

using std::string;

SocketWrapper::SocketWrapper(const std::string& host, int port, bool use_ssl, bool nonblocking)
        : ctx_(nullptr), ssl_(nullptr), host_(host), port_(port), nonblocking_(nonblocking), fd_(-1) {
    use_unix_domain_ = IsLocalhost();
    if (!use_ssl) return;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ctx_ = SSL_CTX_new(SSLv23_client_method());
    ssl_ = SSL_new(ctx_);
    if (!ssl_ || !ctx_)
        throw std::runtime_error("Failed Setting up SSL environment.");
    SSL_set_mode(ssl_, SSL_MODE_AUTO_RETRY);
}

SocketWrapper::~SocketWrapper() {
    if (fd_ == -1) {
        LOG(INFO) << "Not connected so no cleanup needed";
    } else {
        LOG(INFO) << "Closing socket with fd " << fd_;
        if (close(fd_)) {
            PLOG(ERROR) << "Error closing socket fd " << fd_;
        }
    }
    if (ssl_) SSL_free(ssl_);
    if (ctx_) SSL_CTX_free(ctx_);
}

bool SocketWrapper::IsLocalhost() {
    // localhost?
    if(host_ == "localhost" || host_ == "127.0.0.1") {
      return true;
    }

    // get hostname of local machine
    char hostname[MAXHOSTLEN];
    if(gethostname(hostname, MAXHOSTLEN) < 0) {
      perror("gethostname");
      exit(EXIT_FAILURE);
    }
    string str_hostname = hostname;
    if(host_ == str_hostname) {
      return true;
    }

    // could be inet or inet6
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;

    // get ip addr of local machine
    struct addrinfo* result;
    string port_str = std::to_string(port_);
    if (getaddrinfo(hostname, port_str.c_str(), &hints, &result) != 0) {
      // if getaddrinfo failed, no kinetic server process on local machine
      return false;
    }

    // check host_ address is equal to local machine address
    struct addrinfo* ai;
    for(ai = result; ai != NULL; ai = ai->ai_next) {
      void* buf;
      switch(ai->ai_addr->sa_family) {
      case AF_INET:
	buf = &((struct sockaddr_in *) ai->ai_addr)->sin_addr;
	break;
      case AF_INET6:
	buf = &((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr;
	break;
      }
      char inetaddr[INET6_ADDRSTRLEN];
      if(inet_ntop(ai->ai_addr->sa_family, buf, inetaddr, INET6_ADDRSTRLEN) == NULL) {
	perror("inet_ntop");
	exit(EXIT_FAILURE);
      }
      string str_inetaddr = inetaddr;
      if(host_ == str_inetaddr) {
	break;
      }
    }

    freeaddrinfo(result);
    
    if(ai != NULL) return true;
    return false;
}
  
bool SocketWrapper::Connect() {
    LOG(INFO) << "Connecting to " << host_ << ":" << port_;

    int socket_fd;
    if(use_unix_domain_) {
      struct sockaddr_un my_addr;
      memset(&my_addr, 0, sizeof(struct sockaddr_un));
      socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
      
      if(socket_fd == -1) {
	LOG(ERROR) << "Could not create UNIX domain socket";
	return false;
      }

      // use UNIX domain
      my_addr.sun_family = AF_UNIX;
      strncpy(my_addr.sun_path, UNIX_PATH, sizeof(my_addr.sun_path) - 1);
      
      // os x won't let us set close-on-exec when creating the socket, so set it separately
      int current_fd_flags = fcntl(socket_fd, F_GETFD);
      if (current_fd_flags == -1) {
	PLOG(ERROR) << "Failed to get socket fd flags in UNIX domain";
	close(socket_fd);
	return false;
      }
      if (fcntl(socket_fd, F_SETFD, current_fd_flags | FD_CLOEXEC) == -1) {
	PLOG(ERROR) << "Failed to set socket close-on-exit in UNIX domain";
	close(socket_fd);
	return false;
      }
      
      // On BSD-like systems we can set SO_NOSIGPIPE on the socket to prevent it from sending a
      // PIPE signal and bringing down the whole application if the server closes the socket
      // forcibly
#ifdef SO_NOSIGPIPE
      int set = 1;
      int setsockopt_result = setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
      // Allow ENOTSOCK because it allows tests to use pipes instead of real sockets
      if (setsockopt_result != 0 && setsockopt_result != ENOTSOCK) {
	PLOG(ERROR) << "Failed to set SO_NOSIGPIPE on socket";
	close(socket_fd);
	continue;
      }
#endif
      
      if (connect(socket_fd, (struct sockaddr*)&my_addr, sizeof(struct sockaddr_un)) == -1) {
        PLOG(ERROR) << "Unable to connect in UNIX domain";
	close(socket_fd);
	return false;
      }
      
      if (nonblocking_ && fcntl(socket_fd, F_SETFL, O_NONBLOCK) != 0) {
        PLOG(ERROR) << "Failed to set socket nonblocking in UNIX domain";
        close(socket_fd);
	return false;
      }
    }
    // Use INET domain
    else {
      struct addrinfo hints;
      memset(&hints, 0, sizeof(struct addrinfo));

      // could be inet or inet6
      hints.ai_family = PF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      hints.ai_flags = AI_NUMERICSERV;

      struct addrinfo* result;

      string port_str = std::to_string(port_);
      
      if (int res = getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &result) != 0) {
        LOG(ERROR) << "Could not resolve host " << host_ << " port " << port_ << ": "
		   << gai_strerror(res);
        return false;
      }

      struct addrinfo* ai;
      for (ai = result; ai != NULL; ai = ai->ai_next) {
        char host[NI_MAXHOST];
        char service[NI_MAXSERV];
        if (int res = getnameinfo(ai->ai_addr, ai->ai_addrlen, host, sizeof(host), service,
                sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
	  LOG(ERROR) << "Could not get name info: " << gai_strerror(res);
	  continue;
        } else {
	  LOG(INFO) << "Trying to connect to " << string(host) << " on " << string(service);
        }
	
        socket_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	
        if (socket_fd == -1) {
	  LOG(WARNING) << "Could not create socket";
	  continue;
        }
	
        // os x won't let us set close-on-exec when creating the socket, so set it separately
        int current_fd_flags = fcntl(socket_fd, F_GETFD);
        if (current_fd_flags == -1) {
	  PLOG(ERROR) << "Failed to get socket fd flags";
	  close(socket_fd);
	  continue;
        }
        if (fcntl(socket_fd, F_SETFD, current_fd_flags | FD_CLOEXEC) == -1) {
	  PLOG(ERROR) << "Failed to set socket close-on-exit";
	  close(socket_fd);
	  continue;
        }

        // On BSD-like systems we can set SO_NOSIGPIPE on the socket to prevent it from sending a
        // PIPE signal and bringing down the whole application if the server closes the socket
        // forcibly
#ifdef SO_NOSIGPIPE
        int set = 1;
        int setsockopt_result = setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
        // Allow ENOTSOCK because it allows tests to use pipes instead of real sockets
        if (setsockopt_result != 0 && setsockopt_result != ENOTSOCK) {
	  PLOG(ERROR) << "Failed to set SO_NOSIGPIPE on socket";
	  close(socket_fd);
	  continue;
        }
#endif

        if (connect(socket_fd, ai->ai_addr, ai->ai_addrlen) == -1) {
	  PLOG(WARNING) << "Unable to connect";
	  close(socket_fd);
	  continue;
        }

        if (nonblocking_ && fcntl(socket_fd, F_SETFL, O_NONBLOCK) != 0) {
	  PLOG(ERROR) << "Failed to set socket nonblocking";
	  close(socket_fd);
	  continue;
        }

        break;
      }

      freeaddrinfo(result);

      if (ai == NULL) {
        // we went through all addresses without finding one we could bind to
        LOG(ERROR) << "Could not connect to " << host_ << " on port " << port_;
        return false;
      }
    }
    
    fd_ = socket_fd;
    if (ssl_) return ConnectSSL();
    return true;
}

#include <openssl/err.h>

bool SocketWrapper::ConnectSSL() {
    SSL_set_fd(ssl_, fd_);
    int rtn = SSL_connect(ssl_);
    if (rtn == 1)
        return true;

    int err = SSL_get_error(ssl_, rtn);
    if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds); FD_ZERO(&write_fds);
        if (err == SSL_ERROR_WANT_READ)  FD_SET(fd_, &read_fds);
        if (err == SSL_ERROR_WANT_WRITE) FD_SET(fd_, &write_fds);
        struct timeval tv = {1, 1};
        select(fd_+1, &read_fds, &write_fds, NULL, &tv);
        return ConnectSSL();
    }
    return false;
}

SSL * SocketWrapper::getSSL() {
    return ssl_;
}

int SocketWrapper::fd() {
    return fd_;
}

}  // namespace kinetic
