#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <strings.h>
#include <vector>
#include <iostream>
#include <memory>
#include <sstream>
#include "TCPServer.h"
#include "Logger.h"

const char logfilename[] = "server.log";
static std::unique_ptr<Logger> _log = std::make_unique<Logger>(logfilename);

TCPServer::TCPServer(){ // :_server_log("server.log", 0) {
}

TCPServer::~TCPServer() {

}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/
void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) {

   struct sockaddr_in servaddr;

   // _server_log.writeLog("Server started.");

   // Set the socket to nonblocking
   _sockfd.setNonBlocking();

   // Load the socket information to prep for binding
   _sockfd.bindFD(ip_addr, port);
 
}

/**********************************************************************************************
 * listenSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *             them. Also loops through the list of connections and handles data received and
 *             sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/
void TCPServer::listenSvr() {

   bool online = true;
   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;
   int num_read = 0;

   // Start the server socket listening
   _sockfd.listenFD(5);
   _log->log(Logger::l_svr); //Log server startup
    
   while (online) {
      struct sockaddr_in cliaddr;
      socklen_t len = sizeof(cliaddr);

      if (_sockfd.hasData()) {
         TCPConn *new_conn = new TCPConn();
         if (!new_conn->accept(_sockfd)) {
            // _server_log.strerrLog("Data received on socket but failed to accept.");
            continue;
         }
         std::cout << "***Got a connection***\n";

         _connlist.push_back(std::unique_ptr<TCPConn>(new_conn));

         // Get their IP Address string to use in logging
         std::string ipaddr_str;
         new_conn->getIPAddrStr(ipaddr_str);

		 //TESTING: Display IP Address*********
		 std::cout << "IP Address is: " << ipaddr_str << std::endl;
		 //Check if IP Address is on whitelist
		 if (!new_conn->whitelisted(ipaddr_str)) {
			 std::cout << "IP address not on whitelist!\n";
			 _log->log(Logger::l_wlist_no, ipaddr_str); //Log IP not on whitelist
			 //Disconnect and remove them from the connect list
			 new_conn->disconnect();
			 _connlist.pop_back();
			 std::cout << "Connection disconnected.\n";
			 continue;
		 }

         new_conn->sendText("Welcome to the CSCE 689 Server!\n");
		 _log->log(Logger::l_wlist_yes, ipaddr_str); //Log IP on whitelist

         // Change this later
         new_conn->startAuthentication();
      }

      // Loop through our connections, handling them
      std::list<std::unique_ptr<TCPConn>>::iterator tptr = _connlist.begin();
      while (tptr != _connlist.end())
      {
         // If the user lost connection
         if (!(*tptr)->isConnected()) {
            // Log it

            // Remove them from the connect list
            tptr = _connlist.erase(tptr);
            std::cout << "Connection disconnected.\n";
            continue;
         }

         // Process any user inputs
         (*tptr)->handleConnection();

         // Increment our iterator
         tptr++;
      }

      // So we're not chewing up CPU cycles unnecessarily
      nanosleep(&sleeptime, NULL);
   } 


   
}


/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::shutdown() {
	_log->log(Logger::l_disconSvr); //Log Server Shutdown
   _sockfd.closeFD();
}


