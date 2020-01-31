#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <stdexcept>
#include "FileDesc.h"

/****************************************************************************************
 * Logger - 	Logs events to a file called server.log with a time/date 
 *              timestamp to the second. 
 *
 ****************************************************************************************/

class Logger {
public:
	Logger(const char *log_file);
	~Logger();

	//enumerated types to represent conditions to log events
	enum logtype { l_svr, l_wlist_yes, l_wlist_no, l_usr_no, l_usr_yes, l_usr_fail, l_disconn, l_disconSvr};

	void log(logtype l); //Server startup - timestamp of when server starts listening for clients
	void log(logtype l, std::string ip_addr); // overloaded log function
	void log(logtype l, std::string ip_addr, std::string username); // overloaded log function

private:
	logtype l_status = l_svr;
	std::string _log_file;
};

#endif