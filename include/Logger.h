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

	enum logtype { l_svr, l_wlist_yes, l_wlist_no, l_usr_no, l_usr_yes, l_usr_fail, l_disconn, l_disconSvr};

	void log(logtype l); //Server startup - timestamp of when server starts listening for clients
	void log(logtype l, std::string ip_addr); // log new connections not on whitelist (show IP)
	void log(logtype l, std::string ip_addr, std::string username); 

private:
	logtype l_status = l_svr;
	//FileFD _log_fileFD;
	std::string _log_file;
};

#endif