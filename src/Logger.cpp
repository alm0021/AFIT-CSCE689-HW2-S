#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include <time.h>
#include "FileDesc.h"
#include "Logger.h"
#include <sstream> 

Logger::Logger(const char* log_file):_log_file(log_file) {

}

Logger::~Logger() {

}


/*******************************************************************************************
 * log - Logs
 *
 *    Throws: logfile_error if there were unanticipated problems opening the log file for
 *            reading
 *******************************************************************************************/
void Logger::log() {

	//Open log file for writing (append)
	FileFD logfile(_log_file.c_str());
	if (!logfile.openFile(FileFD::appendfd))
		throw logfile_error("Could not open log file for writing");

	std::string msg("Server Startup: "); //Log Message

	time_t rawtime;
	time(&rawtime);
	msg.append(ctime(&rawtime));

	logfile.writeFD(msg);
	logfile.closeFD();
}
void Logger::log(logstatus l, std::string ip_addr) {
	//Open log file for writing (append)
	FileFD logfile(_log_file.c_str());
	if (!logfile.openFile(FileFD::appendfd))
		throw logfile_error("Could not open log file for writing");

	std::string msg;
	if (l == l_wlist_no) { msg = "Blocked Client Connection - IP address not on whitelist: "; }
	else if(l == l_wlist_yes){msg = "Successful Client Connection - IP address on whitelist: " }
	msg.append(ip_addr);
	msg.append(" - ");
	time_t rawtime;
	time(&rawtime);
	msg.append(ctime(&rawtime));

	logfile.writeFD(msg);
	logfile.closeFD();
}

void Logger::log(logstatus l, std::string ip_addr, std::string username) { 
	//Open log file for writing (append)
	FileFD logfile(_log_file.c_str());
	if (!logfile.openFile(FileFD::appendfd))
		throw logfile_error("Could not open log file for writing");

	std::string msg;
	std::ostringstream ss;
	switch (l) {
		case l_usr_no:
			ss << "Unsuccessful User Login - Username Not Recognized - User:" << username
				<< " IP Address: " << ip_addr;
			break;
		
		case l_usr_yes:
			ss << "Successful User Login - Username Recognized - User:" << username
				<< " IP Address: " << ip_addr;
			break;
		
		case l_usr_fail:
			ss << "Unsuccessful User Login - Too May Password Attempts - User:" << username
				<< "IP Address: " << ip_addr;
			break;
		case l_disconn:
			ss << "User Disconnected - User:" << username << "IP Address: " << ip_addr;
			break;
		
	}

	//Get Time
	time_t rawtime;
	time(&rawtime);
	ss << " " << ctime(&rawtime);
	logfile.writeFD(ss.str());
	logfile.closeFD();
}