#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iostream>
#include <memory>
#include "TCPConn.h"
#include "strfuncts.h"
#include "Logger.h"

// The filename/path of the password file
const char pwdfilename[] = "passwd";
const char logfilename[] = "server.log";
static std::unique_ptr<PasswdMgr> _pwd = std::make_unique<PasswdMgr>(pwdfilename);
static std::unique_ptr<Logger> _log = std::make_unique<Logger>(logfilename);

TCPConn::TCPConn() { // LogMgr &server_log):_server_log(server_log) {
}

TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {

   // Skipping this for now
   _status = s_username;

   _connfd.writeFD("Username: "); 
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   try {
      switch (_status) {
         case s_username:
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu:
            getMenuChoice();
            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.";
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
   // Insert your mind-blowing code here

	if (!_connfd.hasData())
		return;
	std::string userName;
	if (!getUserInput(userName))
		return;
	_username = userName;
	std::cout << "Username is: " << _username << std::endl;

	//Check if valid user
	if (_pwd->checkUser(_username.c_str()))
	{
		std::cout << "User Found!\n";
		_status = s_passwd;
	}
	else {
		std::cout << "Invalid user, disconnecting.\n";

		//Log User Not Found
		std::string addr;
		_connfd.getIPAddrStr(addr);
		_log->log(Logger::l_usr_no, addr, _username);

		disconnect();
	}
}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
	// Insert your astounding code here

	std::string clrTxt, msg;
	_pwd_attempts = 2;
	while (_pwd_attempts > 0) {
		_connfd.writeFD("Enter Password: \n");
		if (!getUserInput(clrTxt)) {
			_pwd_attempts--;
			msg += "Invalid Password Attempt. \n";
			msg += std::to_string(_pwd_attempts);
			msg += " attempts remaining.\n";
			_connfd.writeFD(msg);
		}
		else {
			if (!_pwd->checkPasswd(_username.c_str(), clrTxt.c_str())) {
				_pwd_attempts--;
				msg += "Invalid Password Attempt. \n";
				msg += std::to_string(_pwd_attempts);
				msg += " attempts remaining.\n";
				_connfd.writeFD(msg);
			}
			else {
				std::cout << "User Password Accepted\n";
				_connfd.writeFD("Password Accepted. Loggin in...\n");
				_status = s_menu;

				//Log Successful Login Attempt
				std::string addr;
				_connfd.getIPAddrStr(addr);
				_log->log(Logger::l_usr_yes, _username, addr);
				_status = s_menu;

				return;
			}
		}
	}

	//After 2 attempts, disconnect
	std::cout << "Too many invalid password attemtps. Disconnecting user...\n";
	_connfd.writeFD("Too many invalid password attemtps. Disconnecting user...\n");

	//Log Too Many PW Attempts
	std::string addr;
	_connfd.getIPAddrStr(addr);
	_log->log(Logger::l_usr_fail, _username, addr);
	_status = s_passwd;

	disconnect();

}

/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {
	// Insert your amazing code here
	std::string clrTxt, msg;
	_pwd_attempts = 3;

	while (_status == s_changepwd && _pwd_attempts > 0) {
		if (!getUserInput(clrTxt)) {
			_pwd_attempts--;
			msg += "Invalid Password. \n";
			_connfd.writeFD(msg);
		}
		else if (_pwd->checkPasswd(_username.c_str(), clrTxt.c_str())) {
			_connfd.writeFD("New password is the same as current password.\n");
			_status = s_menu;
			return;
		}
		else {
			if (_pwd->changePasswd(_username.c_str(), clrTxt.c_str())) {
				std::cout << "New User Password Accepted\n";
				_connfd.writeFD("New User Password Accepted.\n");
				_pwd_attempts = 3;
				_status = s_confirmpwd;
			}
			else {
				_pwd_attempts--;
				_connfd.writeFD("Invalid.\n");
				return;
			}
		}
	}
	if (_status == s_confirmpwd) {
		getPasswd();
		_status = s_menu;
		return;
	}
	//After 2 attempts, disconnect
	std::cout << "Too many invalid password attemtps. Disconnecting user...\n";
	_connfd.writeFD("Too many invalid password attemtps. Disconnecting user...\n");
	disconnect();
}


/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * whitelisted - Returns true is given IP address in on whitelist and false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::whitelisted(std::string addr) {
	std::string line;
	std::ifstream whtlst;
	whtlst.open("whitelist");
	if (whtlst.is_open()) {
		//Check IP address against whitelist
		while (getline(whtlst, line))
		{
			clrNewlines(line);
			if (addr.compare(line) == 0) {
				std::cout << "IP Address is on whitelist.\n";
				return true;
			}
		}
		whtlst.close();
		return false;
	}
	else {
		std::cout << "Unable to open file\n";
		return false;
	}
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
	//_connfd.writeFD("\nSelect a Menu Option!\n");
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      
   // Don't be lazy and use my outputs--make your own!
   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Hello back!\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("Disconnecting...goodbye!\n");
      disconnect();
   } else if (cmd.compare("passwd") == 0) {
      _connfd.writeFD("New Password: ");
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      msg += "You want a prediction about the weather? You're asking the wrong Phil.\n";
      msg += "I'm going to give you a prediction about this winter. It's going to be\n";
      msg += "cold, it's going to be dark and it's going to last you for the rest of\n";
      msg += "your lives!\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("2") == 0) {
      _connfd.writeFD("42\n");
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("That seems like a terrible idea.\n");
   } else if (cmd.compare("4") == 0) {

   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("I'm singing, I'm in a computer and I'm siiiingiiiing! I'm in a\n");
      _connfd.writeFD("computer and I'm siiiiiiinnnggiiinnggg!\n");
   } else {
      msg = "Unrecognized command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   // Make this your own!
   menustr += "Available choices: \n";
   menustr += "  1). Provide weather report.\n";
   menustr += "  2). Learn the secret of the universe.\n";
   menustr += "  3). Play global thermonuclear war\n";
   menustr += "  4). Do nothing.\n";
   menustr += "  5). Sing. Sing a song. Make it simple, to last the whole day long.\n\n";
   menustr += "Other commands: \n";
   menustr += "  Hello - self-explanatory\n";
   menustr += "  Passwd - change your password\n";
   menustr += "  Menu - display this menu\n";
   menustr += "  Exit - disconnect.\n\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
	std::string addr;
	_connfd.getIPAddrStr(addr);
	if (_username == "") { _username = "NO USER"; }
	_log->log(Logger::l_disconn, addr, _username);
   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
void TCPConn::getIPAddrStr(std::string &buf) {
   return _connfd.getIPAddrStr(buf);
}

