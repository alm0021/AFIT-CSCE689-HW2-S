#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <list>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

#define HASHLEN 32
#define SALTLEN 16

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}

PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> passwd, salt;

   bool result = findUser(name, passwd, salt);

   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;

   std::cout << name << "'s passwd is " << passwd << std::endl; //DEBUGGING
   std::cout << name << "'s hash is "; //DEBUGGING
   printBytes(userhash); //DEBUGGING
   std::cout << name << "'s salt is ";
   printBytes(salt); //DEBUGGING

   hashArgon2(passhash, salt, passwd, &salt);

   std::cout << "After hashing hash is "; //DEBUGGING
   printBytes(passhash); //DEBUGGING
   std::cout << "After hashing salt is "; //DEBUGGING
   printBytes(salt); //DEBUGGING

   if (userhash == passhash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {

   // Insert your insane code here

	//Make sure user exits
	std::vector<uint8_t> hash, salt, newHash;
	if (!findUser(name, hash, salt)) {
		std::cout << "User Doesn't Exist.\n";
		return false;
	}

	hashArgon2(newHash, salt, passwd, &salt); //Hash new password using existing salt

	std::cout << "After hashing new password hash is "; //DEBUGGING
	printBytes(newHash); //DEBUGGING
	std::cout << "After hashing new (old) salt is "; //DEBUGGING
	printBytes(salt); //DEBUGGING

	//Open passwd file for reading
	FileFD pwfile(_pwd_file.c_str());
	if (!pwfile.openFile(FileFD::readfd)) {
		throw pwfile_error("Could not open passwd file for reading");
	}

	std::string line;
	std::vector<std::string> newLines;
	
	//Save data from current passwd file into vector of strings
	while (pwfile.readStr(line) > 0)
	{
		clrNewlines(line);
		pwfile.readBytes(hash, HASHLEN);
		pwfile.readBytes(salt, SALTLEN + 1);
		salt.pop_back();
		std::ostringstream os;

		if (line.compare(name) == 0) { //if usernames match
			os << line << "\n" << toString(newHash) << toString(salt) << "\n";
		}
		else {
			os << line << "\n" << toString(hash) << toString(salt) << "\n";
		}
		std::cout << os.str(); //DEBUGGING
		newLines.push_back(os.str());
		os.flush();
	}
	pwfile.closeFD();

	if (writeNewPWF(newLines) == 0) {
		return false;
	}
	else { return true; }

}

int PasswdMgr::writeNewPWF(std::vector<std::string> newLines) 
{
	//Open passwd file for writing
	FileFD pwfile(_pwd_file.c_str());
	if (!pwfile.openFile(FileFD::writefd)) {
		throw pwfile_error("Could not open passwd file for writing");
	}

	int bytesWritten = 0;

	//write data from vector to passwd file
	for (int i = 0; i < newLines.size(); i++)
	{
		bytesWritten += pwfile.writeFD(newLines[i]);
	}

	return bytesWritten;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Insert your perfect code here!
	std::string line;
	int lineSize = pwfile.readStr(line);
	if (lineSize > 0)
	{
		clrNewlines(line);
		name = line;
		pwfile.readBytes(hash, HASHLEN);
		pwfile.readBytes(salt, SALTLEN+1);
		salt.pop_back();
		std::cout << "Salt size is " << salt.size() << "\n"; //DEBUGGING
		std::cout << "User " << name << " is in passwd file.\n"; //DEBUGGING
		return true;
	}
	std::cout << "End of passwd file.\n";
   return false;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;

   // Insert your wild code here!

   results += pwfile.writeFD(name);
   results += pwfile.writeByte('\n');
   results += pwfile.writeBytes(hash);
   results += pwfile.writeBytes(salt);
   results += pwfile.writeByte('\n');

   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   // Hash those passwords!!!!
	//Check if salt already provided

	uint8_t hash1[HASHLEN];
	uint8_t hash2[SALTLEN];

	uint8_t salt[SALTLEN];
	srand(time(NULL));
	int rando = rand() % 1001 + 1;
	memset(salt, rando, SALTLEN); //salt is not that unique

	//Is salt is provided, use that salt
	if (in_salt->size() > 0) {
		std::copy(in_salt->begin(), in_salt->end(), salt);
	}

	uint8_t* pwd = (uint8_t*)strdup(in_passwd);
	uint32_t pwdlen = strlen((char*)pwd);
	uint32_t saltlen = strlen((char*)salt);

	uint32_t t_cost = 2;            // 1-pass computation
	uint32_t m_cost = (1 << 16);      // 64 mebibytes memory usage
	uint32_t parallelism = 1;       // number of threads and lanes

	// high-level API
	if (argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN) == 0)
	{
		//ret_hash = hash1;
		for (int i = 0; i < HASHLEN; i++) {
			ret_hash.push_back(hash1[i]);
		}
		for (int i = 0; i < SALTLEN; i++) {
			ret_salt.push_back(salt[i]);
		}

	}
	else
	{
		std::cerr << "Error hashing Password\n";
	}
	std::cout << "(INSIDE ARGON) Hashed PW is "; //DEBUGGING
	for (int i = 0; i < HASHLEN; ++i) printf("%02x", ret_hash[i]); printf("\n"); //DEBUGGING
	std::cout << "(INSIDE ARGON) Salt is "; //DEBUGGING
	for (int i = 0; i < SALTLEN; ++i) printf("%02x", ret_salt[i]); printf("\n"); //DEBUGGING
}

/****************************************************************************************************
 * printBytes - Prints hashed vectors
 *
 *    Throws: 
 ****************************************************************************************************/
void PasswdMgr::printBytes(std::vector < uint8_t > hash) {
	
	for (int i = 0; i < hash.size(); ++i) printf("%02x", hash[i]); printf("\n");
}

/****************************************************************************************************
 * toString - Prints hashed vectors
 *
 *    Throws:
 ****************************************************************************************************/
std::string PasswdMgr::toString(std::vector< uint8_t > hash) {

	std::string str;
	std::ostringstream os;
	for (int i = 0; i < hash.size(); ++i) {
		//printf("%02x", hash[i]);
		os << hash[i];
	}
	str = os.str();
	return str;
}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   // Add those users!

	if (checkUser(name)) { 
		std::cout << "User Already Exists.\n"; 
		return;
	}
	
	//Open passwd file for writing
	FileFD pwfile(_pwd_file.c_str());
	if (!pwfile.openFile(FileFD::appendfd))
		throw pwfile_error("Could not open passwd file for writing");
	
	std::string nameStr(name);
	std::vector<uint8_t> hash, salt;
	std::vector<uint8_t> userhash; // hash from the password file
	std::vector<uint8_t> passhash; // hash derived from the parameter passwd

	hashArgon2(passhash, salt, passwd, &salt);
	
	writeUser(pwfile, nameStr, passhash, salt);

	pwfile.closeFD();
}

