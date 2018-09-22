/*

TOTP - A time based one time password generator library
Copyright(C) 2016, James Rupert Swift

This program is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.

*/

#pragma once
#include <string>
#include <time.h>

namespace TOTP_Library
{

	typedef std::string(*hash_function)(const std::string&);

	struct TOTPConf
	{
		TOTPConf(std::string key, int blocksize, unsigned int epoch,
			unsigned int interval, unsigned int margin, hash_function hasher);
		TOTPConf(std::string key, hash_function hasher);
		TOTPConf(TOTPConf* config);

		void setPadding(char o_pad = (char)nullptr, char i_pad = (char)nullptr);

		std::string key;

		char o_pad = 0x5c;
		char i_pad = 0x36;

		unsigned int blocksize = 64;
		unsigned int epoch = 0;
		unsigned int interval = 30;
		unsigned int margin = 2;

		hash_function hash;
	};


	class TOTP
	{

	public:
		TOTP(TOTPConf config);
		~TOTP();

		std::string operator()();
		bool validate(std::string token);
		double getTimeCounter(time_t when);
	private:
		TOTPConf* config;

		std::string hmac(std::string key, std::string message);
		std::string generate(time_t when);
	};

}