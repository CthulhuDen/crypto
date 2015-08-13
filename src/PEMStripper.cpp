/*
 * PEMStripper.cpp
 *
 *  Created on: Aug 12, 2015
 *	  Author: cthulhu
 */

#include "PEMStripper.h"
#include <cryptopp/fltrimpl.h>
#include <cryptopp/misc.h>
#include <cryptopp/cryptlib.h>

template <class T> inline const T& STDMAX(const T& a, const T& b)
{
	return a < b ? b : a;
}
const std::string DEFAULT_CHANNEL;

using CryptoPP::BufferedTransformation;

PEMStripper::PEMStripper(BufferedTransformation *attachment)
	:m_dashcount(0)
{
	Detach(attachment);
}

size_t PEMStripper::Put2(const byte * begin,size_t length, int messageEnd,bool blocking)
{
	char curr;
	FILTER_BEGIN;
	while(m_inputPosition < length)
	{
		curr = begin[m_inputPosition++];
		if(curr == '-') m_dashcount++;
		if(m_dashcount)
		{
			if(m_dashcount == 10) m_dashcount = 0;
			continue;
		} else {
			FILTER_OUTPUT(1,begin+m_inputPosition-1,1,0);
		}
	}
	if(messageEnd)
	{
		FILTER_OUTPUT(2,0,0,messageEnd);
	}
	FILTER_END_NO_MESSAGE_END;
}

PEMStripper::~PEMStripper() {
	// TODO Auto-generated destructor stub
}

