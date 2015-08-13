/*
 * PEMStripper.h
 *
 *  Created on: Aug 12, 2015
 *	  Author: cthulhu
 */

#ifndef PEMSTRIPPER_H_
#define PEMSTRIPPER_H_

#include <cryptopp/filters.h>
#include <cryptopp/simple.h>

typedef unsigned char byte;

namespace CryptoPP {
	class BufferedTransformation;
}

class PEMStripper : public CryptoPP::Unflushable<CryptoPP::Filter>
{
public:
	PEMStripper(CryptoPP::BufferedTransformation *attachment=NULL);
	virtual ~PEMStripper();
	size_t Put2(const byte * begin,size_t length, int messageEnd,bool blocking);
private:
	int m_dashcount;
};


#endif /* PEMSTRIPPER_H_ */
