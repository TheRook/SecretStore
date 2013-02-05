/*
 * base64.h
 *
 *  Created on: Feb 4, 2013
 *      Author: mike
 */

#ifndef BASE64_H_
#define BASE64_H_

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

char
*base64_decode(unsigned char *input, int length);

char
*base64_encode(const unsigned char *input, int length);

#endif /* BASE64_H_ */
