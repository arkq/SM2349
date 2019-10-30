/************************************************************************
  FileName:       KDF.h
  Version:        KDF_V1.1
  Date:           Sep 24,2016
  Description:    This headfile provides KDF function needed in SM2 algorithm
  Function List:
    1.SM3_256            //calls SM3_init、SM3_process and SM3_done to calculate hash value
    2.SM3_init           //init the SM3 state
    3.SM3_process        //compress the the first len/64 blocks of the message
    4.SM3_done           //compress the rest message and output the hash value
    5.SM3_compress       //called by SM3_process and SM3_done, compress a single block of message
    6.BiToW              //called by SM3_compress,to calculate W from Bi
    7.WToW1              //called by SM3_compress, calculate W' from W
    8.CF                 //called by SM3_compress, to calculate CF function.
    9.BigEndian          //called by SM3_compress and SM3_done.GM/T 0004-2012 requires to use big-endian.
                         //if CPU uses little-endian, BigEndian function is a necessary call to change the
                         //little-endian format into big-endian format.
    10.SM3_KDF           //calls SM3_init、SM3_process and SM3_done to generate key stream
  History:
    1. Date: Sep 18,2016
       Author: Mao Yingying, Huo Lili
       Modification: Adding notes to all the functions
************************************************************************/

#pragma once

#include <string.h>
#include "SM3.h"

/******************************************************************************
  Function:          SM3_KDF
  Description:       key derivation function
  Calls:             SM3_init
                     SM3_process
                     SM3_done
  Called By:
  Input:             unsigned char Z[zlen]
                     unsigned short zlen       //bytelen of Z
                     unsigned short klen       //bytelen of K
  Output:            unsigned char K[klen]     //shared secret key
  Return:            null
  Others:
*******************************************************************************/
void SM3_KDF(unsigned char Z[], unsigned short zlen, unsigned short klen, unsigned char K[])
{
	unsigned short i, j, t;
	unsigned int bitklen;
	SM3_STATE md;
	unsigned char Ha[SM2_NUMWORD];
	unsigned char ct[4] = {0, 0, 0, 1};

	bitklen = klen * 8;

	if (bitklen % SM2_NUMBITS)
		t = bitklen / SM2_NUMBITS + 1;
	else
		t = bitklen / SM2_NUMBITS;

	//s4:        K=Ha1||Ha2||...
	for (i = 1; i < t; i++)
	{
		//s2:        Hai=Hv(Z||ct)
		SM3_init(&md);
		SM3_process(&md, Z, zlen);
		SM3_process(&md, ct, 4);
		SM3_done(&md, Ha);
		memcpy((K + SM2_NUMWORD * (i - 1)), Ha, SM2_NUMWORD);

		if (ct[3] == 0xff)
		{
			ct[3] = 0;
			if (ct[2] == 0xff)
			{
				ct[2] = 0;
				if (ct[1] == 0xff)
				{
					ct[1] = 0;
					ct[0]++;
				}
				else
					ct[1]++;
			}
			else
				ct[2]++;
		}
		else
			ct[3]++;
	}

	//s3: klen/v
	SM3_init(&md);
	SM3_process(&md, Z, zlen);
	SM3_process(&md, ct, 4);
	SM3_done(&md, Ha);

	if (bitklen % SM2_NUMBITS)
	{
		i = (SM2_NUMBITS - bitklen + SM2_NUMBITS * (bitklen / SM2_NUMBITS)) / 8;
		j = (bitklen - SM2_NUMBITS * (bitklen / SM2_NUMBITS)) / 8;
		memcpy((K + SM2_NUMWORD * (t - 1)), Ha, j);
	}
	else
	{
		memcpy((K + SM2_NUMWORD * (t - 1)), Ha, SM2_NUMWORD);
	}
}
