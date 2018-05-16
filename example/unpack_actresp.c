/*
 * Atonomi Device SDK: Message Pack Example
 *
 * Copyright (C) 2018 Atonomi
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "atmi.h"

/*
 * WARNING: Do NOT implement ATMI_memrand using a PRNG like this. This
 * is not cryptographically secure. Entropy must come from a HWRNG, or
 * at the very least, a CSPRNG. See the documentation and the notice
 * in atmi.h for more details.
 */
void ATMI_memrand(void *p, size_t n)
{
	uint32_t x;

	for(; n > sizeof(x); n -= sizeof(x), p += sizeof(x)) {
		x = (uint32_t)rand();
		memcpy(p, &x, sizeof(x));
	}

	x = (uint32_t)rand();
	memcpy(p, &x, n);
}

/*
 * WARNING: Do not reuse this keypair.
 */
static const atmi_context_t context = {
	.publicKey = {
		0xa9, 0xb0, 0xa4, 0x1a, 0x10, 0xdd, 0x22, 0x1d,
		0xba, 0x5c, 0xf4, 0xed, 0x2a, 0x07, 0x9f, 0x0e,
		0x19, 0x2a, 0x6b, 0x53, 0x17, 0xf0, 0xa6, 0x1e,
		0x40, 0x0e, 0xe7, 0x6d, 0xa6, 0xb6, 0xb4, 0x6e
	},
	.privateKey = {
		0x9c, 0x27, 0x40, 0x91, 0xda, 0x1c, 0xe4, 0x7b,
		0xd3, 0x21, 0xf2, 0x72, 0xd6, 0x6b, 0x6e, 0x55,
		0x14, 0xfb, 0x82, 0x34, 0x6d, 0x79, 0x92, 0xe2,
		0xd1, 0xa3, 0xee, 0xfd, 0xef, 0xfe, 0xd7, 0x91
	}
};

static atmi_session_t session;



int main()
{
	static const char    fname_pktin[] = "testonly_actresp.packet.bin";
	static const char    fname_psess[] = "testonly_actreq.session.bin";

	atmi_act_response_t  actresp;
	FILE                *fp;
	size_t               rlen;
	int                  r;
	uint8_t              filebuf[512];


	/* 
	 * Read internal session state data from when request was made.
	 * This is needed to decrypt the response.
	 *
	 * This should not be necessary in practice; this is done here since
	 * the request packing example is written to execute as a separate
	 * test program, and process memory is volatile.
	 */
	if( !(fp = fopen(fname_psess, "rb")) ) {
		printf("Error:fopen:Couldn't open '%s' for read.\n", fname_psess);
		return 1;
	}

	rlen = fread(filebuf, 1, sizeof(filebuf), fp);

	if(rlen == 0u) {
		printf("Error:fread:Couldn't read any bytes from '%s'.\n",
		       fname_psess);
		(void)fclose(fp);
		return 2;
	}
	else if(rlen >= sizeof(filebuf)) {
		printf("Error:fread:Length of '%s' exceeded available buffer.\n",
		       fname_psess);
		(void)fclose(fp);
		return 2;
	}
	else if(rlen > sizeof(session.state)) {
		printf("Error:fread:Length of '%s' (%zu bytes) exceeded state"
		       " size (%zu bytes).\n", fname_psess,
		       rlen, sizeof(session.state));
		(void)fclose(fp);
		return 2;
	}

	if(!!fclose(fp)) {
		printf("Error:fclose:Couldn't close file '%s'.\n", fname_psess);
		return 3;
	}

	memcpy(session.state, filebuf, rlen);


	/* Read response packet data. */
	if( !(fp = fopen(fname_pktin, "rb")) ) {
		printf("Error:fopen:Couldn't open '%s' for read.\n", fname_pktin);
		return 4;
	}

	rlen = fread(filebuf, 1, sizeof(filebuf), fp);

	if(rlen == 0u) {
		printf("Error:fread:Couldn't read any bytes from '%s'.\n",
		       fname_pktin);
		(void)fclose(fp);
		return 5;
	}
	else if(rlen >= sizeof(filebuf)) {
		printf("Error:fread:Length of '%s' exceeded available buffer.\n",
		       fname_pktin);
		(void)fclose(fp);
		return 5;
	}

	if(!!fclose(fp)) {
		printf("Error:fclose:Couldn't close file '%s'.\n", fname_pktin);
		return 6;
	}


	/* Try unpacking response. */
	r = ATMIunpack_act_response(&context, &session, filebuf, rlen, &actresp);
	if(r != 0) {
		if(r > 0)
			printf("FATAL:ATMIunpack_act_respone:Returned error "
			       "%d. This should be impossible!\n", r);
		else
			printf("Error:ATMIunpack_act_response:Returned error "
			       "%d.\n", -r);
		return 7;
	}

	printf("Success:ATMIunpack_act_response:Server returned success=%"
	       PRId32 ".\n", actresp.success);
	return 0;
}

