/*
 * Atonomi Device SDK: Message Pack Example
 *
 * Copyright (C) 2018 Atonomi
 */
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
 * Your Device ID will differ (obviously).
 */
static const uint8_t TestDeviceID[32] = {
	0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u,
	0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u,
	0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u, 0x0u,
	 't',  'e',  's',  't',  'o',  'n',  'l',  'y'
};

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
	static const char   fname_pktout[] = "testonly_actreq.packet.bin";
	static const char   fname_psessn[] = "testonly_actreq.session.bin";

	atmi_act_request_t  actreq;
	FILE               *fp;
	int                 len;
	size_t              wlen;

	memcpy(actreq.id_requestor, TestDeviceID, sizeof(actreq.id_requestor));

	len = ATMIpack_act_request(&context, &session, &actreq);
	if(len < 0) {
		// Error
		printf("Error:ATMIpack_act_request:Returned error %d.\n", -len);
		return 1;
	}

	/* 
	 * Write out internal session state data from formation of request.
	 * This will be needed to decrypt the response.
	 *
	 * This should not be necessary in practice; this is done here since
	 * the response unpacking example is written as a separate test
	 * program, and process memory is volatile.
	 */
	fp = fopen(fname_psessn, "wb");
	if(!fp) {
		printf("Error:fopen:Couldn't open '%s' for write.\n", fname_psessn);
		return 2;
	}

	wlen = fwrite(session.state, 1, sizeof(session.state), fp);
	if(wlen != sizeof(session.state)) {
		printf("Error:fwrite:Only wrote %zu of %zu bytes to '%s'.\n",
		       wlen, sizeof(session.state), fname_psessn);
		(void)fclose(fp);
		return 3;
	}

	if(!!fclose(fp)) {
		printf("Error:fclose:Couldn't close file '%s'.\n", fname_psessn);
		return 4;
	}


	/* Write out packet itself. */
	fp = fopen(fname_pktout, "wb");
	if(!fp) {
		printf("Error:fopen:Couldn't open '%s' for write.\n", fname_pktout);
		return 5;
	}

	wlen = fwrite(session.packet, 1, len, fp);
	if(len != (int)wlen) {
		printf("Error:fwrite:Only wrote %d of %d bytes to '%s'.\n",
		       (int)wlen, len, fname_pktout);
		(void)fclose(fp);
		return 6;
	}

	if(!!fclose(fp)) {
		printf("Error:fclose:Couldn't close file '%s'.\n", fname_pktout);
		return 7;
	}

	return 0;
}

