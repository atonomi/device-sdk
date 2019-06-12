/*
 * Atonomi Device SDK
 *
 * Copyright (C) 2018 Atonomi
 */
#ifndef ATMI_H_
#define ATMI_H_

#include <stddef.h>
#include <stdint.h>
#include "lib/centri_ps.h"


/*
 * The maximum amount of space required to store encoded requests or
 * decoded responses for any of the messages Atonomi's protocol. The
 * raw messages correspond roughly to their respective struct sizes,
 * but the CENTRI Protected Sessions library needs additional room
 * for encryption, hence the inflated size. This is rounded up to
 * the nearest sizeof(void*) for alignment purposes.
 */
#define ATMI_SESSBUF_SIZE           (537u)
#define ATMI_SESSBUF_STATE_SIZE     (sizeof(PSPackage) + 3u*sizeof(void*))


/**
 * Atonomi Library Context
 *
 * Contains the device's public and private keys. These only need to be
 * populated for use while executing the Atonomi message pack/unpack routines.
 * If desired, the private key (or both keys) may be explicitly zeroed from
 * RAM between calls, being re-fetched or re-derived immediately beforehand
 * from some form of secure storage.
 */
typedef struct {
	uint8_t   publicKey[32];
	uint8_t   privateKey[32];
} atmi_context_t;


/**
 * Atonomi Session
 *
 * Retains any state that may be required to persist between the packing of a
 * request and the unpacking of a response. This state is required to correctly
 * decode a particular request's response. However, it does not need to persist
 * between two separate message requests, whether of the same type or otherwise.
 *
 * Some internal data has been made opaque here solely for clarity. Namely,
 * while the packet buffer is intended to be accessed directly, all other
 * contents are not. Those curious can find the definition of the
 * atmi_session_state_t structure near the top of the .c file which defines
 * the contents of the state buffer.
 *
 * All ATMIpack* routines place their output in the session's packet[] buffer
 * and return the length of packed data in bytes. All ATMIunpack* routines
 * use packet[] as a temporary working buffer only, populating the provided
 * output structure.
 *
 * \note This structure is about 830 bytes in size (platform-dependent).
 */
typedef struct {
	uint8_t    state[ATMI_SESSBUF_STATE_SIZE]; /** Internal state data. */
	uint8_t    packet[ATMI_SESSBUF_SIZE];      /** Working buffer.      */
} atmi_session_t;



/** Device Activation request packet */
typedef struct {
	uint8_t  id_requestor[32];          /** Requestor's Device ID.       */
} atmi_act_request_t;

/** Device Validation request packet */
typedef struct {
	uint8_t  id_requestor[32];          /** Requestor's Device ID.       */
	uint8_t  id_requestor_xsigned[72];  /** Requestor's Device ID, cross-
	                                        signed by the subject. Value
	                                        should be preserved by caller
	                                        since this value is also used
	                                        in reputation requests.      */
	uint8_t  id_subject  [32];          /** Subject's (other) Device ID. */
} atmi_val_request_t;

/** Device Reputation request packet */
typedef struct {
	/* Device IDs */
	uint8_t  id_requestor[32];          /** Requestor's Device ID.       */
	uint8_t  id_subject  [32];          /** Subject's (other) Device ID. */
	uint8_t  reputation_token[16];      /** Reputation token received from
	                                        validation response. This is
	                                        a one-time use token.        */

	/* Reputation Description: */
	uint8_t  comms_replyreceived;       /** 0 = false, otherwise true. 
	                                        Remote device responded to 
	                                        initial communication        */
	uint8_t  comms_successful;          /** 0 = false, otherwise true. 
	                                        Communication completed 
	                                        expectedly.                  */
} atmi_rep_request_t;


/** Device Activation response packet */
typedef struct {
	int32_t  success;              /** 0 = success, negative = error.   */
} atmi_act_response_t;

/** Device Validation response packet */
typedef struct {
	int32_t  success;              /** Query success code/flags.
	                                   negative = error.                */
	uint8_t  reputation_token[16]; /** Reputation token used during 
                                           reputation submission.           */
	uint32_t reputation_total;     /** Total reputation submissions.    */
	uint32_t comm_reply_count;     /** Successful reply received count  */
	uint32_t comm_success_count;   /** Successful communication count.  */
} atmi_val_response_t;

/** Device Reputation Amendment response packet */
typedef struct {
	int32_t  success;              /** 0 = success, negative = error.   */
} atmi_rep_response_t;



#ifdef __cplusplus
extern "C" {
#endif


/**
 * Pack request message: Device Activation
 *
 * \note          Ensure at least 4400 bytes of stack space are available.
 *
 * \param ctx     Location of Atonomi library context structure.
 * \param ssn     Location of message transaction state. Must be preserved for
 *                unpacking the corresponding response.
 * \param act     Location of activation request descriptor.
 *
 * \return -EINVAL   Invalid arguments (bad pointers).
 * \return -EFAULT   Could not encrypt message data (bad keys?).
 * \return len > 0   Number of bytes of packed message written to packet buffer.
 */
int ATMIpack_act_request(const atmi_context_t *ctx, atmi_session_t *ssn,
                         const atmi_act_request_t *act);

/**
 * Pack request message: Device-Device Validation
 *
 * \note          Ensure at least 4400 bytes of stack space are available.
 *
 * \param ctx     Location of Atonomi library context structure.
 * \param ssn     Location of message transaction state. Must be preserved for
 *                unpacking the corresponding response.
 * \param val     Location of validation request descriptor.
 *
 * \return -EINVAL   Invalid arguments (bad pointers).
 * \return -EFAULT   Could not encrypt message data (bad keys?).
 * \return -ENXIO    Signed id provided, but signing function never called.
 * \return -EPIPE
 * \return len > 0   Number of bytes of packed message written to packet buffer.
 */
int ATMIpack_val_request(const atmi_context_t *ctx, atmi_session_t *ssn,
                         const atmi_val_request_t *val);

/**
 * Pack request message: Reputation Amendment
 *
 * \note          Ensure at least 4400 bytes of stack space are available.
 *
 * \param ctx     Location of Atonomi library context structure.
 * \param ssn     Location of message transaction state. Must be preserved for
 *                unpacking the corresponding response.
 * \param rep     Location of reputation request descriptor.
 *
 * \return -EINVAL   Invalid arguments (bad pointers).
 * \return -EFAULT   Could not encrypt message data (bad keys?).
 * \return len > 0   Number of bytes of packed message written to packet buffer.
 */
int ATMIpack_rep_request(const atmi_context_t *ctx, atmi_session_t *ssn,
                         atmi_rep_request_t *rep);



/**
 * Unpack response message: Device Activation
 *
 * \note          Ensure at least 4400 bytes of stack space are available.
 *
 * \param ctx     Location of Atonomi library context structure.
 * \param ssn     Location of message transaction state. Must have been
 *                preserved from the initial call to pack the corresponding
 *                request.
 * \param pinbuf  Location of received input message in which to unpack.
 * \param nin     Length of received input in bytes.
 * \param act     Location of unpacked response descriptor.
 *
 * \return -EINVAL   Invalid arguments (bad pointers or input length).
 * \return -ENOENT   Input does not contain an expected Atonomi packet, either
 *                   due to a bad header or an incorrect response type.
 * \return -EBADF    Packet found but could not be properly unpacked, either
 *                   due to an unexpected length or an invalid CRC.
 * \return -EFAULT   Packet found but encrypted payload was bad or could not
 *                   be decrypted (bad keys?).
 * \return 0         Success. Unpacked contents written to structure.
 */
int ATMIunpack_act_response(const atmi_context_t *ctx, atmi_session_t *ssn,
                            const void *pinbuf, size_t nin,
                            atmi_act_response_t *act);

/**
 * Unpack response message: Device-Device Validation
 *
 * \note          Ensure at least 4400 bytes of stack space are available.
 *
 * \param ctx     Location of Atonomi library context structure.
 * \param ssn     Location of message transaction state. Must have been
 *                preserved from the initial call to pack the corresponding
 *                request.
 * \param pinbuf  Location of received input message in which to unpack.
 * \param nin     Length of received input in bytes.
 * \param val     Location of unpacked response descriptor.
 *
 * \return -EINVAL   Invalid arguments (bad pointers or input length).
 * \return -ENOENT   Input does not contain an expected Atonomi packet, either
 *                   due to a bad header or an incorrect response type.
 * \return -EBADF    Packet found but could not be properly unpacked, either
 *                   due to an unexpected length or an invalid CRC.
 * \return -EFAULT   Packet found but encrypted payload was bad or could not
 *                   be decrypted (bad keys?).
 * \return 0         Success. Unpacked contents written to structure.
 */
int ATMIunpack_val_response(const atmi_context_t *ctx, atmi_session_t *ssn,
                            const void *pinbuf, size_t nin,
                            atmi_val_response_t *val);

/**
 * Unpack response message: Reputation Amendment
 *
 * \note          Ensure at least 4400 bytes of stack space are available.
 *
 * \param ctx     Location of Atonomi library context structure.
 * \param ssn     Location of message transaction state. Must have been
 *                preserved from the initial call to pack the corresponding
 *                request.
 * \param pinbuf  Location of received input message in which to unpack.
 * \param nin     Length of received input in bytes.
 * \param val     Location of unpacked response descriptor.
 *
 * \return -EINVAL   Invalid arguments (bad pointers or input length).
 * \return -ENOENT   Input does not contain an expected Atonomi packet, either
 *                   due to a bad header or an incorrect response type.
 * \return -EBADF    Packet found but could not be properly unpacked, either
 *                   due to an unexpected length or an invalid CRC.
 * \return -EFAULT   Packet found but encrypted payload was bad or could not
 *                   be decrypted (bad keys?).
 * \return 0         Success. Unpacked contents written to structure.
 */
int ATMIunpack_rep_response(const atmi_context_t *ctx, atmi_session_t *ssn,
                            const void *pinbuf, size_t nin,
                            atmi_rep_response_t *rep);



/**
 * Sign the provided Device ID with this device's keypair.
 *
 * \note A cross-signed Device ID is a Device ID value that has been signed
 *       by another party. In order to correctly construct and pack
 *       validation and reputation requests, the requestor needs the subject's
 *       Device ID in addition to its own ID that's been signed by the subject
 *       (yielding the requestor's cross-signed ID). This cross-signing
 *       process prevents malicious devices from submitting false reputation
 *       reports against other devices when transactions did not occur.
 *
 *       Note that the signing procedure incorporates some randomly-generated
 *       source data into its output, so assuming a constant Device ID input
 *       value, each call to this function will generate different output.
 *
 *       Ensure at least 3000 bytes of stack space are available.
 *
 * \param ctx       Location of Atonomi library context structure.
 * \param ssn       Location of message transaction state.
 * \param idsgn_out Location in which to store signed Device ID output.
 *                  This output is 72 bytes in length.
 * \param devid_in  Location of input Device ID to be signed.
 *                  This input is 32 bytes in length.
 *
 * \return -EINVAL   Invalid arguments (bad pointers).
 * \return -EFAULT   Signing procedure failed (bad keys?).
 * \return 0         Success. Signed Device ID written to \param id_signed.
 */
int ATMIsign_device_id(const atmi_context_t *ctx, atmi_session_t *ssn,
                       uint8_t       idsgn_out[72],
                       const uint8_t devid_in [32]);



/*
 * The CENTRI component of the Atonomi packet requires a source of entropy
 * in order to create any new packages (i.e. an RNG). Due to a limitation in
 * how they are currently generated, this is exposed not by function pointer
 * but by declared symbol that the linker is expected to locate.
 *
 * The 'ATMI_memrand' symbol has been aliased to an Atonomi-specific
 * symbol name for improved clarity and must be provided by the developer:
 * he or she must declare a function with the exact signature below (note:
 * with C linkage). The function should obtain the specified number of bytes
 * of random entropy from a hardware RNG or other similar source and write
 * them into the location provided.
 *
 * Note: A CSPRNG (cryptographically secure PRNG) could also suffice. All
 * implementation details and choices are left up to the developer, whom is
 * expected to understand the ramifications and potential security impacts
 * resulting from said choice.
 */
extern void ATMI_memrand(void *p, size_t n);


#ifdef __cplusplus
}
#endif

#endif /*ATMI_H_*/

