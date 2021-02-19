/*
 *  centri_ps.h
 *  Protected Sessions Library
 *
 *  Copyright © 2018 CENTRI Technology. All rights reserved.
 */
#ifndef CENTRI_PS_H_
#define CENTRI_PS_H_

#include <stdint.h>
#include "centri_ps_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* high level api calls
   --session manager--
    int psm_process_incoming_package (const PSMPackageHandler* packageHandler, const uint8_t* inBuf, size_t inBufLen);
    int psm_generate_response (const PSKeys* smKeys, PSPackage* responsePackage);
    int psm_generate_data_package (const PSKeys* smKeys, PSPackage* dataPackage);
    int psm_generate_stop_package (const PSKeys* smKeys, PSPackage* stopPackage, uint8_t reason);

   --session endpoint--
    int pse_process_incoming_package (const PSEPackageHandler* packageHandler, const uint8_t* inBuf, size_t inBufLen, PSSession* sessionPtr);
    int pse_generate_greeting(const PSKeys* seKeys, PSPackage* startPackage, PSGreetingInfo* greetingInfo);
    int pse_generate_data_package (const PSKeys* seKeys, PSPackage* dataPackage);
    int pse_generate_stop_package (const PSKeys* seKeys, PSPackage* stopPackage, uint8_t reason);
*/
/* This structure stores session information.
   It does not need to be modified or used directly by the user, however
   the user needs to store this for the lifetime of a given session */
typedef struct PSSession
{
    uint8_t         sessionId[PS_SESSION_ID_BYTES];
    uint8_t         privateData[256];

} PSSession;

/* This structure is optional for endpoints and required for session managers.
   If not provided for a session endpoint, ephemeral keys will be used instead.
   If not provided for a session manager, generate package and process package calls will fail. */
typedef struct PSKeys
{
    const uint8_t*  publicKey;
    size_t          publicKeySize;
    const uint8_t*  privateKey;
    size_t          privateKeySize;

} PSKeys;

/* This structure contains most of the variables needed to encode a session package
   It is used by both endpoint and manager. */
typedef struct PSPackage
{
    const uint8_t*  payload;        /* [IN]  Data to be encrypted in the package or NULL if not needed */
    size_t          payloadLen;     /* [IN]  the length of payload */
    uint8_t*        outBuf;         /* [IN]  A buffer provided by the user to store the encrypted output */
    size_t          outBufLen;      /* [IN]  The length of outBuf */
    size_t          outBufWritten;  /* [OUT] Actual bytes written by the system after calling a function to make a package */
    PSSession       sessionInfo;    /* [IN-OUT] For the session manager, leave this null.  It will either be populated by the manager when decoding a request,
                                                or via a callback for the manager to lookup and return.
                                                For an endpoint, this must be provided and is obtained through a call to pse_generate_request */
} PSPackage;

/* This structure is passed to all callbacks for both endpoint and manager.
   It contains the decrypted buffer, user data passed in through PSPackage, and a pointer to the session data used. */
typedef struct PSCallbackInfo
{
    const uint8_t*  buffer;         /* Decrypted data from the package */
    size_t          bufferLen;      /* Length of the decrypted data */
    PSSession*      sessionInfo;    /* Pointer to the session data used to decrypt 'buffer'. */

} PSCallbackInfo;

/* This structure is passed to pse_generate_greeting and contains information needed
   to start a session. */
typedef struct PSGreetingInfo
{
    const void* destPubKey;        /* An endpoint populates this with the session manager public key. */
                                   /* A manager provides the public key of the endpoint via on_session_greeting() */
    const void* endpointId;        /* This is a unique identifier that the session manager will use to authenticate the device. */
    size_t      endpointIdSize;    /* The length of endpointId */

} PSGreetingInfo;

/* This structure is provided in both session manager and endpoint stop request callbacks. */
typedef struct PSStopInfo
{
    uint8_t reason;                /* The reason the 'other side' wanted to stop the session. */
    const void* sessionId;         /* The session ID of the current session. */
    size_t sessionIdSize;          /* The size of sessionId */

} PSStopInfo;

/* This structure is used on an endpoint to both procure and free memory needed for decrypting a package. */
typedef struct PSOutputBuffer
{
    uint8_t* buffer;               /* A buffer to be filled by the caller */
    size_t bufferLen;              /* The length of the buffer provided */
    size_t bufferRequired;         /* The size requested */

} PSOutputBuffer;

struct PSEPackageHandler;           /* forward declaration for the endpoint callbacks */
struct PSMPackageHandler;           /* forward declaration for the manager callbacks */

/* Session endpoint specific callback definitions (described below) */
typedef int(*pse_session_established_cb)(const struct PSEPackageHandler* packageHandler, PSCallbackInfo* callbackInfo);
typedef int(*pse_session_stop_cb)       (const struct PSEPackageHandler* packageHandler, PSCallbackInfo* callbackInfo, PSStopInfo* stopInfo);
typedef int(*pse_session_data_cb)       (const struct PSEPackageHandler* packageHandler, PSCallbackInfo* callbackInfo);

/* Session manager specific callback definitions (described below) */
typedef int(*psm_session_stop_cb)       (const struct PSMPackageHandler* packageHandler, PSCallbackInfo* callbackInfo, PSStopInfo* stopInfo);
typedef int(*psm_session_data_cb)       (const struct PSMPackageHandler* packageHandler, PSCallbackInfo* callbackInfo);
typedef int(*psm_session_greeting_cb)   (const struct PSMPackageHandler* packageHandler, PSCallbackInfo* callbackInfo, PSGreetingInfo* greetingInfo);
typedef int(*psm_get_session_info_cb)   (const void* sessionId, size_t sessionIdSize, PSSession* sessionDataToPopulate, void* userContext);

/* Generic callback definitions (described below) */
typedef int(*ps_buffer_cb)              (PSOutputBuffer* outputBuffer, void* userContext);

typedef struct PSECallbacks
{
    pse_session_established_cb  on_session_established;  /* Called when a response package is processed */
    pse_session_stop_cb         on_session_stop;         /* Called when a stop package is processed */
    pse_session_data_cb         on_session_data;         /* Called when a data package is processed */
    ps_buffer_cb                on_get_output_buffer;    /* Called to obtain a buffer to decrypt a package into */
    ps_buffer_cb                on_free_output_buffer;   /* Called to free the buffer obtained through on_get_output_buffer() */

} PSECallbacks;

/* This structure contains all of the calls used by a session endpoint through callback. */
typedef struct PSEPackageHandler
{
    const PSECallbacks*         callbacks;               /* Callbacks that implement the user's behavior. */
    PSKeys*                     keys;                    /* Optionally used to decrypt packages when ephemeral keys are not used.  Otherwise, NULL. */
    void*                       context;                 /* User context passed to the callback functions */

} PSEPackageHandler;

typedef struct PSMCallbacks
{
    psm_session_greeting_cb   on_session_greeting;       /* Called when a request package is processed */
    psm_session_stop_cb       on_session_stop;           /* Called when a stop package is processed */
    psm_session_data_cb       on_session_data;           /* Called when a data package is processed */
    psm_get_session_info_cb   on_get_session_info;       /* Called to obtain existing session information */
    ps_buffer_cb              on_get_output_buffer;      /* Called to obtain a buffer to decrypt a package into */
    ps_buffer_cb              on_free_output_buffer;     /* Called to free the buffer obtained through on_get_output_buffer() */

} PSMCallbacks;

/* This structure contains all of the calls used by a session manager through callback. */
typedef struct PSMPackageHandler
{
    const PSMCallbacks*       callbacks;                 /* Callbacks that implement the user's behavior. */
    PSKeys*                   keys;                      /* Used to decrypt packages and session info.  Required. */
    void*                     context;                   /* User context passed to the callback functions */

} PSMPackageHandler;

/****************************************************************************
 * High level session manager API functions
 */

/**
* Session manager call to process a package originating from a session endpoint
* @param packageHandler contains a collection of callback pointers to be called depending on the package type
* @param inBuf contains the buffer encrypted on an endpoint device
* @param inBufLen is the length of inBuf
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int psm_process_incoming_package (const PSMPackageHandler* packageHandler, const uint8_t* inBuf, size_t inBufLen);

/**
* Session manager call to create a response package for an session endpoint request package
* @param smKeys contains a structure holding the public and private keys for the session manager. This must be populated.
* @param responsePackage contains both input and output buffers, a user context.  When the function exits, it will also contain the session information
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int psm_generate_response (const PSKeys* smKeys, PSPackage* responsePackage);

/**
* Session manager call to create a data package for an established session
* @param smKeys contains a structure holding the public and private keys for the session manager.  This must be populated.
* @param dataPackage contains both input and output buffers, a user context.  When the function exits, it will also contain the session information
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int psm_generate_data_package (const PSKeys* smKeys, PSPackage* dataPackage);

/**
* Session manager call to create a stop package for an established session.
* @param smKeys contains a structure holding the public and private keys for the session manager.  This must be populated.
* @param stopPackage contains both input and output buffers, a user context.  When the function exits, it will also contain the session information
* @param reason contains a numeric value to tell the session endpoint why the session was closed.
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int psm_generate_stop_package (const PSKeys* smKeys, PSPackage* stopPackage, uint8_t reason);

/****************************************************************************
 * High level session endpoint API functions
 */
/**
* Session endpoint call to process a package originating from a session manager
* @param packageHandler contains a collection of callback pointers to be called depending on the package type
* @param inBuf contains the buffer encrypted by a session manager
* @param inBufLen is the length of inBuf
* @param sessionPtr is the buffer recieved during the call to pse_generate_greeting and kept updated after each API call
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int pse_process_incoming_package (const PSEPackageHandler* packageHandler, const uint8_t* inBuf, size_t inBufLen, PSSession* sessionPtr);

/**
* Session endpoint call to start a session by creating a greeting package to be sent to a session manager.
* @param seKeys contains an OPTIONAL structure holding the public and private keys for the session endpoint.  Otherwise, NULL and ephemeral keys will be used.
* @param startPackage contains input buffer, output buffer, a user context, and a PSSession object that must be held for the life of the session.
* @param greetingInfo contains information required to start a session like the session manager public key and unique endpoint device information.
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int pse_generate_greeting(const PSKeys* seKeys, PSPackage* startPackage, PSGreetingInfo* greetingInfo);

/**
* Session endpoint call to create a data package for an established session
* @param seKeys contains an OPTIONAL structure holding the public and private keys for the session endpoint.  Otherwise, NULL and ephemeral keys will be used.
* @param responsePackage contains the session information, both input and output buffers, and a user context.
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int pse_generate_data_package (const PSKeys* seKeys, PSPackage* dataPackage);

/**
* Session endpoint call to create a stop package for an established session.
* @param seKeys contains an OPTIONAL structure holding the public and private keys for the session endpoint.  Otherwise, NULL and ephemeral keys will be used.
* @param stopPackage contains the session information, both input and output buffers, and a user context.
* @param reason contains a numeric value to tell the session endpoint why the session was closed.
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int pse_generate_stop_package (const PSKeys* seKeys, PSPackage* stopPackage, uint8_t reason);

/**
* Utility function to generate a 32byte public and private key pair
* @param publicKey contains a 32 unsigned byte buffer to hold the public key
* @param privateKey contains a 32 unsigned byte buffer to hold the private key
* @return On success, 0, otherwise -1 for an error
*/
int ps_generate_key_pair(unsigned char* publicKey, unsigned char* privateKey);

#define PS_BOX_BYTES  (16u + 24u)

int ps_encrypt_box(
    void* c,
    size_t clen,
    const void* m,
    size_t mlen,
    const void* pk,
    const void* sk
);

int ps_decrypt_box(
    void* m,
    size_t mlen,
    const void* c,
    size_t clen,
    const void* pk,
    const void* sk
);

#ifdef __cplusplus
}
#endif

#endif /*CENTRI_PS_H_*/
