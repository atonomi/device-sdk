#ifndef CENTRI_PS_H_
#define CENTRI_PS_H_

/*
 *  centri_ps.h
 *
 *  Copyright © 2018 CENTRI Technology. All rights reserved.
 *
 * This header is for defining the protected session endpoint and session manager library
 */

#include <stdint.h>
#include "centri_ps_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* high level api calls
    // session manager api calls
    int psm_process_incoming_package (const PSMCallbackStruct* callbacks, uint8_t* inBuf, size_t inBufLen, void* userContext );
    int psm_generate_response(const PSMCallbackStruct* callbacks, PSPackage* responsePackage);
    int psm_generate_data_package(const PSMCallbackStruct* callbacks, PSPackage* dataPackage);
    int psm_generate_stop_package(const PSMCallbackStruct* callbacks, PSPackage* stopPackage, uint8_t reason);
    
    // session endpoint api calls
    int pse_process_incoming_package(const PSECallbackStruct* callbacks, uint8_t* inBuf, size_t inBufLen, PSSession* sessionPtr, void* userContext);
    int pse_generate_greeting(const PSECallbackStruct* callbacks, PSPackage* startPackage, PSRequestInfo* requestInfo);
    int pse_generate_data_package(const PSECallbackStruct* callbacks, PSPackage* dataPackage);
    int pse_generate_stop_package(const PSECallbackStruct* callbacks, PSPackage* stopPackage, uint8_t reason);
*/
/* This structure stores session inforamtion.
   It does not need to be modified or used directly by the user, however
   the user needs to store this for the lifetime of a given session */
typedef struct PSSession
{
    uint8_t         sessionId[PS_SESSION_ID_BYTES];
    uint8_t         privateData[240];

} PSSession;

/* This structure contains most of the variables needed to encode a session package
   It is used by both endpoint and manager. */
typedef struct PSPackage
{
    const uint8_t*  payload;        /* [IN]  Data to be encrypted in the package or NULL if not needed */
    size_t          payloadLen;     /* [IN]  the length of payload */
    uint8_t*        outBuf;         /* [IN]  A buffer provided by the user to store the encrypted output */
    size_t          outBufLen;      /* [IN]  The length of outBuf */
    size_t          outBufWritten;  /* [OUT] Actual bytes written by the system after calling a function to make a package */
    void*           userContext;    /* [IN]  Pointer to user data.  This will be passed to callbacks when decrypting a package. */
    PSSession       sessionInfo;    /* [IN-OUT] For the session manager, leave this null.  It will either be populated by the manager when decoding a request,
                                                or via a callback for the manager to lookup and return.
                                                For and endpoint, this must be provided and is obtained through a call to pse_generate_request */
} PSPackage;

/* This structure is passed to all callbacks for both endpoint and manager.
   It contains the decrypted buffer, user data passed in through PSPackage, and a pointer to the session data used. */
typedef struct PSCallbackInfo
{
    const uint8_t*  buffer;         /* Decrypted data from the package */
    size_t          bufferLen;      /* Length of the decrypted data */
    void*           userContext;    /* Pointer to user data. */
    PSSession*      sessionInfo;    /* Pointer to the session data used to decrypt 'buffer'. */

} PSCallbackInfo;

/* This structure is passed to pse_generate_request and contains information needed
   to start a session. */
typedef struct PSRequestInfo
{
    const void* recipientPubKey;   /* This is the public key of the session manager. */
    const void* endpointId;        /* This is a unique identifier that the session manager will use to authenticate the device. */
    size_t      endpointIdSize;    /* The length of endpointId */

} PSRequestInfo;

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

struct PSECallbackStruct;           /* forward declaration for the endpoint callbacks */
struct PSMCallbackStruct;           /* forward declaration for the manager callbacks */

/* Session endpoint specific callback definitions (described below) */
typedef int(*pse_session_established_cb)(const struct PSECallbackStruct* callbacks, PSCallbackInfo* callbackInfo);
typedef int(*pse_session_stop_cb)       (const struct PSECallbackStruct* callbacks, PSCallbackInfo* callbackInfo, PSStopInfo* stopInfo);
typedef int(*pse_session_data_cb)       (const struct PSECallbackStruct* callbacks, PSCallbackInfo* callbackInfo);

/* Session manager specific callback definitions (described below) */
typedef int(*psm_session_stop_cb)       (const struct PSMCallbackStruct* callbacks, PSCallbackInfo* callbackInfo, PSStopInfo* stopInfo);
typedef int(*psm_session_data_cb)       (const struct PSMCallbackStruct* callbacks, PSCallbackInfo* callbackInfo);
typedef int(*psm_session_greeting_cb)   (const struct PSMCallbackStruct* callbacks, PSCallbackInfo* callbackInfo, PSRequestInfo* greetingInfo);
typedef int(*psm_get_session_info_cb)   (const void* sessionId, size_t sessionIdSize, PSSession* sessionDataToPopulate, void* userContext);

/* Generic callback definitions (described below) */
typedef int(*ps_get_key_cb)             (void* key, size_t size, void* userContext);
typedef int(*ps_buffer_cb)              (PSOutputBuffer* outputBuffer, void* userContext);

/* This structure contains all of the calls used by a session endpoint through callback. */
typedef struct PSECallbackStruct {
    pse_session_established_cb  on_session_established;  /* Called when a response package is processed */
    pse_session_stop_cb         on_session_stop;         /* Called when a stop package is processed */
    pse_session_data_cb         on_session_data;         /* Called when a data package is processed */
    ps_buffer_cb                on_get_output_buffer;    /* Called to obtain a buffer to decrypt a package into */
    ps_buffer_cb                on_free_output_buffer;   /* Called to free the buffer obtained through on_get_output_buffer() */
    ps_get_key_cb               on_get_private_key;      /* Called to obtain an endpoint private key */
    ps_get_key_cb               on_get_public_key;       /* Called to obtain an endpoint public key */

} PSECallbackStruct;

/* This structure contains all of the calls used by a session manager through callback. */
typedef struct PSMCallbackStruct
{
    psm_session_greeting_cb   on_session_greeting;       /* Called when a request package is processed */
    psm_session_stop_cb       on_session_stop;           /* Called when a stop package is processed */
    psm_session_data_cb       on_session_data;           /* Called when a data package is processed */
    psm_get_session_info_cb   on_get_session_info;       /* Called to obtain existing session information */
    ps_buffer_cb              on_get_output_buffer;      /* Called to obtain a buffer to decrypt a package into */
    ps_buffer_cb              on_free_output_buffer;     /* Called to free the buffer obtained through on_get_output_buffer() */
    ps_get_key_cb             on_get_private_key;        /* Called to obtain a session manager private key */
    ps_get_key_cb             on_get_public_key;         /* Called to obtain a session manager public key */

} PSMCallbackStruct;

/*
 * High level session manager API functions
 */
/**
* Session manager call to process a package originating from a session endpoint
* @param callbacks contains a collection of callback pointers to be called depending on the package type
* @param inBuf contains the buffer encrypted on an endpoint device
* @param inBufLen is the length of inBuf
* @param userContext is a user defined pointer that will be passed to all callback functions
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int psm_process_incoming_package (const PSMCallbackStruct* callbacks, const uint8_t* inBuf, size_t inBufLen, void* userContext);

/**
* Session manager call to create a response package for an session endpoint request package
* @param callbacks contains a collection of callback pointers to be called depending on the package type
* @param responsePackage contains both input and output buffers, a user context.  When the function exits, it will also contain the session information
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int psm_generate_response (const PSMCallbackStruct* callbacks, PSPackage* responsePackage);

/**
* Session manager call to create a data package for an established session
* @param callbacks contains a collection of callback pointers to be called depending on the package type
* @param dataPackage contains both input and output buffers, a user context.  When the function exits, it will also contain the session information
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int psm_generate_data_package (const PSMCallbackStruct* callbacks, PSPackage* dataPackage);

/**
* Session manager call to create a stop package for an established session.
* @param callbacks contains a collection of callback pointers to be called depending on the package type
* @param stopPackage contains both input and output buffers, a user context.  When the function exits, it will also contain the session information
* @param reason contains a numeric value to tell the session endpoint why the session was closed.
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int psm_generate_stop_package (const PSMCallbackStruct* callbacks, PSPackage* stopPackage, uint8_t reason);

/*
 * High level session endpoint API functions
 */
/**
* Session endpoint call to process a package originating from a session manager
* @param callbacks contains a collection of callback pointers to be called depending on the package type
* @param inBuf contains the buffer encrypted by a session manager
* @param inBufLen is the length of inBuf
* @param sessionPtr is the buffer recieved during the call to pse_generate_greeting and kept updated after each API call
* @param userContext is a user defined pointer that will be passed to all callback functions
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int pse_process_incoming_package (const PSECallbackStruct* callbacks, const uint8_t* inBuf, size_t inBufLen, PSSession* sessionPtr, void* userContext);

/**
* Session endpoint call to start a session by creating a request package to be sent to a session manager.
* @param callbacks contains a collection of callback pointers to be called depending on the package type
* @param startPackage contains input buffer, output buffer, a user context, and a PSSession object that must be held for the life of the session.
* @param requestInfo contains information required to start a session like the session manager public key and unique endpoint device information.
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int pse_generate_greeting(const PSECallbackStruct* callbacks, PSPackage* startPackage, PSRequestInfo* requestInfo);

/**
* Session endpoint call to create a data package for an established session
* @param callbacks contains a collection of callback pointers to be called depending on the package type
* @param responsePackage contains the session information, both input and output buffers, and a user context.
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int pse_generate_data_package (const PSECallbackStruct* callbacks, PSPackage* dataPackage);

/**
* Session endpoint call to create a stop package for an established session.
* @param callbacks contains a collection of callback pointers to be called depending on the package type
* @param stopPackage contains the session information, both input and output buffers, and a user context.
* @param reason contains a numeric value to tell the session endpoint why the session was closed.
* @return On success, PS_ERR_OK otherwise, one of the PS_ERR_* values.
*/
int pse_generate_stop_package (const PSECallbackStruct* callbacks, PSPackage* stopPackage, uint8_t reason);

/**
* Utility function to generate a 32byte public and private key pair
* @param publicKey contains a 32 unsigned byte buffer to hold the public key
* @param privateKey contains a 32 unsigned byte buffer to hold the private key
* @return On success, 0, otherwise -1 for an error
*/
int ps_generate_key_pair(unsigned char* publicKey, unsigned char* privateKey);

#ifdef __cplusplus
}
#endif

#endif /*CENTRI_PS_H_*/
