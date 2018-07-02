/*
 *  centri_ps_common.h
 *  Protected Sessions Library
 *
 *  Copyright © 2018 CENTRI Technology. All rights reserved.
 */
#ifndef CENTRI_PS_COMMON_H_
#define CENTRI_PS_COMMON_H_

#define PS_SESSION_ID_BYTES     16u
#define PS_KEY_BYTES            32u
#define PS_IV_BYTES             32u
#define PS_NONCE_BYTES          24u

#define PS_ERR_OK               0
#define PS_ERR_ERROR            -1
#define PS_ERR_INCOMPLETE       -2
#define PS_ERR_ARGUMENT         -3
#define PS_ERR_CRYPTO           -4
#define PS_ERR_BAD_DATA         -5
#define PS_ERR_INPUT_TOO_SMALL  -6
#define PS_ERR_INPUT_TOO_BIG    -7
#define PS_ERR_OUTPUT_TOO_SMALL -8
#define PS_ERR_CALLBACK         -9
#define PS_ERR_WRONG_STATE      -10
#define PS_ERR_INCOMPATIBLE     -11

#define PS_STOP_SHUTDOWN        1
#define PS_STOP_REFUSED         2
#define PS_STOP_UNREACHABLE     3

/* These macros are used to estimate the size of a buffer needed to encode each
   package type with attributes of the given sizes. */

#define PS_ENCODING_OLEN_BYTES(ilen)                    ((ilen) + (ilen) / 8 + 128)
#define PS_CALC_PLAIN_PKG_SIZE(payload)                 (171+32 + PS_ENCODING_OLEN_BYTES(payload))
#define PS_CALC_GREETING_PKG_SIZE(deviceId, payload)    (171+32 + PS_ENCODING_OLEN_BYTES((deviceId)  + (payload) + 43))
#define PS_CALC_REPLY_PKG_SIZE(sessionId, payload)      (171+32 + PS_ENCODING_OLEN_BYTES((sessionId) + (payload) + 117))
#define PS_CALC_DATA_PKG_SIZE(sessionId, payload)       (8  +32 + PS_ENCODING_OLEN_BYTES((sessionId) + (payload) + 6))
#define PS_CALC_STOP_PKG_SIZE(sessionId, payload)       (171+32 + PS_ENCODING_OLEN_BYTES((sessionId) + (payload) + 3))

#endif /*CENTRI_PS_COMMON_H_*/
