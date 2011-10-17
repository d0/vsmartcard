/*
 * Copyright (C) 2011 Frank Morgner
 *
 * This file is part of ccid.
 *
 * ccid is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * ccid is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ccid.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "npa.h"
#include "sm.h"
#include "scutil.h"
#include "sslutil.h"
#include <libopensc/asn1.h>
#include <libopensc/log.h>
#include <libopensc/opensc.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cv_cert.h>
#include <openssl/eac.h>
#include <openssl/ta.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pace.h>
#include <string.h>


#define ASN1_APP_IMP_OPT(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION|ASN1_TFLG_OPTIONAL, tag, stname, field, type)
#define ASN1_APP_IMP(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, tag, stname, field, type)

typedef CVC_DISCRETIONARY_DATA_TEMPLATES APDU_DISCRETIONARY_DATA_TEMPLATES;
DECLARE_ASN1_FUNCTIONS(APDU_DISCRETIONARY_DATA_TEMPLATES)
ASN1_ITEM_TEMPLATE(APDU_DISCRETIONARY_DATA_TEMPLATES) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, 0x7,
                APDU_DISCRETIONARY_DATA_TEMPLATES,
                CVC_DISCRETIONARY_DATA_TEMPLATES)
ASN1_ITEM_TEMPLATE_END(APDU_DISCRETIONARY_DATA_TEMPLATES)
IMPLEMENT_ASN1_FUNCTIONS(APDU_DISCRETIONARY_DATA_TEMPLATES)

/*
 * MSE:Set AT
 */

typedef struct npa_mse_set_at_cd_st {
    ASN1_OBJECT *cryptographic_mechanism_reference;
    ASN1_OCTET_STRING *key_reference1;
    ASN1_OCTET_STRING *key_reference2;
    ASN1_OCTET_STRING *eph_pub_key;
    APDU_DISCRETIONARY_DATA_TEMPLATES *auxiliary_data;
    CVC_CHAT *chat;
} NPA_MSE_SET_AT_C;
ASN1_SEQUENCE(NPA_MSE_SET_AT_C) = {
    /* 0x80
     * Cryptographic mechanism reference */
    ASN1_IMP_OPT(NPA_MSE_SET_AT_C, cryptographic_mechanism_reference, ASN1_OBJECT, 0),
    /* 0x83
     * Reference of a public key / secret key */
    ASN1_IMP_OPT(NPA_MSE_SET_AT_C, key_reference1, ASN1_OCTET_STRING, 3),
    /* 0x84
     * Reference of a private key / Reference for computing a session key */
    ASN1_IMP_OPT(NPA_MSE_SET_AT_C, key_reference2, ASN1_OCTET_STRING, 4),
    /* 0x91
     * Ephemeral Public Key */
    ASN1_IMP_OPT(NPA_MSE_SET_AT_C, eph_pub_key, ASN1_OCTET_STRING, 0x11),
    /* 0x67
     * Auxiliary authenticated data */
    ASN1_OPT(NPA_MSE_SET_AT_C, auxiliary_data, APDU_DISCRETIONARY_DATA_TEMPLATES),
    /*ASN1_APP_IMP_OPT(NPA_MSE_SET_AT_C, auxiliary_data, ASN1_OCTET_STRING, 7),*/
    /* Certificate Holder Authorization Template */
    ASN1_OPT(NPA_MSE_SET_AT_C, chat, CVC_CHAT),
} ASN1_SEQUENCE_END(NPA_MSE_SET_AT_C)
DECLARE_ASN1_FUNCTIONS(NPA_MSE_SET_AT_C)
IMPLEMENT_ASN1_FUNCTIONS(NPA_MSE_SET_AT_C)

/* Due to limitations of OpenSSL it is not possible to *encode* an optional
 * item template (such as APDU_DISCRETIONARY_DATA_TEMPLATES). So we need this
 * second type of mse:set at with non-optional discretionary data templates for
 * ta.
 *
 * See also openssl/crypto/asn1/tasn_dec.c:183
 */
typedef struct npa_ta_mse_set_at_cd_st {
    ASN1_OBJECT *cryptographic_mechanism_reference;
    ASN1_OCTET_STRING *key_reference1;
    ASN1_OCTET_STRING *key_reference2;
    ASN1_OCTET_STRING *eph_pub_key;
    APDU_DISCRETIONARY_DATA_TEMPLATES *auxiliary_data;
    CVC_CHAT *chat;
} NPA_TA_MSE_SET_AT_C;
ASN1_SEQUENCE(NPA_TA_MSE_SET_AT_C) = {
    /* 0x80
     * Cryptographic mechanism reference */
    ASN1_IMP_OPT(NPA_TA_MSE_SET_AT_C, cryptographic_mechanism_reference, ASN1_OBJECT, 0),
    /* 0x83
     * Reference of a public key / secret key */
    ASN1_IMP_OPT(NPA_TA_MSE_SET_AT_C, key_reference1, ASN1_OCTET_STRING, 3),
    /* 0x84
     * Reference of a private key / Reference for computing a session key */
    ASN1_IMP_OPT(NPA_TA_MSE_SET_AT_C, key_reference2, ASN1_OCTET_STRING, 4),
    /* 0x91
     * Ephemeral Public Key */
    ASN1_IMP_OPT(NPA_TA_MSE_SET_AT_C, eph_pub_key, ASN1_OCTET_STRING, 0x11),
    /* 0x67
     * Auxiliary authenticated data */
    ASN1_SIMPLE(NPA_TA_MSE_SET_AT_C, auxiliary_data, APDU_DISCRETIONARY_DATA_TEMPLATES),
    /*ASN1_APP_IMP_OPT(NPA_MSE_SET_AT_C, auxiliary_data, ASN1_OCTET_STRING, 7),*/
    /* Certificate Holder Authorization Template */
    ASN1_OPT(NPA_TA_MSE_SET_AT_C, chat, CVC_CHAT),
} ASN1_SEQUENCE_END(NPA_TA_MSE_SET_AT_C)
DECLARE_ASN1_FUNCTIONS(NPA_TA_MSE_SET_AT_C)
IMPLEMENT_ASN1_FUNCTIONS(NPA_TA_MSE_SET_AT_C)


/*
 * General Authenticate
 */

/* Protocol Command Data */
typedef struct npa_gen_auth_cd_st {
    ASN1_OCTET_STRING *mapping_data;
    ASN1_OCTET_STRING *eph_pub_key;
    ASN1_OCTET_STRING *auth_token;
} NPA_GEN_AUTH_C_BODY;
ASN1_SEQUENCE(NPA_GEN_AUTH_C_BODY) = {
    /* 0x81
     * Mapping Data */
    ASN1_IMP_OPT(NPA_GEN_AUTH_C_BODY, mapping_data, ASN1_OCTET_STRING, 1),
    /* 0x83
     * Ephemeral Public Key */
    ASN1_IMP_OPT(NPA_GEN_AUTH_C_BODY, eph_pub_key, ASN1_OCTET_STRING, 3),
    /* 0x85
     * Authentication Token */
    ASN1_IMP_OPT(NPA_GEN_AUTH_C_BODY, auth_token, ASN1_OCTET_STRING, 5),
} ASN1_SEQUENCE_END(NPA_GEN_AUTH_C_BODY)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_C_BODY)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_C_BODY)

typedef NPA_GEN_AUTH_C_BODY NPA_GEN_AUTH_C;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(NPA_GEN_AUTH_C) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x1c, NPA_GEN_AUTH_C, NPA_GEN_AUTH_C_BODY)
ASN1_ITEM_TEMPLATE_END(NPA_GEN_AUTH_C)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_C)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_C)

/* Protocol Response Data */
typedef struct npa_gen_auth_rapdu_body_st {
    ASN1_OCTET_STRING *enc_nonce;
    ASN1_OCTET_STRING *mapping_data;
    ASN1_OCTET_STRING *eph_pub_key;
    ASN1_OCTET_STRING *auth_token;
    ASN1_OCTET_STRING *cur_car;
    ASN1_OCTET_STRING *prev_car;
} NPA_GEN_AUTH_R_BODY;
ASN1_SEQUENCE(NPA_GEN_AUTH_R_BODY) = {
    /* 0x80
     * Encrypted Nonce */
    ASN1_IMP_OPT(NPA_GEN_AUTH_R_BODY, enc_nonce, ASN1_OCTET_STRING, 0),
    /* 0x82
     * Mapping Data */
    ASN1_IMP_OPT(NPA_GEN_AUTH_R_BODY, mapping_data, ASN1_OCTET_STRING, 2),
    /* 0x84
     * Ephemeral Public Key */
    ASN1_IMP_OPT(NPA_GEN_AUTH_R_BODY, eph_pub_key, ASN1_OCTET_STRING, 4),
    /* 0x86
     * Authentication Token */
    ASN1_IMP_OPT(NPA_GEN_AUTH_R_BODY, auth_token, ASN1_OCTET_STRING, 6),
    /* 0x87
     * Most recent Certification Authority Reference */
    ASN1_IMP_OPT(NPA_GEN_AUTH_R_BODY, cur_car, ASN1_OCTET_STRING, 7),
    /* 0x88
     * Previous Certification Authority Reference */
    ASN1_IMP_OPT(NPA_GEN_AUTH_R_BODY, prev_car, ASN1_OCTET_STRING, 8),
} ASN1_SEQUENCE_END(NPA_GEN_AUTH_R_BODY)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_R_BODY)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_R_BODY)

typedef NPA_GEN_AUTH_R_BODY NPA_GEN_AUTH_R;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(NPA_GEN_AUTH_R) =
    ASN1_EX_TEMPLATE_TYPE(
            ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
            0x1c, NPA_GEN_AUTH_R, NPA_GEN_AUTH_R_BODY)
ASN1_ITEM_TEMPLATE_END(NPA_GEN_AUTH_R)
DECLARE_ASN1_FUNCTIONS(NPA_GEN_AUTH_R)
IMPLEMENT_ASN1_FUNCTIONS(NPA_GEN_AUTH_R)



#define maxresp SC_MAX_APDU_BUFFER_SIZE - 2

/** NPA secure messaging context */
struct npa_sm_ctx {
    /** Send sequence counter */
    BIGNUM *ssc;
    /** EAC context */
    EAC_CTX *ctx;
    /** Certificate Description given on initialization of PACE */
    BUF_MEM *certificate_description;
    /** picc's compressed ephemeral public key of PACE */
    BUF_MEM *id_icc;
    /** PCD's compressed ephemeral public key of CA */
    BUF_MEM *eph_pub_key;
    /** Auxiliary Data */
    BUF_MEM *auxiliary_data;
    /** Nonce generated in TA */
    BUF_MEM *nonce;
    /** CAR of the card's most recent imported certificate */
    BUF_MEM *cur_car;
    /** CHR of the certificate to be imported */
    BUF_MEM *next_car;
};

static int npa_sm_encrypt(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *data, size_t datalen, u8 **enc);
static int npa_sm_decrypt(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *enc, size_t enclen, u8 **data);
static int npa_sm_authenticate(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *data, size_t datalen, u8 **outdata);
static int npa_sm_verify_authentication(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *mac, size_t maclen,
        const u8 *macdata, size_t macdatalen);
static int npa_sm_pre_transmit(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *apdu);
static int npa_sm_post_transmit(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *sm_apdu);
static int npa_sm_finish(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *apdu);
static void npa_sm_clear_free(const struct sm_ctx *ctx);

static int increment_ssc(struct npa_sm_ctx *eacsmctx);
static int decrement_ssc(struct npa_sm_ctx *eacsmctx);
static int reset_ssc(struct npa_sm_ctx *eacsmctx);

static struct npa_sm_ctx *
npa_sm_ctx_create(EAC_CTX *ctx, const unsigned char *certificate_description,
        size_t certificate_description_length,
        const unsigned char *id_icc, size_t id_icc_length,
        const unsigned char *car, size_t car_length)
{
    struct npa_sm_ctx *out = malloc(sizeof *out);
    if (!out)
        goto err;

    out->ssc = BN_new();
    if (!out->ssc || reset_ssc(out) < 0)
        goto err;

    out->ctx = ctx;

    out->certificate_description = BUF_MEM_create_init(certificate_description,
            certificate_description_length);
    if (!out->certificate_description)
        goto err;

    out->id_icc = BUF_MEM_create_init(id_icc, id_icc_length);
    if (!out->id_icc)
        goto err;

    out->cur_car = BUF_MEM_create_init(car, car_length);
    if (!out->cur_car)
        goto err;

    out->nonce = NULL;
    out->next_car = NULL;
    out->eph_pub_key = NULL;
    out->auxiliary_data = NULL;

    return out;

err:
    if (out) {
        if (out->ssc)
            BN_clear_free(out->ssc);
        free(out);
    }
    return NULL;
}


int GetReadersPACECapabilities(u8 *bitmap)
{
    if (!bitmap)
        return SC_ERROR_INVALID_ARGUMENTS;

    /* BitMap */
    *bitmap = NPA_BITMAP_PACE|NPA_BITMAP_EID|NPA_BITMAP_ESIGN;

    return SC_SUCCESS;
}

/** select and read EF.CardAccess */
int get_ef_card_access(sc_card_t *card,
        u8 **ef_cardaccess, size_t *length_ef_cardaccess)
{
    int r;
    /* we read less bytes than possible. this is a workaround for acr 122,
     * which only supports apdus of max 250 bytes */
    size_t read = maxresp - 8;
    sc_path_t path;
    sc_file_t *file = NULL;
    u8 *p;

    if (!card || !ef_cardaccess || !length_ef_cardaccess) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }

    memcpy(&path, sc_get_mf_path(), sizeof path);
    r = sc_append_file_id(&path, FID_EF_CARDACCESS);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create path object.");
        goto err;
    }

    r = sc_select_file(card, &path, &file);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select EF.CardAccess.");
        goto err;
    }

    *length_ef_cardaccess = 0;
    while(1) {
        p = realloc(*ef_cardaccess, *length_ef_cardaccess + read);
        if (!p) {
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        *ef_cardaccess = p;

        r = sc_read_binary(card, *length_ef_cardaccess,
                *ef_cardaccess + *length_ef_cardaccess, read, 0);

        if (r > 0 && r != read) {
            *length_ef_cardaccess += r;
            break;
        }

        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read EF.CardAccess.");
            goto err;
        }

        *length_ef_cardaccess += r;
    }

    /* test cards only return an empty FCI template,
     * so we can't determine any file proberties */
    if (*length_ef_cardaccess < file->size) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Actual filesize differs from the size in file "
                "proberties (%u!=%u).", *length_ef_cardaccess, file->size);
        r = SC_ERROR_FILE_TOO_SMALL;
        goto err;
    }

    /* All cards with PACE support extended length
     * XXX this should better be done by the card driver */
    card->caps |= SC_CARD_CAP_APDU_EXT;

    r = SC_SUCCESS;

err:
    if (file) {
        free(file);
    }

    return r;
}

static int npa_mse_set_at(struct sm_ctx *oldnpactx, sc_card_t *card,
        int protocol, int secret_key, const CVC_CHAT *chat, u8 *sw1, u8 *sw2)
{
    sc_apdu_t apdu;
    unsigned char *d = NULL;
    NPA_MSE_SET_AT_C *data = NULL;
    int r, tries, class, tag;
    long length;
    const unsigned char *p;

    memset(&apdu, 0, sizeof apdu);

    if (!card || !sw1 || !sw2) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }

    apdu.ins = 0x22;
    apdu.p1 = 0xc1;
    apdu.p2 = 0xa4;
    apdu.cse = SC_APDU_CASE_3_SHORT;
    apdu.flags = SC_APDU_FLAGS_NO_GET_RESP|SC_APDU_FLAGS_NO_RETRY_WL;


    data = NPA_MSE_SET_AT_C_new();
    if (!data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }

    data->cryptographic_mechanism_reference = OBJ_nid2obj(protocol);
    data->key_reference1 = ASN1_INTEGER_new();

    if (!data->cryptographic_mechanism_reference
            || !data->key_reference1) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }

    if (!ASN1_INTEGER_set(data->key_reference1, secret_key)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error setting key reference 1 of MSE:Set AT data");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    data->chat = (CVC_CHAT *) chat;


    r = i2d_NPA_MSE_SET_AT_C(data, &d);
    p = d;
    if (r < 0
            || (0x80 & ASN1_get_object(&p, &length, &tag, &class, r))) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error encoding MSE:Set AT APDU data");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = p;
    apdu.datalen = length;
    apdu.lc = length;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "MSE:Set AT command data", apdu.data, apdu.datalen);

    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    if (apdu.resplen) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "MSE:Set AT response data should be empty "
                "(contains %u bytes)", apdu.resplen);
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }

    *sw1 = apdu.sw1;
    *sw2 = apdu.sw2;

    if (apdu.sw1 == 0x63) {
        if ((apdu.sw2 & 0xc0) == 0xc0) {
            tries = apdu.sw2 & 0x0f;
            if (tries <= 1) {
                /* this is only a warning... */
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Remaining tries: %d (%s must be %s)\n",
                        tries, npa_secret_name(secret_key),
                        tries ? "resumed" : "unblocked");
            }
            r = SC_SUCCESS;
        } else {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Unknown status bytes: SW1=%02X, SW2=%02X\n",
                    apdu.sw1, apdu.sw2);
            r = SC_ERROR_CARD_CMD_FAILED;
            goto err;
        }
    } else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x83) {
             sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Password is deactivated\n");
             r = SC_ERROR_AUTH_METHOD_BLOCKED;
             goto err;
    } else {
        r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    }

err:
    if (apdu.resp)
        free(apdu.resp);
    if (data) {
        /* do not free the functions parameter chat */
        data->chat = NULL;
        NPA_MSE_SET_AT_C_free(data);
    }
    if (d)
        free(d);

    return r;
}

static int npa_gen_auth_1_encrypted_nonce(struct sm_ctx *oldnpactx,
        sc_card_t *card, u8 **enc_nonce, size_t *enc_nonce_len)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_C *c_data = NULL;
    NPA_GEN_AUTH_R *r_data = NULL;
    unsigned char *d = NULL, *p;
    int r, l;
	unsigned char resp[maxresp];

    memset(&apdu, 0, sizeof apdu);
    apdu.cla = 0x10;
    apdu.ins = 0x86;
    apdu.cse = SC_APDU_CASE_4_SHORT;
    apdu.flags = SC_APDU_FLAGS_NO_GET_RESP|SC_APDU_FLAGS_NO_RETRY_WL;

    c_data = NPA_GEN_AUTH_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Encrypted Nonce) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Encrypted Nonce) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (!r_data->enc_nonce
            || r_data->mapping_data
            || r_data->eph_pub_key
            || r_data->auth_token
            || r_data->cur_car
            || r_data->prev_car) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
                "step 1 should (only) contain the encrypted nonce.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }
    p = r_data->enc_nonce->data;
    l = r_data->enc_nonce->length;

    *enc_nonce = malloc(l);
    if (!*enc_nonce) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    /* Flawfinder: ignore */
    memcpy(*enc_nonce, p, l);
    *enc_nonce_len = l;

err:
    if (c_data)
        NPA_GEN_AUTH_C_free(c_data);
    if (d)
        free(d);
    if (r_data)
        NPA_GEN_AUTH_R_free(r_data);

    return r;
}
static int npa_gen_auth_2_map_nonce(struct sm_ctx *oldnpactx,
        sc_card_t *card, const u8 *in, size_t in_len, u8 **map_data_out,
        size_t *map_data_out_len)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_C *c_data = NULL;
    NPA_GEN_AUTH_R *r_data = NULL;
    unsigned char *d = NULL, *p;
    int r, l;
	unsigned char resp[maxresp];

    memset(&apdu, 0, sizeof apdu);
    apdu.cla = 0x10;
    apdu.ins = 0x86;
    apdu.cse = SC_APDU_CASE_4_SHORT;
    apdu.flags = SC_APDU_FLAGS_NO_GET_RESP|SC_APDU_FLAGS_NO_RETRY_WL;

    c_data = NPA_GEN_AUTH_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    c_data->mapping_data = ASN1_OCTET_STRING_new();
    if (!c_data->mapping_data
            || !M_ASN1_OCTET_STRING_set(
                c_data->mapping_data, in, in_len)) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Map Nonce) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Map Nonce) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (r_data->enc_nonce
            || !r_data->mapping_data
            || r_data->eph_pub_key
            || r_data->auth_token
            || r_data->cur_car
            || r_data->prev_car) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
                "step 2 should (only) contain the mapping data.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }
    p = r_data->mapping_data->data;
    l = r_data->mapping_data->length;

    *map_data_out = malloc(l);
    if (!*map_data_out) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    /* Flawfinder: ignore */
    memcpy(*map_data_out, p, l);
    *map_data_out_len = l;

err:
    if (c_data)
        NPA_GEN_AUTH_C_free(c_data);
    if (d)
        free(d);
    if (r_data)
        NPA_GEN_AUTH_R_free(r_data);

    return r;
}
static int npa_gen_auth_3_perform_key_agreement(
        struct sm_ctx *oldnpactx, sc_card_t *card,
        const u8 *in, size_t in_len, u8 **eph_pub_key_out, size_t *eph_pub_key_out_len)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_C *c_data = NULL;
    NPA_GEN_AUTH_R *r_data = NULL;
    unsigned char *d = NULL, *p;
    int r, l;
	unsigned char resp[maxresp];

    memset(&apdu, 0, sizeof apdu);
    apdu.cla = 0x10;
    apdu.ins = 0x86;
    apdu.cse = SC_APDU_CASE_4_SHORT;
    apdu.flags = SC_APDU_FLAGS_NO_GET_RESP|SC_APDU_FLAGS_NO_RETRY_WL;

    c_data = NPA_GEN_AUTH_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    c_data->eph_pub_key = ASN1_OCTET_STRING_new();
    if (!c_data->eph_pub_key
            || !M_ASN1_OCTET_STRING_set(
                c_data->eph_pub_key, in, in_len)) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (r_data->enc_nonce
            || r_data->mapping_data
            || !r_data->eph_pub_key
            || r_data->auth_token
            || r_data->cur_car
            || r_data->prev_car) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
                "step 3 should (only) contain the ephemeral public key.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }
    p = r_data->eph_pub_key->data;
    l = r_data->eph_pub_key->length;

    *eph_pub_key_out = malloc(l);
    if (!*eph_pub_key_out) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    /* Flawfinder: ignore */
    memcpy(*eph_pub_key_out, p, l);
    *eph_pub_key_out_len = l;

err:
    if (c_data)
        NPA_GEN_AUTH_C_free(c_data);
    if (d)
        free(d);
    if (r_data)
        NPA_GEN_AUTH_R_free(r_data);

    return r;
}
static int npa_gen_auth_4_mutual_authentication(
        struct sm_ctx *oldnpactx, sc_card_t *card,
        const u8 *in, size_t in_len, u8 **auth_token_out,
        size_t *auth_token_out_len, u8 **recent_car, size_t *recent_car_len,
        u8 **prev_car, size_t *prev_car_len)
{
    sc_apdu_t apdu;
    NPA_GEN_AUTH_C *c_data = NULL;
    NPA_GEN_AUTH_R *r_data = NULL;
    unsigned char *d = NULL, *p;
    int r, l;
	unsigned char resp[maxresp];

    memset(&apdu, 0, sizeof apdu);
    apdu.cla = 0x10;
    apdu.ins = 0x86;
    apdu.cse = SC_APDU_CASE_4_SHORT;
    apdu.flags = SC_APDU_FLAGS_NO_GET_RESP|SC_APDU_FLAGS_NO_RETRY_WL;

    c_data = NPA_GEN_AUTH_C_new();
    if (!c_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    apdu.cla = 0;
    c_data->auth_token = ASN1_OCTET_STRING_new();
    if (!c_data->auth_token
            || !M_ASN1_OCTET_STRING_set(
                c_data->auth_token, in, in_len)) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = i2d_NPA_GEN_AUTH_C(c_data, &d);
    if (r < 0) {
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    apdu.data = (const u8 *) d;
    apdu.datalen = r;
    apdu.lc = r;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) command data", apdu.data, apdu.datalen);

    apdu.resplen = sizeof resp;
    apdu.resp = resp;
    if (oldnpactx)
        r = sm_transmit_apdu(oldnpactx, card, &apdu);
    else
        r = sc_transmit_apdu(card, &apdu);
    if (r < 0)
        goto err;

    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r < 0)
        goto err;

    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "General authenticate (Perform Key Agreement) response data", apdu.resp, apdu.resplen);

    if (!d2i_NPA_GEN_AUTH_R(&r_data,
                (const unsigned char **) &apdu.resp, apdu.resplen)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (r_data->enc_nonce
            || r_data->mapping_data
            || r_data->eph_pub_key
            || !r_data->auth_token) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
                "step 4 should (only) contain the authentication token.");
        r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
        goto err;
    }
    p = r_data->auth_token->data;
    l = r_data->auth_token->length;
    if (r_data->cur_car) {
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Most recent Certificate Authority Reference",
                r_data->cur_car->data, r_data->cur_car->length);
        *recent_car = malloc(r_data->cur_car->length);
        if (!*recent_car) {
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        /* Flawfinder: ignore */
        memcpy(*recent_car, r_data->cur_car->data, r_data->cur_car->length);
        *recent_car_len = r_data->cur_car->length;
    } else
        *recent_car_len = 0;
    if (r_data->prev_car) {
        bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Previous Certificate Authority Reference",
                r_data->prev_car->data, r_data->prev_car->length);
        *prev_car = malloc(r_data->prev_car->length);
        if (!*prev_car) {
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        /* Flawfinder: ignore */
        memcpy(*prev_car, r_data->prev_car->data, r_data->prev_car->length);
        *prev_car_len = r_data->prev_car->length;
    } else
        *prev_car_len = 0;

    *auth_token_out = malloc(l);
    if (!*auth_token_out) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    /* Flawfinder: ignore */
    memcpy(*auth_token_out, p, l);
    *auth_token_out_len = l;

err:
    if (c_data)
        NPA_GEN_AUTH_C_free(c_data);
    if (d)
        free(d);
    if (r_data)
        NPA_GEN_AUTH_R_free(r_data);

    return r;
}

int
npa_reset_retry_counter(struct sm_ctx *ctx, sc_card_t *card,
        enum s_type pin_id, int ask_for_secret,
        const char *new, size_t new_len)
{
    sc_apdu_t apdu;
    char *p = NULL;
    int r;

    if (ask_for_secret && (!new || !new_len)) {
        p = malloc(MAX_PIN_LEN+1);
        if (!p) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for new PIN.\n");
            return SC_ERROR_OUT_OF_MEMORY;
        }
        if (0 > EVP_read_pw_string_min(p,
                    MIN_PIN_LEN, MAX_PIN_LEN+1,
                    "Please enter your new PIN: ", 0)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read new PIN.\n");
            free(p);
            return SC_ERROR_INTERNAL;
        }
        new_len = strlen(p);
        if (new_len > MAX_PIN_LEN)
            return SC_ERROR_INVALID_PIN_LENGTH;
        new = p;
    }

    memset(&apdu, 0, sizeof apdu);
    apdu.ins = 0x2C;
    apdu.p2 = pin_id;
    apdu.data = (u8 *) new;
    apdu.datalen = new_len;
    apdu.lc = apdu.datalen;
    apdu.flags = SC_APDU_FLAGS_NO_GET_RESP|SC_APDU_FLAGS_NO_RETRY_WL;

    if (new_len) {
        apdu.p1 = 0x02;
        apdu.cse = SC_APDU_CASE_3_SHORT;
    } else {
        apdu.p1 = 0x03;
        apdu.cse = SC_APDU_CASE_1;
    }

    r = sm_transmit_apdu(ctx, card, &apdu);

    if (p) {
        OPENSSL_cleanse(p, new_len);
        free(p);
    }

    return r;
}

static PACE_SEC *
get_psec(sc_card_t *card, const char *pin, size_t length_pin, enum s_type pin_id)
{
    char *p = NULL;
    PACE_SEC *r;
    int sc_result;
    /* Flawfinder: ignore */
    char buf[MAX_MRZ_LEN > 32 ? MAX_MRZ_LEN : 32];

    if (!length_pin || !pin) {
        if (0 > snprintf(buf, sizeof buf, "Please enter your %s: ",
                    npa_secret_name(pin_id))) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create password prompt.\n");
            return NULL;
        }
        p = malloc(MAX_MRZ_LEN+1);
        if (!p) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for %s.\n",
                    npa_secret_name(pin_id));
            return NULL;
        }
        if (0 > EVP_read_pw_string_min(p, 0, MAX_MRZ_LEN, buf, 0)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read %s.\n",
                    npa_secret_name(pin_id));
            return NULL;
        }
        length_pin = strlen(p);
        if (length_pin > MAX_MRZ_LEN) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "MRZ too long");
            return NULL;
        }
        pin = p;
    }

    r = PACE_SEC_new(pin, length_pin, pin_id);

    if (p) {
        OPENSSL_cleanse(p, length_pin);
        free(p);
    }

    return r;
}

int EstablishPACEChannel(struct sm_ctx *oldnpactx, sc_card_t *card,
        struct establish_pace_channel_input pace_input,
        struct establish_pace_channel_output *pace_output,
        struct sm_ctx *sctx)
{
    u8 *p = NULL;
	EAC_CTX *eac_ctx = NULL;
	BUF_MEM *enc_nonce = NULL, *mdata = NULL, *mdata_opp = NULL,
			*token_opp = NULL, *token = NULL, *pub = NULL, *pub_opp = NULL,
			*comp_pub = NULL, *comp_pub_opp = NULL;
    PACE_SEC *sec = NULL;
    CVC_CHAT *chat = NULL;
    BIO *bio_stdout = NULL;
	CVC_CERTIFICATE_DESCRIPTION *desc = NULL;
    int r;
    const unsigned char *pp;

    if (!card || !pace_output || !sctx)
        return SC_ERROR_INVALID_ARGUMENTS;

    /* show description in advance to give the user more time to read it...
     * This behaviour differs from TR-03119 v1.1 p. 44. */
    if (pace_input.certificate_description_length &&
            pace_input.certificate_description) {

        pp = pace_input.certificate_description;
		if (!d2i_CVC_CERTIFICATE_DESCRIPTION(&desc,
                    &pp, pace_input.certificate_description_length)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse certificate description.");
            ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

        if (!bio_stdout)
            bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (!bio_stdout) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create output buffer.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        printf("Certificate Description\n");
		switch(certificate_description_print(bio_stdout, desc, 8)) {
            case 0:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not print certificate description.");
                ssl_error(card->ctx);
                r = SC_ERROR_INTERNAL;
                goto err;
                break;
            case 1:
                /* text format */
                break;
            case 2:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
                        "HTML format can not (yet) be handled.");
                r = SC_ERROR_NOT_SUPPORTED;
                goto err;
                break;
            case 3:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
                        "PDF format can not (yet) be handled.");
                r = SC_ERROR_NOT_SUPPORTED;
                goto err;
                break;
            default:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
                        "unknown format can not be handled.");
                r = SC_ERROR_NOT_SUPPORTED;
                goto err;
                break;
        }
    }

    /* show chat in advance to give the user more time to read it...
     * This behaviour differs from TR-03119 v1.1 p. 44. */
    if (pace_input.chat_length && pace_input.chat) {

        if (!bio_stdout)
            bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (!bio_stdout) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create output buffer.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        pp = pace_input.chat;
        if (!d2i_CVC_CHAT(&chat, &pp, pace_input.chat_length)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse card holder authorization template (CHAT).");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        printf("Card holder authorization template (CHAT)\n");
        if (!cvc_chat_print(bio_stdout, chat, 8)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not print card holder authorization template (CHAT).");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }
    }

    if (!pace_output->ef_cardaccess_length || !pace_output->ef_cardaccess) {
        r = get_ef_card_access(card, &pace_output->ef_cardaccess,
                &pace_output->ef_cardaccess_length);
        if (r < 0) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get EF.CardAccess.");
            goto err;
        }
    }
    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "EF.CardAccess", pace_output->ef_cardaccess,
            pace_output->ef_cardaccess_length);

	eac_ctx = EAC_CTX_new();
    if (!eac_ctx
			|| !EAC_CTX_init_ef_cardaccess(pace_output->ef_cardaccess,
				pace_output->ef_cardaccess_length, eac_ctx)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse EF.CardAccess.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    eac_ctx->tr_version = pace_input.tr_version;

    r = npa_mse_set_at(oldnpactx, card, eac_ctx->pace_ctx->protocol, pace_input.pin_id,
            chat, &pace_output->mse_set_at_sw1, &pace_output->mse_set_at_sw2);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol proberties "
                "(MSE: Set AT failed).");
        goto err;
    }
    enc_nonce = BUF_MEM_new();
    if (!enc_nonce) {
        ssl_error(card->ctx);
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    r = npa_gen_auth_1_encrypted_nonce(oldnpactx, card, (u8 **) &enc_nonce->data,
            &enc_nonce->length);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get encrypted nonce from card "
                "(General Authenticate step 1 failed).");
        goto err;
    }
    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Encrypted nonce from MRTD", (u8 *)enc_nonce->data, enc_nonce->length);
    enc_nonce->max = enc_nonce->length;

    sec = get_psec(card, (char *) pace_input.pin, pace_input.pin_length,
            pace_input.pin_id);
    if (!sec) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not encode PACE secret.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (!PACE_STEP2_dec_nonce(eac_ctx, sec, enc_nonce)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not decrypt MRTD's nonce.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    mdata_opp = BUF_MEM_new();
    mdata = PACE_STEP3A_generate_mapping_data(eac_ctx);
    if (!mdata || !mdata_opp) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate mapping data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = npa_gen_auth_2_map_nonce(oldnpactx, card, (u8 *) mdata->data, mdata->length,
            (u8 **) &mdata_opp->data, &mdata_opp->length);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange mapping data with card "
                "(General Authenticate step 2 failed).");
        goto err;
    }
    mdata_opp->max = mdata_opp->length;
    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Mapping data from MRTD", (u8 *) mdata_opp->data, mdata_opp->length);

    if (!PACE_STEP3A_map_generator(eac_ctx, mdata_opp)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not map generator.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    pub = PACE_STEP3B_generate_ephemeral_key(eac_ctx);
    pub_opp = BUF_MEM_new();
    if (!pub || !pub_opp) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate ephemeral domain parameter or "
                "ephemeral key pair.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = npa_gen_auth_3_perform_key_agreement(oldnpactx, card, (u8 *) pub->data, pub->length,
            (u8 **) &pub_opp->data, &pub_opp->length);
    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange ephemeral public key with card "
                "(General Authenticate step 3 failed).");
        goto err;
    }
    pub_opp->max = pub_opp->length;
    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "Ephemeral public key from MRTD", (u8 *) pub_opp->data, pub_opp->length);

    
    if (!PACE_STEP3B_compute_shared_secret(eac_ctx, pub_opp)
			|| !PACE_STEP3C_derive_keys(eac_ctx)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compute ephemeral shared secret or "
                "derive keys for encryption and authentication.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    token = PACE_STEP3D_compute_authentication_token(eac_ctx, pub_opp);
    token_opp = BUF_MEM_new();
    if (!token || !token_opp) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compute authentication token.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    r = npa_gen_auth_4_mutual_authentication(oldnpactx, card, (u8 *) token->data, token->length,
            (u8 **) &token_opp->data, &token_opp->length,
            &pace_output->recent_car, &pace_output->recent_car_length,
            &pace_output->previous_car, &pace_output->previous_car_length);

    if (r < 0) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange authentication token with card "
                "(General Authenticate step 4 failed).");
        goto err;
    }
    token_opp->max = token_opp->length;

    if (!PACE_STEP3D_verify_authentication_token(eac_ctx, token_opp)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not verify authentication token.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    /* Initialize secure channel */
    if (!EAC_CTX_set_encryption_ctx(eac_ctx, EAC_ID_PACE)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize encryption.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    /* Identifier for ICC and PCD */
    comp_pub = EAC_Comp(eac_ctx, EAC_ID_PACE, pub);
    comp_pub_opp = EAC_Comp(eac_ctx, EAC_ID_PACE, pub_opp);
    if (!comp_pub || !comp_pub_opp) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compress public keys for identification.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    p = realloc(pace_output->id_icc, comp_pub_opp->length);
    if (!p) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for ID ICC.\n");
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    pace_output->id_icc = p;
    pace_output->id_icc_length = comp_pub_opp->length;
    /* Flawfinder: ignore */
    memcpy(pace_output->id_icc, comp_pub_opp->data, comp_pub_opp->length);
    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "ID ICC", pace_output->id_icc,
            pace_output->id_icc_length);
    p = realloc(pace_output->id_pcd, comp_pub->length);
    if (!p) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for ID PCD.\n");
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    pace_output->id_pcd = p;
    pace_output->id_pcd_length = comp_pub->length;
    /* Flawfinder: ignore */
    memcpy(pace_output->id_pcd, comp_pub->data, comp_pub->length);
    bin_log(card->ctx, SC_LOG_DEBUG_NORMAL, "ID PCD", pace_output->id_pcd,
            pace_output->id_pcd_length);

    if(!EAC_CTX_init_ta(eac_ctx, NULL, 0, NULL, 0, pace_output->recent_car,
                pace_output->recent_car_length)) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize TA.\n");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }
    eac_ctx->ta_ctx->flags |= TA_FLAG_SKIP_TIMECHECK;

    sctx->priv_data = npa_sm_ctx_create(eac_ctx,
            pace_input.certificate_description,
            pace_input.certificate_description_length,
            pace_output->id_icc,
            pace_output->id_icc_length,
            pace_output->recent_car,
            pace_output->recent_car_length);
    if (!sctx->priv_data) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    sctx->authenticate = npa_sm_authenticate;
    sctx->encrypt = npa_sm_encrypt;
    sctx->decrypt = npa_sm_decrypt;
    sctx->verify_authentication = npa_sm_verify_authentication;
    sctx->pre_transmit = npa_sm_pre_transmit;
    sctx->post_transmit = npa_sm_post_transmit;
    sctx->finish = npa_sm_finish;
    sctx->clear_free = npa_sm_clear_free;
    sctx->padding_indicator = SM_ISO_PADDING;
    sctx->block_length = EVP_CIPHER_block_size(eac_ctx->key_ctx->cipher);
    sctx->active = 1;

err:
    if (enc_nonce)
        BUF_MEM_free(enc_nonce);
    if (mdata)
        BUF_MEM_free(mdata);
    if (mdata_opp)
        BUF_MEM_free(mdata_opp);
    if (token_opp)
        BUF_MEM_free(token_opp);
    if (token)
        BUF_MEM_free(token);
    if (pub)
        BUF_MEM_free(pub);
    if (pub_opp)
        BUF_MEM_free(pub_opp);
    if (comp_pub_opp)
        BUF_MEM_free(comp_pub_opp);
    if (comp_pub)
        BUF_MEM_free(comp_pub);
    if (sec)
        PACE_SEC_clear_free(sec);
    if (bio_stdout)
        BIO_free_all(bio_stdout);
    if (desc)
        CVC_CERTIFICATE_DESCRIPTION_free(desc);

    if (r < 0) {
        if (eac_ctx)
            EAC_CTX_clear_free(eac_ctx);
        if (sctx->priv_data)
            npa_sm_clear_free(sctx->priv_data);
    }

    return r;
}

static const char *MRZ_name = "MRZ";
static const char *PIN_name = "PIN";
static const char *PUK_name = "PUK";
static const char *CAN_name = "CAN";
static const char *UNDEF_name = "UNDEF";
const char *npa_secret_name(enum s_type pin_id) {
    switch (pin_id) {
        case PACE_MRZ:
            return MRZ_name;
        case PACE_PUK:
            return PUK_name;
        case PACE_PIN:
            return PIN_name;
        case PACE_CAN:
            return CAN_name;
        default:
            return UNDEF_name;
    }
}

int
increment_ssc(struct npa_sm_ctx *eacsmctx)
{
    if (!eacsmctx)
        return SC_ERROR_INVALID_ARGUMENTS;

    BN_add_word(eacsmctx->ssc, 1);

    return SC_SUCCESS;
}

int
decrement_ssc(struct npa_sm_ctx *eacsmctx)
{
    if (!eacsmctx)
        return SC_ERROR_INVALID_ARGUMENTS;

    BN_sub_word(eacsmctx->ssc, 1);

    return SC_SUCCESS;
}

int
reset_ssc(struct npa_sm_ctx *eacsmctx)
{
    if (!eacsmctx)
        return SC_ERROR_INVALID_ARGUMENTS;

    BN_zero(eacsmctx->ssc);

    return SC_SUCCESS;
}

static int
npa_sm_encrypt(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *data, size_t datalen, u8 **enc)
{
    BUF_MEM *encbuf = NULL, *databuf = NULL;
    u8 *p = NULL;
    int r;

    if (!card || !ctx || !enc || !ctx->priv_data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    databuf = BUF_MEM_create_init(data, datalen);
    encbuf = EAC_encrypt(eacsmctx->ctx, eacsmctx->ssc, databuf);
    if (!databuf || !encbuf) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not encrypt data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    p = realloc(*enc, encbuf->length);
    if (!p) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    *enc = p;
    /* Flawfinder: ignore */
    memcpy(*enc, encbuf->data, encbuf->length);
    r = encbuf->length;

err:
    if (databuf) {
        OPENSSL_cleanse(databuf->data, databuf->max);
        BUF_MEM_free(databuf);
    }
    if (encbuf)
        BUF_MEM_free(encbuf);

    return r;
}

static int
npa_sm_decrypt(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *enc, size_t enclen, u8 **data)
{
    BUF_MEM *encbuf = NULL, *databuf = NULL;
    u8 *p = NULL;
    int r;

    if (!card || !ctx || !enc || !ctx->priv_data || !data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    encbuf = BUF_MEM_create_init(enc, enclen);
    databuf = EAC_decrypt(eacsmctx->ctx, eacsmctx->ssc, encbuf);
    if (!encbuf || !databuf) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not decrypt data.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    p = realloc(*data, databuf->length);
    if (!p) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    *data = p;
    /* Flawfinder: ignore */
    memcpy(*data, databuf->data, databuf->length);
    r = databuf->length;

err:
    if (databuf) {
        OPENSSL_cleanse(databuf->data, databuf->max);
        BUF_MEM_free(databuf);
    }
    if (encbuf)
        BUF_MEM_free(encbuf);

    return r;
}

static int
npa_sm_authenticate(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *data, size_t datalen, u8 **macdata)
{
    BUF_MEM *macbuf = NULL;
    u8 *p = NULL, *ssc = NULL;
    int r;

    if (!card || !ctx || !ctx->priv_data || !macdata) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

	macbuf = EAC_authenticate(eacsmctx->ctx, eacsmctx->ssc, data, datalen);
    if (!macbuf) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                "Could not compute message authentication code (MAC).");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    p = realloc(*macdata, macbuf->length);
    if (!p) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto err;
    }
    *macdata = p;
    /* Flawfinder: ignore */
    memcpy(*macdata, macbuf->data, macbuf->length);
    r = macbuf->length;

err:
    if (macbuf)
        BUF_MEM_free(macbuf);
    if (ssc)
        free(ssc);

    return r;
}

static int
npa_sm_verify_authentication(sc_card_t *card, const struct sm_ctx *ctx,
        const u8 *mac, size_t maclen,
        const u8 *macdata, size_t macdatalen)
{
    int r;
    char *p;
    BUF_MEM *my_mac = NULL;

    if (!card || !ctx || !ctx->priv_data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

	my_mac = EAC_authenticate(eacsmctx->ctx, eacsmctx->ssc, macdata,
			macdatalen);
    if (!my_mac) {
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                "Could not compute message authentication code (MAC) for verification.");
        ssl_error(card->ctx);
        r = SC_ERROR_INTERNAL;
        goto err;
    }

    if (my_mac->length != maclen ||
            memcmp(my_mac->data, mac, maclen) != 0) {
        r = SC_ERROR_OBJECT_NOT_VALID;
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                "Authentication data not verified");
        goto err;
    }

    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Authentication data verified");

    r = SC_SUCCESS;

err:
    if (my_mac)
        BUF_MEM_free(my_mac);

    return r;
}

static int
add_tag(unsigned char **asn1new, int constructed, int tag,
        int xclass, const unsigned char *data, size_t len)
{
    unsigned char *p;
    int newlen;

    if (!asn1new || !data)
        return -1;

    newlen = ASN1_object_size(constructed, len, tag);
    if (newlen < 0)
        return newlen;

    p = OPENSSL_realloc(*asn1new, newlen);
    if (!p)
        return -1;
    *asn1new = p;

    ASN1_put_object(&p, constructed, len, tag, xclass);
    memcpy(p, data, len);

    return newlen;
}
extern int
cvc_certificate_extension_print(BIO *bio,
        CVC_DISCRETIONARY_DATA_TEMPLATE *extension, int indent);
static int
npa_sm_pre_transmit(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *apdu)
{
    int r;
    CVC_CERT *cvc_cert = NULL;
    unsigned char *cert = NULL;
    int len;
    BUF_MEM *signature = NULL;
    unsigned char *sequence = NULL;
    NPA_TA_MSE_SET_AT_C *msesetat = NULL;
    const unsigned char *p;

    if (!card || !ctx || !apdu || !ctx->priv_data) {
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto err;
    }
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    if (apdu->ins == 0x22 && apdu->p1 == 0x81 && apdu->p2 == 0xbe) {
        /* MSE:Set DST
         * setup certificate verification for TA */

        if (!eacsmctx->cur_car || !eacsmctx->cur_car->length != apdu->datalen
                || memcmp(eacsmctx->cur_car->data, apdu->data, apdu->datalen) != 0) {
            r = SC_ERROR_INVALID_DATA;
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                    "CAR doesn't match the most recent imported certificate");
            goto err;
        }
        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "CAR matches the most recent imported certificate");

    } else if (apdu->ins == 0x2a && apdu->p1 == 0x00 && apdu->p2 == 0xbe) {
        /* PSO:Verify Certificate
         * check certificate description to match given certificate */

        len = add_tag(&cert, 1, 0x21, V_ASN1_APPLICATION, apdu->data, apdu->datalen);
        p = cert;
        if (len < 0 || !d2i_CVC_CERT(&cvc_cert, &p, len)
                || !cvc_cert || !cvc_cert->body) {
            r = SC_ERROR_INVALID_DATA;
            goto err;
        }

        switch (CVC_get_terminal_type(cvc_cert->body->chat)) {
            case CVC_CVCA:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing CVCA certificate");
                break;

            case CVC_DV:
            case CVC_DocVer:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing DV certificate");
                break;

            case CVC_Terminal:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing Terminal certificate");

                if (!eacsmctx->certificate_description) {
                    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                            "Certificate Description missing");
                    r = SC_ERROR_INVALID_DATA;
                    goto err;
                }

                switch (CVC_check_description(cvc_cert,
                            eacsmctx->certificate_description->data,
                            eacsmctx->certificate_description->length)) {
                    case 1:
                        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                                "Certificate Description matches Certificate");
                        break;
                    case 0:
                        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                                "Certificate Description doesn't match Certificate");
                        r = SC_ERROR_INVALID_DATA;
                        goto err;
                        break;
                    default:
                        sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                                "Error verifying Certificate Description");
                        ssl_error(card->ctx);
                        r = SC_ERROR_INTERNAL;
                        goto err;
                        break;
                }
                break;

            default:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Unknown type of certificate");
                r = SC_ERROR_INVALID_DATA;
                goto err;
                break;
        }

        if (!TA_STEP2_import_certificate(eacsmctx->ctx, cert, len)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                    "Error importing certificate");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }

        if (eacsmctx->next_car)
            BUF_MEM_free(eacsmctx->next_car);
        if (cvc_cert->body->certificate_holder_reference) {
            eacsmctx->next_car = BUF_MEM_create_init(apdu->data, apdu->datalen);
            if (!eacsmctx->next_car) {
                r = SC_ERROR_OUT_OF_MEMORY;
                goto err;
            }
        } else {
            eacsmctx->next_car = NULL;
        }

    } else if (apdu->ins == 0x22 && apdu->p1 == 0x81 && apdu->p2 == 0xa4) {
        /* MSE:Set AT
         * fetch auxiliary data and terminal's compressed ephemeral public key
         * for CA */

        len = add_tag(&sequence, 1, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, apdu->data, apdu->datalen);
        p = sequence;
        if (len < 0 || !d2i_NPA_TA_MSE_SET_AT_C(&msesetat, &p, len)) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse MSE:Set AT.");
            ssl_error(card->ctx);
            r = SC_ERROR_INTERNAL;
            goto err;
        }
        if (msesetat->auxiliary_data) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving terminal's auxiliary data");
            if (eacsmctx->auxiliary_data)
                BUF_MEM_free(eacsmctx->auxiliary_data);
            eacsmctx->auxiliary_data = BUF_MEM_new();
            if (!eacsmctx->auxiliary_data) {
                r = SC_ERROR_OUT_OF_MEMORY;
                goto err;
            }
            eacsmctx->auxiliary_data->length =
                i2d_APDU_DISCRETIONARY_DATA_TEMPLATES(msesetat->auxiliary_data,
                        (unsigned char **) &eacsmctx->auxiliary_data->data);
            if ((int) eacsmctx->auxiliary_data->length < 0) {
                r = SC_ERROR_OUT_OF_MEMORY;
                goto err;
            }
            eacsmctx->auxiliary_data->max = eacsmctx->auxiliary_data->length;
        }
        if (msesetat->eph_pub_key) {
            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving terminal's compressed ephemeral public key");
            if (eacsmctx->eph_pub_key)
                BUF_MEM_free(eacsmctx->eph_pub_key);
            eacsmctx->eph_pub_key =
                BUF_MEM_create_init(msesetat->eph_pub_key->data,
                        msesetat->eph_pub_key->length);
            if (!eacsmctx->eph_pub_key) {
                r = SC_ERROR_OUT_OF_MEMORY;
                goto err;
            }
        }

    } else if (apdu->ins == 0x82 && apdu->p1 == 0x00 && apdu->p2 == 0x00) {
        /* External Authenticate
         * check terminal's signature */

        signature = BUF_MEM_create_init(apdu->data, apdu->datalen);
        if (!signature) {
            r = SC_ERROR_OUT_OF_MEMORY;
            goto err;
        }
        switch (TA_STEP6_verify(eacsmctx->ctx, eacsmctx->eph_pub_key,
                    eacsmctx->id_icc, eacsmctx->nonce,
                    eacsmctx->auxiliary_data, signature)) {
            case 1:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                        "Verified Terminal's signature");
                break;
            case 0:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                        "Terminal's signature not verified");
                r = SC_ERROR_INVALID_DATA;
                goto err;
                break;
            default:
                sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
                        "Error verifying terminal's signature");
                ssl_error(card->ctx);
                r = SC_ERROR_INTERNAL;
                goto err;
                break;
        }
    }

    r = increment_ssc(ctx->priv_data);

err:
    if (cvc_cert)
        CVC_CERT_free(cvc_cert);
    if (signature)
        BUF_MEM_free(signature);
    if (cert)
        OPENSSL_free(cert);
    if (sequence)
        free(sequence);

    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int
npa_sm_post_transmit(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *sm_apdu)
{
    SC_FUNC_RETURN(card->ctx,  SC_LOG_DEBUG_NORMAL,
            increment_ssc(ctx->priv_data));
}

static int
npa_sm_finish(sc_card_t *card, const struct sm_ctx *ctx,
        sc_apdu_t *apdu)
{
    if (!card || !ctx || !ctx->priv_data || !apdu || !card)
        SC_FUNC_RETURN(card->ctx,  SC_LOG_DEBUG_NORMAL,
                SC_ERROR_INVALID_ARGUMENTS);
    struct npa_sm_ctx *eacsmctx = ctx->priv_data;

    if (apdu->sw1 == 0x90 && apdu->sw2 == 0x00) {
        if (apdu->ins == 0x2a && apdu->p1 == 0x00 && apdu->p2 == 0xbe) {
            /* PSO:Verify Certificate
             * copy the currently imported certificate's CHR to the current CAR */

            if (eacsmctx->cur_car)
                BUF_MEM_free(eacsmctx->cur_car);
            eacsmctx->cur_car = eacsmctx->next_car;
            eacsmctx->next_car = NULL;

        } else if (apdu->ins == 0x84 && apdu->p1 == 0x00 && apdu->p2 == 0x00
                && apdu->le == 8 && apdu->resplen == 8) {
            /* Get Challenge
             * copy challenge to EAC context */

            sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving MRTD's nonce to later verify Terminal's signature");

            if (eacsmctx->nonce)
                BUF_MEM_free(eacsmctx->nonce);

            eacsmctx->nonce = BUF_MEM_create_init(apdu->resp, apdu->resplen);
            if (!eacsmctx->nonce)
                SC_FUNC_RETURN(card->ctx,  SC_LOG_DEBUG_NORMAL,
                        SC_ERROR_OUT_OF_MEMORY);
        }
    }

    SC_FUNC_RETURN(card->ctx,  SC_LOG_DEBUG_NORMAL, 0);
}

static void
npa_sm_clear_free(const struct sm_ctx *ctx)
{
    if (ctx) {
        struct npa_sm_ctx *eacsmctx = ctx->priv_data;
        EAC_CTX_clear_free(eacsmctx->ctx);
        if (eacsmctx->ssc)
            BN_clear_free(eacsmctx->ssc);
        if (eacsmctx->certificate_description)
            BUF_MEM_free(eacsmctx->certificate_description);
        if (eacsmctx->nonce)
            BUF_MEM_free(eacsmctx->nonce);
        if (eacsmctx->id_icc)
            BUF_MEM_free(eacsmctx->id_icc);
        if (eacsmctx->eph_pub_key)
            BUF_MEM_free(eacsmctx->eph_pub_key);
        if (eacsmctx->auxiliary_data)
            BUF_MEM_free(eacsmctx->auxiliary_data);
        if (eacsmctx->cur_car)
            BUF_MEM_free(eacsmctx->cur_car);
        if (eacsmctx->next_car)
            BUF_MEM_free(eacsmctx->next_car);
        free(eacsmctx);
    }
}
