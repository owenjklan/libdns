/* String routines for DNS library. Split from dns.c on 28th August, 2003.
 * 
 * Written by Owen Klan  -  27th August, 2003
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"

/* This function will take an address in the form foo.bar.com and
 * convert it to the required format. For example:
 * 
 *           foo.bar.com  would give:   0x03foo0x03bar0x03com0x00
 * 
 * Will return NULL on error, otherwise returns a malloc()ed string
 * that the caller must free when finished with. The error parameter
 * is optional and if non-NULL, will be used to store an error code. */
char *dns_convert_name(char *name, int *error)
{
    char *conv_name = NULL;            /* Holds string to return to user */
    char *tok_start, *tok_end;         /* Used for tokenising */
    int len;                           /* Length of created string. */
    int tok_len;
    
    if (!name) {                       /* Make sure we have a name string */
        SET_ERROR(DNS_ERR_NULL_PARAM);
        return NULL;
    }
        
    tok_start = tok_end = name;
    len = strlen(name) + 2;
    
    if ((conv_name = malloc(len)) == NULL) {
        SET_ERROR(DNS_ERR_SEE_ERRNO);
        return NULL;
    } else {
        memset(conv_name, 0x00, len);
    }
    
    /* Tokenise the hostname into individual components. */
    for (; tok_end < (name + strlen(name));) {
        if ((tok_end = strchr(tok_start, '.')) == NULL) {
            /* Last token */
            tok_end = (char *)tok_start + strlen(tok_start);
        }
        
        tok_len = (int)tok_end - (int)tok_start;
        
        /* If the token length is > 63, then we will abort the
         * string construction. */
        if (tok_len > 63) {
            SET_ERROR(DNS_ERR_TOKEN_TOO_LONG);
            free(conv_name);
            return NULL;
        }
        
        /* Copy token length then token into constructed string */
        *(unsigned char *)(conv_name + strlen(conv_name)) =
          (unsigned char)tok_len;
        strncpy((conv_name + strlen(conv_name)), tok_start, tok_len);
        tok_start = tok_end + 1;
    }
    
    return conv_name;
}

/*
 * TODO:  Recheck this function when my mind is clearer...
 *  - make sure pointer calculations are as sane as possible.
 *  - *** CRITICAL ***  Fix recursion problem (re: hitting bottom of
 *    stack)
 */
/* 'count' is non-zero if the routine is just to count the length of a
 * generated string. 'level' is used as a recursion control to make sure
 * we count the moved offset properly. It is set to one only when this
 * function is called from outside. If we call ourselves, we make sure
 * level is zero.
 * 
 * Returns length of created string on success, -1 on error. */
static int dns_brs_helper(char *data, char *start, char *buffer,
                          int *dist, int count, int level)
{
    int len = 0;
    int tok_size = 0;
    uint16_t comp_offset = 0;
    int offset = 0;
    int top_level = level;
    int seg_size = 0;          /* Size of this string segment */
        
    do {    
        tok_size = *(unsigned char *)(start + offset);

        if (tok_size == 0) {           /* Eliminate last dot */
            *(buffer + strlen(buffer) - 1) = '\0';
            break;
        }

        /* Is this component compressed? */
        if (tok_size & 0xC0) {
            /* Get the offset into the reply data of the string
             * component in question. */

            comp_offset = (ntohs(*(unsigned short *)(start + offset)))
              & ~0xC000;
            
            dns_brs_helper(data, (data + comp_offset), buffer,
                           dist, count, 0);
            if (top_level) {
                seg_size += 2;
                *dist = seg_size; /* Return how far we moved from start */
            }
            return len;
        }
        
        /* Are we to actually copy data? */
        if (!count) {
            memcpy((buffer + strlen(buffer)), (start + offset + 1),
                    tok_size);

            /* Append dot if necessary */
            *(buffer + strlen(buffer)) = '.';
        }
        
        len += (tok_size + 1);

        if (top_level && tok_size > 0)
          seg_size += (tok_size + 1);

        offset += (tok_size + 1);
    } while (1);
    
    *dist = seg_size + 1;

    return len;
}

/* Function that will parse returned string values in replies and build
 * a full string, taking into account the DNS compression scheme. Returns
 * a malloc()'ed buffer with the string or NULL on failure.
 * 
 * data     is a pointer to the FULL reply packet data.
 * start    is a pointer (which resides within data) that the string in
 *          question begins at.
 * len      is the size of data buffer
 * dist     pointer to an integer location to store the number of bytes
 *          moved /RELATIVE TO start/ to build this string. This parameter
 *          is optional. */
char *dns_build_reply_string(char *data, int len, char *start, int *dist)
{
    char *ret_str = NULL;
    int str_size = 0;

    ret_str = malloc(128);
    memset(ret_str, 0x00, 128);
    
    dns_brs_helper(data, start, ret_str, &str_size, 0, 1);
    if (dist)
        *dist = str_size;
    
    return ret_str;    
}

/* Function that returns a string indicating what kind of resource
 * type matches the given code. DO NOT free the returned pointer,
 * it is a constant string... */
char *dns_type_to_str(uint16_t type)
{
    switch (type) {
      case DNS_QT_A:     return "A";
      case DNS_QT_NS:    return "NS";
      case DNS_QT_CNAME: return "CNAME";
      case DNS_QT_SOA:   return "SOA";
      case DNS_QT_PTR:   return "PTR";
      case DNS_QT_WKS:   return "WKS";
      case DNS_QT_AAAA:  return "AAAA";
      case DNS_QT_LOC:   return "LOC";
      case DNS_QT_HINFO: return "HINFO";
      case DNS_QT_MINFO: return "MINFO";
      case DNS_QT_MX:    return "MX";
      case DNS_QT_TXT:   return "TXT";
      case DNS_QT_AXFR:  return "AXFR";
      case DNS_QT_ANY:   return "ANY";
      case DNS_QT_RT:    return "RT";
      case DNS_QT_RP:    return "RP";
      case DNS_QT_AFSDB: return "AFSDB";
      case DNS_QT_A6:    return "A6";
      default:
        return "?";
    }
}

/* Function that returns a string indicating what class matches
 * a given class code. DO NOT free the returned pointer, it is a
 * constant string! */
char *dns_class_to_str(uint16_t class)
{
    switch (class) {
      case DNS_CLASS_INET:  return "INET";
      default:
        return "?";
    }
}

/* Function that returns a string describing one of the self-defined
 * error codes. If the error code is DNS_ERR_SEE_ERRNO, then strerror()
 * is called with the value of q->dns_errno. The returned string
 * MUST be free'd by the caller. */
char *dns_strerror(dnsq_t *q, int code)
{
    char *ret_str;
    
    if (code == DNS_ERR_SEE_ERRNO) {
        char *errno_str = strerror(q->dns_errno);
        ret_str = malloc(strlen(errno_str) + 10);
        snprintf(ret_str, strlen(errno_str) + 10, "(errno): %s",
                 errno_str);
        
        return ret_str;
    }
    
    switch (code) {
      case DNS_ERR_FORMAT_ERROR:
        return strdup("Badly formatted request string");
      case DNS_ERR_TOKEN_TOO_LONG:
        return strdup("A request token is too large (> 63)");
      case DNS_ERR_NULL_PARAM:
        return strdup("An illegal null value was given");
      case DNS_ERR_INVALID_QUERY:
        return strdup("Query structure is invalid");
      case DNS_ERR_PARAM_ERROR:
        return strdup("An illegal parameter value was given");
      case DNS_ERR_QUERY_TOO_LONG:
        return strdup("Query exceeds 512 bytes");
      case DNS_ERR_REPLY_TRUNCATED:
        return strdup("Server reply was truncated");
      case DNS_ERR_NO_SUCH_NAME:
        return strdup("No such name exists");
      case DNS_ERR_QUERY_REFUSED:
        return strdup("Server refused to handle this query");
      case DNS_ERR_BAD_FORMAT:
        return strdup("The sent query was badly formatted");
      case DNS_ERR_SERVER_FAILURE:
        return strdup("Server reports general failure");
      case DNS_ERR_NOT_IMPLEMENTED:
        return strdup("Server does not support requested query");
      case DNS_ERR_TIMED_OUT:
        return strdup("Timed out waiting for reply");
      default:
        return strdup("Unknown error code");
    };
}
