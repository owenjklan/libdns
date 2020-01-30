/* DNS Query construction and response parsing code.
 * 
 * Written by Owen Klan  -  23rd August 2003
 */

/* TODO:
 * - review usage of data pointer of reply packet. Be careful as to 
 * where it is free()'d, I have a suspicion of a memory leak... */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include "dns.h"


/* Types defined for dns_add_to_list(). These definitions can stay
 * internal to dns.c without issues. */
#define DNS_QUESTION    1              /* Question structure */
#define DNS_RR          2              /* Resource Record structure */

/*
 * Static function prototypes or external prototypes that library users
 * don't need to see. */
static int dns_add_to_list(dnsq_t *q, void **list, void *obj, int type);
static int dns_parse_response(dnsq_t *q, char *data, int len);
static struct dns_rr *dns_build_rr(dnsq_t *, char *data, char *start,
                                   int len, int *dist);

/* From dns_udp.c */
extern int dns_send_query_udp(dnsq_t *q, int s, struct sockaddr_in *addr);
extern int dns_get_response_udp(dnsq_t *q, int s, struct sockaddr_in *addr,
                                int timeout, char **data, int *len);

/* From dns_str.c */
//extern char *dns_build_reply_string(char *data, int len, char *start,
//                                  int *dist);

/* This function will add a question record to a previously allocated
 * DNS Query structure. Returns 0 on success, or one of the error codes
 * defined in dns.h.
 * 
 * Parameters:
 *    q :          DNS Query structure previously allocated
 *    host :       The hostname (or IP) to query
 *    type :       Query type (see dns.h)
 *    class:       Query class (see dns.h)
 */
int dns_add_question(dnsq_t *q, char *host, uint16_t type,
                     uint16_t class)
{
    struct dns_question *quest;
    int err = 0;
    
    if (!q || !host)                   /* Check pointer validity */
      return DNS_ERR_NULL_PARAM;
    
    if ((quest = malloc(sizeof(struct dns_question))) == NULL) {
        q->dns_errno = errno;
        return DNS_ERR_SEE_ERRNO;              /* Most likely memory alloc. failure */
    }
    memset(quest, 0x00, sizeof(struct dns_question));
    
    /* Convert the requested hostname to the required DNS format */
    if ((quest->q_content = dns_convert_name(host, &err)) == NULL) {
        free(quest);
        if (err == DNS_ERR_SEE_ERRNO)    /* Save errno if necessary */
          q->dns_errno = errno;
        return err;
    }
    quest->q_type = type;              /* Setup type, class and next ptr. */
    quest->q_class = class;
    quest->next  = NULL;
    
    /* Now add this item to the list */
    dns_add_to_list(q, (void *)&q->questions, (void *)quest, DNS_QUESTION);

    q->header.dns_num_quest++;         /* One more question to pile... */
    
    return 0;
}


/* This function returns a new DNS Query structure, ready to have
 * questions added to it. Returns NULL on error. */
dnsq_t *dns_new_query(uint16_t id, int opcode, int recursive)
{
    dnsq_t *q;                         /* Query structure */
    
    if ((q = malloc(sizeof(dnsq_t))) == NULL) {
        return NULL;
    }
    
    /* Zero out the entire structure */
    memset(q, 0x00, sizeof(dnsq_t));
    
    /* Now setup initial fields */
    q->header.dns_id = id;
    q->header.dns_flags = 0;
    DNS_SET_FLAGS(q, opcode, recursive);
    
    return q;
}

/* This procedure will destroy *ALL* memory associated with a DNS Query
 * structure. It will free the lists of questions, all RRs and any data
 * that was saved as part of an RR. Finally, it will free the query
 * structure itself */
void dns_free_query(dnsq_t *q)
{
    struct dns_question *quest, *quest_old;
    struct dns_rr *rr, *rr_old;
    
    /* Free the lists of questions and RRs first */
    quest = q->questions;
    
    while (quest) {
        FREE_IF_VALID(quest->q_content);   /* Free content string */
        quest_old = quest;
        quest = quest->next;               /* Next element */
        free(quest_old);                   /* Free old element */
    }
    
    rr = q->answers;                   /* Free the answers list */
    while (rr) {
        FREE_IF_VALID(rr->rr_name);
        FREE_IF_VALID(rr->rr_data);
        rr_old = rr;
        rr = rr->next;
        FREE_IF_VALID(rr_old);
    }

    rr = q->authority;                 /* Free the authority list */
    while (rr) {
        FREE_IF_VALID(rr->rr_name);
        FREE_IF_VALID(rr->rr_data);
        rr_old = rr;
        rr = rr->next;
        free(rr_old);
    }

    rr = q->additional;                /* Free the additional list */
    while (rr) {
        FREE_IF_VALID(rr->rr_name);
        FREE_IF_VALID(rr->rr_data);
        rr_old = rr;
        rr = rr->next;
        free(rr_old);
    }

    /* Free the reply data */
    FREE_IF_VALID(q->dns_data);
    
    free(q);                           /* Done */
}

/* Function that sends off a DNS request. Requires a sockaddr_in structure
 * specifying the destination server and the DNS query to send. Will return
 * zero on success, other wise an error code is returned. */
int dns_send_query(dnsq_t *q, int s, struct sockaddr_in *addr, int timeout)
{
    int retval;
    char *response_data;
    int data_size = 0;                 /* Hold size of returned data */
    
    if (!q || !addr)                   /* Confirm pointer validity */
      return DNS_ERR_NULL_PARAM;
    
    /* 23rd August 2003:  Currently only UDP transmission is supported! */
    if ((retval = dns_send_query_udp(q, s, addr)) > 0)
      return retval;
    if ((retval = dns_get_response_udp(q, s, addr, timeout, &response_data,
                                       &data_size)) > 0)
      return retval;

    retval = dns_parse_response(q, response_data, data_size);
    
    return retval;
}

/* Function that parses the DNS response data into lists of records
 * and also performs some flags checks. Returns zero on success,
 * error code on failure.
 * 
 * Parameters:
 *      q    Pointer to DNS query structure to work with
 *   data    Pointer to buffer containing reply data
 *    len    Length of returned reply data 
 */
static int dns_parse_response(dnsq_t *q, char *data, int len)
{
    struct dns_rr *rr;                 /* Response record */
    int i;
    int ret_val;
    int reply_code;
    int offset = sizeof(struct dns_header);      /* Offset in data */
    
    /* Check the truncated response flag first */
    if (q->header.dns_flags & 0x0200)
      return DNS_ERR_REPLY_TRUNCATED;
    
    /* Now check the reply code */
    reply_code = q->header.dns_flags & 0x000F;

    /* TODO:  Properly implement these checks */
    /* Note that a root server will most likely ignore queries that
     * request recursive resolution. */
    switch (reply_code) {
      case DNS_R_FORMAT_ERROR:         /* Format error with sent query */
        FREE_IF_VALID(data);
        return DNS_ERR_BAD_FORMAT;

      case DNS_R_NAME_ERROR:           /* No such name exists */
        FREE_IF_VALID(data);
        return DNS_ERR_NO_SUCH_NAME;

      case DNS_R_SERVER_FAILURE:       /* Server reports failure */
        FREE_IF_VALID(data);
        return DNS_ERR_SERVER_FAILURE;

      case DNS_R_NOT_IMPLEMENTED:      /* Requested query not supported */
        FREE_IF_VALID(data);
        return DNS_ERR_NOT_IMPLEMENTED;
        
      case DNS_R_REFUSED:              /* Server refused to handle query */
        FREE_IF_VALID(data);
        return DNS_ERR_QUERY_REFUSED;
    }
    
    /* So far all is fine. Now parse response into lists of items */
    /* Assume that the question section remains unchanged and start
     * with the answers section instead. */
    for (i = 0; i < q->header.dns_num_quest; i++) {
        offset += strlen((char *)(data + offset)) + 1;
        offset += 4;
    }

    /* Now offset is at beginning of Answers section */
    for (i = 0; i < q->header.dns_num_ans; i++) {
        int dist = 0;
        
        rr = dns_build_rr(q, data, (data + offset), len, &dist);
        
        /* Update the offset to point to the next record */
        offset += (dist + 10 + rr->rr_datalen);
        
        /* Add this to the list of answers */
        if ((ret_val = dns_add_to_list(q, (void *)&q->answers,
                                       (void *)rr, DNS_RR)) != 0) {
            /* Some error has occurred */
            FREE_IF_VALID(data);
            free(rr);
            return ret_val;
        }
    }
    
    /* Now offset is at beginning of Authority section */
    for (i = 0; i < q->header.dns_num_auth; i++) {
        int dist = 0;
        
        if ((rr = dns_build_rr(q, data, (data + offset),
                               len, &dist)) == NULL) {
            FREE_IF_VALID(data);
            free(rr);
            
            /* This is potentially nasty... */
            q->dns_errno = ENOMEM;
            return DNS_ERR_SEE_ERRNO;
        }
        
        /* Update the offset to point to the next record */
        offset += (dist + 10 + rr->rr_datalen);
        
        /* Add this to the list of answers */
        if ((ret_val = dns_add_to_list(q, (void *)&q->authority,
                                       (void *)rr, DNS_RR)) != 0) {
            /* Some error has occurred */
            FREE_IF_VALID(data);
            free(rr);
            return ret_val;
        }
    }

    /* Now offset is at beginning of Additional section */
    for (i = 0; i < q->header.dns_num_add; i++) {
        int dist = 0;
        
        if ((rr = dns_build_rr(q, data, (data + offset),
                               len, &dist)) == NULL) {
            FREE_IF_VALID(data);
            free(rr);
            
            /* This is potentially nasty... */
            q->dns_errno = ENOMEM;
            return DNS_ERR_SEE_ERRNO;
        }
        
        /* Update the offset to point to the next record */
        offset += (dist + 10 + rr->rr_datalen);
        
        /* Add this to the list of answers */
        if ((ret_val = dns_add_to_list(q, (void *)&q->additional,
                                       (void *)rr, DNS_RR)) != 0) {
            /* Some error has occurred */
            FREE_IF_VALID(data);
            free(rr);
            return ret_val;
        }
    }

    /* Duplicate the query data */
    if ((q->dns_data = malloc(len)) == NULL) {
        q->dns_errno = errno;
        return DNS_ERR_SEE_ERRNO;
    }
    memcpy(q->dns_data, data, len);
    
    return 0;
}


/* Function that builds a resource record. Returns a copy of the
 * dns_rr structure on sucess, NULL on failure.
 * 
 * Parameters:
 *   q         DNS query structure we are working with
 *   data      pointer to beginning of packet data
 *   start     pointer to beginning of RR
 *   len       length of data buffer (currently unused  27-08-2003)
 *   dist      address of integer to store the number of bytes this
 *             RR takes up in the reply.
 */
static struct dns_rr *dns_build_rr(dnsq_t *q, char *data, char *start,
                                   int len, int *dist)
{
    uint16_t rdl = 0;          /* Resource Data Length */
    struct dns_rr *rr;
    int rr_size = 0;                   /* Place to store bytes processed by
                                        dns_build_reply_string(). */
    
    if ((rr = malloc(sizeof(struct dns_rr))) == NULL) {
        /* Malloc failure. */
        return NULL;
    }
    
    rr->rr_name = dns_build_reply_string(data, len, start, &rr_size);
    rdl = ntohs(*(uint16_t *)(start + rr_size + 8));
    rr->rr_datalen = rdl;
    rr->rr_type    = ntohs(*(uint16_t *)(start + rr_size));
    rr->rr_class   = ntohs(*(uint16_t *)(start + rr_size + 2));
    rr->rr_ttl     = ntohl(*(uint32_t *)(start + rr_size + 4));
    
    /* Duplicate this resource records data section. */
    if ((rr->rr_data = malloc(rr->rr_datalen)) == NULL) {
        FREE_IF_VALID(rr->rr_name);
        FREE_IF_VALID(rr);
        return NULL;
    }
    
    memcpy(rr->rr_data, (start + rr_size + 10), rr->rr_datalen);
    rr->next    = NULL;
    
    *dist = rr_size;
    return rr;
}

/* Helper function that will add an item to a list in a dnsq_t structure.
 * Returns 0 on success, error code on error. */
static int dns_add_to_list(dnsq_t *q, void **list, void *obj, int type)
{
    if (!q || !list || !obj)           /* Check pointer validity */
      return DNS_ERR_NULL_PARAM;
    
    switch (type) {
      case DNS_QUESTION: {             /* Add to a question list */
          struct dns_question *current = (struct dns_question *)*list;
          
          if (!current) {              /* List is empty */
              *list = (struct dns_question *)obj;
          } else {
              while (current->next)    /* Add to end of list */
                current = current->next;
              
              current->next = (struct dns_question *)obj;
          }
          break;
      }
      case DNS_RR: {                   /* Add to a resource record list */
          struct dns_rr *current = (struct dns_rr *)*list;
          
          if (!current) {              /* List is empty */
              *list = (struct dns_rr *)obj;
          } else {
              while (current->next)    /* Add to end of list */
                current = current->next;
              
              current->next = (struct dns_rr *)obj;
          }
          break;
      }
      default:
        return DNS_ERR_PARAM_ERROR;            /* Unknown type */
    }
    
    return 0;
}
