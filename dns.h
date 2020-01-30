 /* DNS Query construction and reply parsing library. Note the following:
 *  - Currently only supports UDP
 *  - Zone transfers are currently unsupported (they require TCP) and
 *    attempting to add a zone transfer question will result in an
 *    DNS_INVALID_PARAM error
 * 
 * Written by Owen Klan  -  23rd August 2003 */

#ifndef __DNS_H_
#define __DNS_H_

/* Common include files for source files */
#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Version symbols and macros to obtain them */
#define LIBDNS_VERSION   "0.1-alpha"
#define LIBDNS_MAJOR     0
#define LIBDNS_MINOR     1

#define dns_get_lib_version_str()     \
      (char *)LIBDNS_VERSION
#define dns_get_lib_version()         \
      (uint16_t)((LIBDNS_MAJOR << 8) | LIBDNS_MINOR)

/*
 * Declaration of LibDNS data structures
 */
/* Structure that forms the common header of the DNS query. */
struct dns_header {
    uint16_t dns_id;	       /* Identifier */
    uint16_t dns_flags;	       /* Flags word */
    uint16_t dns_num_quest;    /* # of questions */
    uint16_t dns_num_ans;      /* # of answer RRs */
    uint16_t dns_num_auth;     /* # of authority RRs */
    uint16_t dns_num_add;      /* # of additional RRs */
};

/*
 * The following structures are used to build lists of questions
 * and resource records.
 */
/* Question structure */
struct dns_question {
    char *       q_content;	       /* Question content */
    uint16_t     q_type;	       /* Question type */
    uint16_t     q_class;	       /* Question class */
    struct dns_question *next;	       /* Next question pointer */
};

/* Resource Record structure */
struct dns_rr {
    char *     rr_name;		       /* Domain name */
    uint16_t   rr_type; 	       /* RR type */
    uint16_t   rr_class;	       /* RR class */
    uint32_t   rr_ttl;  	       /* RR Time-to-live */
    uint16_t   rr_datalen;	       /* RR Data length */
    char *     rr_data;		       /* RR Data */
    struct dns_rr *next;	       /* Next RR in the list */
};

/* Query construction structure. */
struct dns_query {
    struct dns_header   header;
    struct dns_question *questions;    /* List of questions */
    struct dns_rr       *answers;      /* List of answers */
    struct dns_rr       *authority;    /* List of authority replies */
    struct dns_rr       *additional;   /* List of additional replies */
    int dns_errno;		       /* Local copy of last errno */
    char *dns_data;		       /* The reply data */
};
typedef struct dns_query dnsq_t;


/* 
 * Declaration of #define's for DNS fields.
 */
/* DNS Opcode values */
#define DNS_OP_QUERY          0x00     /* Query */
#define DNS_OP_INVQUERY       0x01     /* Inverse query */
#define DNS_OP_SERVSTAT       0x02     /* Server status */

/* DNS Query reply codes */
#define DNS_R_NO_ERROR        0	       /* No error */
#define DNS_R_FORMAT_ERROR    1	       /* Format error with query */
#define DNS_R_SERVER_FAILURE  2	       /* Server failure */
#define DNS_R_NAME_ERROR      3	       /* Name error */
#define DNS_R_NOT_IMPLEMENTED 4	       /* Query type not supported */
#define DNS_R_REFUSED         5	       /* Server refused to handle query */

/* Bits for 'recursive' option for dns_new_query() */
#define DNS_DO_RECURSE	      1        /* Enable recursion */
#define DNS_DONT_RECURSE      0	       /* Disable recursion */

/* DNS Query types */
#define DNS_QT_A              1	       /* IPv4 Address record */
#define DNS_QT_NS             2	       /* Name server */
#define DNS_QT_CNAME          5	       /* Canonical name (IP-hostname) */
#define DNS_QT_SOA            6        /* Start of zone-of-authority */
#define DNS_QT_WKS            11       /* Well Known Service description */
#define DNS_QT_PTR            12       /* Pointer record */
#define DNS_QT_HINFO          13       /* Host information */
#define DNS_QT_MINFO          14       /* Mail{box,list} information */
#define DNS_QT_MX             15       /* Mail exchange record */
#define DNS_QT_TXT            16       /* Text strings */
#define DNS_QT_RP             17       /* Responsible Person */
#define DNS_QT_AFSDB          18       /* AFS cell database server */
#define DNS_QT_RT             21       /* Route-through record */
#define DNS_QT_AAAA           28       /* IPv6 address record (RFC-1886) */
#define DNS_QT_LOC            29       /* Location information (RFC-1876) */
#define DNS_QT_SRV            33       /* Service information (RFC-2782) */
#define DNS_QT_A6             38       /* IPv6 A6 address record (RFC-2874) */
/* the following appear in query records only! */
#define DNS_QT_AXFR           252      /* Zone transfer */
#define DNS_QT_ANY            255      /* All records */

/* DNS Query classes */
#define DNS_CLASS_INET        1	       /* Inet address */
#define DNS_CLASS_CHAOS       3	       /* Chaos system */

/* Accessor routines declared as macros to get at elements of the dnsq_t
 * structure */
#define dns_get_data(q)               \
      (void *)((dnsq_t *)q)->dns_data
#define dns_get_question_list(q)      \
      (struct dns_rr *)((dnsq_t *)q)->questions
#define dns_get_answer_list(q)        \
      (struct dns_rr *)((dnsq_t *)q)->answers
#define dns_get_authority_list(q)     \
      (struct dns_rr *)((dnsq_t *)q)->authority
#define dns_get_additional_list(q)    \
      (struct dns_rr *)((dnsq_t *)q)->additional

/* Accessor routines declared as macros to get at elements of a resource
 * record structure */
#define dns_rr_get_data(r)        \
      (void *)((struct dns_rr *)r)->rr_data
#define dns_rr_get_data_len(r)    \
      (uint16_t)((struct dns_rr *)r)->rr_datalen
#define dns_rr_get_type(r)        \
      (uint16_t)((struct dns_rr *)r)->rr_type
#define dns_rr_get_class(r)       \
      (uint16_t)((struct dns_rr *)r)->rr_class
#define dns_rr_get_ttl(r)         \
      (uint32_t)((struct dns_rr *)r)->rr_ttl


/*
 * Macro that sets up the flags word as appropriate for a query.
 * o is the opcode field, r is the 'recursion desired' bit. The
 * Query-Response field will be set to 0 to indicate a query.
 * d is the dnsq_t structure to set the flags of.
 */
#define DNS_SET_FLAGS(d,o,r)                   \
    d->header.dns_flags = 0x0000;              \
    d->header.dns_flags |= ((o & 0x0F) << 11); \
    d->header.dns_flags |= (r << 8);

/* 
 * #define's for Libdns error codes
 */
#define DNS_ERR_FORMAT_ERROR            1  /* Format error of request string */
#define DNS_ERR_TOKEN_TOO_LONG          2  /* A token was longer than 63 */
#define DNS_ERR_SEE_ERRNO               3  /* Look at value of errno */
#define DNS_ERR_NULL_PARAM              4  /* A NULL parameter was given */
#define DNS_ERR_INVALID_QUERY           5  /* The given dnsq_t is invalid */
#define DNS_ERR_PARAM_ERROR		6  /* Function given invalid param */
#define DNS_ERR_QUERY_TOO_LONG          7  /* The whole query is too big
					    * (> 512 for UDP) */
#define DNS_ERR_REPLY_TRUNCATED         8  /* The response was truncated */
#define DNS_ERR_NO_SUCH_NAME            9  /* requested name doesn't exist */
#define DNS_ERR_QUERY_REFUSED          10  /* Server refused to handle query */
#define DNS_ERR_BAD_FORMAT             11  /* sent query was badly formatted */
#define DNS_ERR_SERVER_FAILURE         12  /* Server failure */
#define DNS_ERR_NOT_IMPLEMENTED        13  /* Query type not supported */
#define DNS_ERR_TIMED_OUT              14  /* Timed out waiting for reply */

/* Function prototypes */
/* From dns.c */
extern dnsq_t *dns_new_query(uint16_t id, int opcode, int recursive);
extern void dns_free_query(dnsq_t *q);
extern int dns_add_question(dnsq_t *q, char *host, uint16_t type,
			    uint16_t class);
extern int dns_send_query(dnsq_t *q, int s, struct sockaddr_in *addr,
			  int timeout);

/* From dns_str.c */
extern char *dns_convert_name(char *name, int *error);
extern char *dns_type_to_str(uint16_t type);
extern char *dns_class_to_str(uint16_t class);
extern char *dns_strerror(dnsq_t *q, int code);
extern char *dns_build_reply_string(char *data, int len,
				    char *start, int *dist);

/* Some helper macros, these are mostly for the library code, but could
 * be utilised by user apps. as well */
/* Macro that free's a pointer if it's non-NULL */
#define FREE_IF_VALID(p)     \
     { if (p)                \
	  free(p); }

/* Macro that is used by functions that return an error in a user
 * provided integer location. */
#define SET_ERROR(e)          \
    { if (error)              \
	*error = e; }

/* Macro to convert an unsigned short to network byte order, then
 * assign back into the variable */
#define FIX_FOR_NBO(s)    s = htons(s)

#endif				       /* __DNS_H_ */
