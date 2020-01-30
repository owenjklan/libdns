/* TCP-specific code for DNS library.
 *
 * Written by Owen Klan  -  6th October, 2003.
 */

#include "dns.h"

#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* Maximum for UDP DNS query. We keep this around in the TCP version as
 * a nice size for the query buffer. Perhaps this should be larger but
 * I really doubt that DNS will ever or has ever seen a 512-byte query...
 * 
 * Famous last words I'm sure :)
 */
#define MAX_DGRAM_SIZE    512

/* TCP-specific reply retrieval function. Will set the pointer passed
 * in as data to point to the received packet data for parsing. */
int dns_get_response_tcp(dnsq_t *q, int s, struct sockaddr_in *addr,
			 int timeout, char **data, int *len)
{
    char dgram[MAX_DGRAM_SIZE];
    char *data_copy;
    struct sockaddr_in saddr;
    struct dns_header *head;
    uint32_t addr_size = sizeof(struct sockaddr_in);
    int loop = 1;		       /* Loop until correct reply received */
    int data_len;		       /* Length of reply data */
    struct timeval t;		       /* Timeout structure */
    fd_set rfd_set;		       /* Read FD set for select() */
    int retval;
    
    while (loop) {
	/* Setup the time structure for select() */
	t.tv_sec = timeout;
	FD_ZERO(&rfd_set);
	FD_SET(s, &rfd_set);
	
	/* Now, wait for something to come in on the socket or for the
	 * timeout to expire. */
	retval = select(s + 1, &rfd_set, NULL, NULL, &t);
	if (retval < 0) {	       /* Error calling select() */
	    q->dns_errno = errno;
	    return DNS_ERR_SEE_ERRNO;
	} else if (retval == 0) {      /* Timed out */
	    return DNS_ERR_TIMED_OUT;
	}
	
	data_len = recvfrom(s, dgram, 512, 0, (struct sockaddr *)&saddr,
			    &addr_size);

	if (data_len < 0) {
	    q->dns_errno = errno;
	    return DNS_ERR_SEE_ERRNO;
	}

	head = (struct dns_header *)dgram;
	if (ntohs(head->dns_id) != q->header.dns_id)
	  continue;		       /* Try the next packet */
	else
	  loop = 0;
    }
    
    /* Now, set the number of RRs returned for this reply and the
     * flags word */
    q->header.dns_num_quest = ntohs(head->dns_num_quest);
    q->header.dns_num_ans   = ntohs(head->dns_num_ans);
    q->header.dns_num_auth  = ntohs(head->dns_num_auth);
    q->header.dns_num_add   = ntohs(head->dns_num_add);
    q->header.dns_flags     = ntohs(head->dns_flags);
    
    if ((data_copy = malloc(data_len)) == NULL) {
	q->dns_errno = errno;
	return DNS_ERR_SEE_ERRNO;
    }
    memcpy(data_copy, dgram, data_len);
    *data = data_copy;
    *len = data_len;
    
    return 0;
}


/* TCP-specific query sending function. */
int dns_send_query_tcp(dnsq_t *q, int s, struct sockaddr_in *addr)
{
    char dgram[MAX_DGRAM_SIZE];
    struct dns_header *head = (struct dns_header *)dgram;
    struct dns_question *quest = q->questions;
    int query_len = 0;
    int retval = 0;
    
    memset(dgram, 0x00, MAX_DGRAM_SIZE);

    /* Now, copy the DNS query header into the datagram buffer, then
     * convert all items from Host to Network byte order */
    memcpy(dgram, &q->header, sizeof(struct dns_header));
    
    FIX_FOR_NBO(head->dns_id);
    FIX_FOR_NBO(head->dns_flags);
    FIX_FOR_NBO(head->dns_num_quest);		
    FIX_FOR_NBO(head->dns_num_ans);   
    FIX_FOR_NBO(head->dns_num_auth);
    FIX_FOR_NBO(head->dns_num_add);

    query_len += 12;		       /* Add 12 for basic DNS header... */
    
    /* Now, for each question, fix the byte order of the type and
     * class fields, copy the content into the datagram and then
     * copy the type and class fields */
    while (quest && query_len < MAX_DGRAM_SIZE) {
	memcpy((dgram + query_len), quest->q_content,
		strlen(quest->q_content) + 1);
	query_len += strlen(quest->q_content) + 1;
	
	FIX_FOR_NBO(quest->q_type);
	FIX_FOR_NBO(quest->q_class);
	
	*(uint16_t *)(dgram + query_len) = quest->q_type;
	query_len += 2;
	*(uint16_t *)(dgram + query_len) = quest->q_class;
	query_len += 2;
	
	quest = quest->next;
    }
    if (query_len > MAX_DGRAM_SIZE)
      return DNS_ERR_QUERY_TOO_LONG;       /* The overall query is too big */
    
    /* Now we do the TCP send */
    retval = sendto(s, dgram, query_len, 0,
		    (struct sockaddr *)addr, sizeof(struct sockaddr));
    if (retval == -1) {
	q->dns_errno = errno;	       /* Save current errno */
	return DNS_ERR_SEE_ERRNO;
    }
    
    /* Everything is dandy */
    return 0;
}
