/* dnsq - DNS querying application. This tool does what nslookup and such
 * tools do. The reason I wrote it was because I had only a vague idea on
 * how DNS works. So, I decided to fix that and this is the result...
 * enjoy. Written as a kludge to test libdns.
 * 
 * Written by Owen Klan  -  23rd August 2003 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <libdns/dns.h>

/* Escape sequences for ANSI colorisation on the terminal */
#define BR_WHITE_ON    "[37m[1m"
#define BR_WHITE_OFF   "[37m[22m"

/* Function prototypes */
void usage(char *app);
static unsigned long resolve_ip(char *ipstr);
void display_rr_detail(dnsq_t *q, struct dns_rr *rr);
char *sec_to_time(unsigned int s);

int main(int argc, char *argv[])
{
    dnsq_t *query;
    char *start_color, *end_color;
    struct dns_rr *rr;
    struct sockaddr_in serv_addr;
    int retval = 0;
    int i;
    int s;                             /* Socket descriptor */
    
    /* Change this to specify whether ANSI colour highlighting should
     * be used or not */
    start_color = end_color = "";       /* No highlighting */
    // start_color = BR_WHITE_ON;
    // end_color   = BR_WHITE_OFF;
    
    /* We need at least 2 arguments: the DNS server address and a query */
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    fprintf(stdout, "Using LibDNS version %s\n", dns_get_lib_version_str());
    
    /* Get a socket and socket address structure that we can use for
     * the send request library calls */
    s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    if ((serv_addr.sin_addr.s_addr = resolve_ip(argv[1])) == 0x00000000) {
        fprintf(stdout, "Failed determining IP address for %s!\n",
                argv[1]);
        return 1;
    }    
    serv_addr.sin_port = htons(53);
    serv_addr.sin_family = AF_INET;

    fprintf(stdout, "Using server at %s\n", inet_ntoa(serv_addr.sin_addr));

    /* Get a new query structure. Ask for recursive resolution */
    if ((query = dns_new_query(0xBABE, DNS_OP_QUERY,
                               DNS_DO_RECURSE)) == NULL) {
        fprintf(stdout, "Failed allocating DNS Query structure!\n");
        return 1;
    }

    /* Add all the given queries */
    for (i = 2; i < argc; i++) {
        if ((retval = dns_add_question(query, argv[i],
                                       DNS_QT_ANY, DNS_CLASS_INET))) {
            fprintf(stdout, "Failed adding question to DNS Query!\n");
            fprintf(stdout, "%s\n", dns_strerror(query, retval));
            return 1;
        } else {
            fprintf(stdout, "Added %s to query section...\n", argv[i]);
        }
    }
        
    /* send off the query */
    if ((retval = dns_send_query(query, s, &serv_addr, 10))) {
        char *error_string = dns_strerror(query, retval);
        fprintf(stdout, "Query failed! %s\n",
                error_string);
        free(error_string);
        dns_free_query(query);
        return 1;
    }
    
    fprintf(stdout, "%sReturned RRs:%s\n", start_color, end_color);
    if (query->header.dns_num_ans)
      fprintf(stdout, "  Answers:       %d\n", query->header.dns_num_ans);
    if (query->header.dns_num_auth)
      fprintf(stdout, "  Authority:     %d\n", query->header.dns_num_auth);
    if (query->header.dns_num_add)
      fprintf(stdout, "  Additional:    %d\n", query->header.dns_num_add);

    /* Display answers */
    if (query->header.dns_num_ans) {
        fprintf(stdout, "\n%sAnswers:%s\n", start_color, end_color);
        rr = dns_get_answer_list(query);
        
        i = 0;
        while (rr) {
            fprintf(stdout, " %2d  %-32s %-6s %s  (%s)\n", i + 1, rr->rr_name,
                    dns_type_to_str(rr->rr_type),
                    dns_class_to_str(rr->rr_class),
                    sec_to_time(dns_rr_get_ttl(rr)));

            if (rr)
              display_rr_detail(query, rr);
            
            rr = rr->next;
            i++;
        }
    }

    /* Display authoritive NS's */
    if (query->header.dns_num_auth) {
        fprintf(stdout, "\n%sAuthoritive Name Servers:%s\n",
                start_color, end_color);
        rr = dns_get_authority_list(query);
        
        i = 0;
        while (rr) {
            fprintf(stdout, " %2d  %-32s %-6s %s  (%s)\n", i + 1, rr->rr_name,
                    dns_type_to_str(rr->rr_type),
                    dns_class_to_str(rr->rr_class),
                    sec_to_time(dns_rr_get_ttl(rr)));

            if (rr)
              display_rr_detail(query, rr);
            rr = rr->next;
            i++;
        }
    }

    /* Display additional entries */
    if (query->header.dns_num_add) {
        fprintf(stdout, "\n%sAdditional Entries:%s\n",
                start_color, end_color);
        rr = dns_get_additional_list(query);
        
        i = 0;
        while (rr) {
            fprintf(stdout, " %2d  %-32s %-6s %s\n", i + 1, rr->rr_name,
                    dns_type_to_str(rr->rr_type),
                    dns_class_to_str(rr->rr_class));

            if (rr)
              display_rr_detail(query, rr);
            
            rr = rr->next;
            i++;
        }
    }

    dns_free_query(query);
    
    return 0;
}

/* Display additional information for resource records */
void display_rr_detail(dnsq_t *q, struct dns_rr *rr)
{
    switch (rr->rr_type) {
      case DNS_QT_MX: {
          uint16_t  pref;
          char *mx_str;
          char *reply_data = (char *)dns_get_data(q);
          
          pref = ntohs(*(uint16_t *)(dns_rr_get_data(rr)));
          mx_str = dns_build_reply_string(reply_data, 0,
                                          (rr->rr_data + 2), NULL);
          fprintf(stdout, "\tPreference:  %d\tName:  %s\n", pref, mx_str);
          FREE_IF_VALID(mx_str);
          
          return;
      }
      case DNS_QT_A: {
          struct sockaddr_in addr;
          addr.sin_addr.s_addr = *(unsigned int *)rr->rr_data;
          fprintf(stdout, "\tAddress:  %s\n", inet_ntoa(addr.sin_addr));
          return;
      }
      case DNS_QT_PTR: {
          char *ptr_str;
          char *reply_data = (char *)dns_get_data(q);
          
          ptr_str = dns_build_reply_string(reply_data, 0, rr->rr_data, NULL);
          fprintf(stdout, "\tName:  %s\n", ptr_str);
          FREE_IF_VALID(ptr_str);
          return;
      }
      case DNS_QT_CNAME: {
          char *cname_str;
          char *reply_data = dns_get_data(q);
          
          cname_str = dns_build_reply_string(reply_data, 0, rr->rr_data, NULL);
          fprintf(stdout, "\tName:  %s\n", cname_str);
          FREE_IF_VALID(cname_str);
          return;
      }
      case DNS_QT_NS: {
          char *ns_str;
          char *reply_data = dns_get_data(q);
          
          ns_str = dns_build_reply_string(reply_data, 0, rr->rr_data, NULL);
          fprintf(stdout, "\tName Server:  %s\n", ns_str);
          FREE_IF_VALID(ns_str);
          return;
      }
      case DNS_QT_TXT: {
          char *txt_str;
          char *reply_data = dns_get_data(q);
          
          txt_str = dns_build_reply_string(reply_data, 0, rr->rr_data, NULL);
          fprintf(stdout, "\tText String:  %s\n", txt_str);
          FREE_IF_VALID(txt_str);
          return;
      }
      case DNS_QT_AAAA: {
          char *reply_data = dns_rr_get_data(rr);
          int i = 0;
          unsigned short addr_word;
          
          fprintf(stdout, "\tIPv6 Address:  %X",
                  ntohs(*(unsigned short *)(reply_data + i)));
          for (i = 2; i < 16; i+=2) {
              addr_word = ntohs(*(unsigned short *)(reply_data + i));
              if (addr_word == 0x0000)
                fprintf(stdout, ":");
              else
                fprintf(stdout, ":%X", addr_word);
          }
          fprintf(stdout, "\n");
          return;
      }
    }
}

/* Function that takes a seconds value and converts it to a number of
 * years, days, hours, minutes and seconds. Returns a freshly
 * malloc()'ed string. */
char *sec_to_time(unsigned int s)
{
    int years = 0;
    int days = 0;
    int hours = 0;
    int minutes = 0;
    unsigned int lo = s;               /* Left-overs... */
    
    char buffer[256];                  /* This should be generous enough... */
#define STR_END(s)  (s + strlen(s))
    
    years = s / 31536000;              /* seconds in a year, assuming
                                        1 year == 365 days */
    lo -= years * 31536000;
    
    days = lo / 86400;
    lo -= days * 86400;
    
    hours = lo / 3600;
    lo -= hours * 3600;
    
    minutes = lo / 60;
    lo -= minutes * 60;

    memset(buffer, 0x00, 256);
    
    if (years)
      sprintf(buffer, "%d yrs, ", years);
    if (days) 
      sprintf(STR_END(buffer), "%d d, ", days);
    if (hours)
      sprintf(STR_END(buffer), "%d h, ", hours);
    if (minutes)
      sprintf(STR_END(buffer), "%d m, ", minutes);
    
    if (lo)
      sprintf(STR_END(buffer), "%d s", lo);
    else
      *(STR_END(buffer) - 2) = '\0';
  
    return strdup(buffer);
}

/* Display usage information */
void usage(char *app)
{
    fprintf(stderr, "Usage:  %s server queries ...\n", app);
}

/* Function that takes a string and attempts to convert it to an IP
 * address. */
static unsigned long resolve_ip(char *ipstr)
{
    struct hostent *host;
    
    if ((host = gethostbyname(ipstr)) == NULL) {
        return 0;
    }
    
    return *(unsigned long *)(host->h_addr);
}
