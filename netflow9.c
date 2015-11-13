/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"
#include "log.h"
#include "treetype.h"
#include "softflowd.h"

/* Specific IDs */
#define NF9_TEMPLATE_FLOWSET_ID		0
#define NF9_OPTIONS_FLOWSET_ID		1
#define NF9_MIN_RECORD_FLOWSET_ID	256

/* Flowset RFC fields types IDs */
#define NF9_IN_BYTES				1
#define	NF9_IN_PACKETS				2
#define	NF9_FLOWS				3
#define	NF9_PROTOCOL				4
#define	NF9_TOS 				5
#define	NF9_TCP_FLAGS 	          		6
#define	NF9_L4_SRC_PORT 			7
#define	NF9_IPV4_SRC_ADDR 			8
#define	NF9_SRC_MASK		 		9
#define	NF9_INPUT_SNMP 				10
#define	NF9_L4_DST_PORT				11
#define	NF9_IPV4_DST_ADDR 			12
#define	NF9_DST_MASK 				13
#define	NF9_OUTPUT_SNMP 			14
#define	NF9_IPV4_NEXT_HOP 			15
#define	NF9_SRC_AS 				16
#define	NF9_DST_AS 				17
#define	NF9_BGP_IPV4_NEXT_HOP 			18
#define	NF9_MUL_DST_PKTS 			19
#define	NF9_MUL_DST_BYTES 			20
#define	NF9_LAST_SWITCHED 			21
#define	NF9_FIRST_SWITCHED 			22
#define	NF9_OUT_BYTES 				23
#define	NF9_OUT_PKTS 				24
#define	NF9_IPV6_SRC_ADDR 			27
#define	NF9_IPV6_DST_ADDR 			28
#define	NF9_IPV6_SRC_MASK 			29
#define	NF9_IPV6_DST_MASK 			30
#define	NF9_IPV6_FLOW_LABEL 		        31
#define	NF9_ICMP_TYPE 				32
#define	NF9_MUL_IGMP_TYPE 			33
#define	NF9_SAMPLING_INTERVAL 			34
#define	NF9_SAMPLING_ALGORITHM 			35
#define	NF9_FLOW_ACTIVE_TIMEOUT 		36
#define	NF9_FLOW_INACTIVE_TIMEOUT 		37
#define	NF9_ENGINE_TYPE 			38
#define	NF9_ENGINE_ID 				39
#define	NF9_TOTAL_BYTES_EXP 			40
#define	NF9_TOTAL_PKTS_EXP 			41
#define	NF9_TOTAL_FLOWS_EXP 			42
#define	NF9_MPLS_TOP_LABEL_TYPE 		46
#define	NF9_MPLS_TOP_LABEL_IP_ADDR		47
#define	NF9_FLOW_SAMPLER_ID 			48
#define	NF9_FLOW_SAMPLER_MODE 			49
#define	NF9_FLOW_SAMPLER_RANDOM_INTERVAL        50
#define	NF9_DST_TOS				55
#define	NF9_SRC_MAC			 	56
#define	NF9_DST_MAC			 	57
#define	NF9_SRC_VLAN			 	58
#define	NF9_DST_VLAN			 	59
#define	NF9_IP_PROTOCOL_VERSION			60
#define	NF9_DIRECTION			 	61
#define	NF9_IPV6_NEXT_HOP			62
#define	NF9_BGP_IPV6_NEXT_HOP			63
#define	NF9_IPV6_OPTION_HEADERS 		64
#define	NF9_MPLS_LABEL_1	  		70
#define	NF9_MPLS_LABEL_2	  		71
#define	NF9_MPLS_LABEL_3	  		72
#define	NF9_MPLS_LABEL_4	  		73
#define	NF9_MPLS_LABEL_5	  		74
#define	NF9_MPLS_LABEL_6	  		75
#define	NF9_MPLS_LABEL_7	  		76
#define	NF9_MPLS_LABEL_8	  		77
#define	NF9_MPLS_LABEL_9	  		78
#define	NF9_MPLS_LABEL_10	  		79
/* Flowset custom fields types IDs */
#define NF9_TCP_NB_ACK                          256
#define NF9_TCP_NB_PUSH                         257
#define NF9_TCP_NB_RESET                        258
#define NF9_TCP_NB_SYN                          259
#define NF9_TCP_NB_FIN                          260

/* Template strings */
#define NF9_STR_IN_BYTES                      "\%IN_BYTES"
#define NF9_STR_IN_PKTS                       "\%IN_PKTS"
#define NF9_STR_FLOWS                         "\%FLOWS"
#define NF9_STR_PROTOCOL                      "\%PROTOCOL"
#define NF9_STR_TOS                           "\%TOS"
#define NF9_STR_TCP_FLAGS                     "\%TCP_FLAGS"
#define NF9_STR_L4_SRC_PORT                   "\%L4_SRC_PORT"
#define NF9_STR_IPV4_SRC_ADDR                 "\%IPV4_SRC_ADDR"
#define NF9_STR_SRC_MASK                      "\%SRC_MASK"
#define NF9_STR_INPUT_SNMP                    "\%INPUT_SNMP"
#define NF9_STR_L4_DST_PORT                   "\%L4_DST_PORT"
#define NF9_STR_IPV4_DST_ADDR                 "\%IPV4_DST_ADDR"
#define NF9_STR_DST_MASK                      "\%DST_MASK"
#define NF9_STR_OUTPUT_SNMP                   "\%OUTPUT_SNMP"
#define NF9_STR_IPV4_NEXT_HOP                 "\%IPV4_NEXT_HOP"
#define NF9_STR_SRC_AS                        "\%SRC_AS"
#define NF9_STR_DST_AS                        "\%DST_AS"
#define NF9_STR_BGP_IPV4_NEXT_HOP             "\%BGP_IPV4_NEXT_HOP"
#define NF9_STR_MUL_DST_PKTS                  "\%MUL_DST_PKTS"
#define NF9_STR_MUL_DST_BYTES                 "\%MUL_DST_BYTES"
#define NF9_STR_LAST_SWITCHED                 "\%LAST_SWITCHED"
#define NF9_STR_FIRST_SWITCHED                "\%FIRST_SWITCHED"
#define NF9_STR_OUT_BYTES                     "\%OUT_BYTES"
#define NF9_STR_OUT_PKTS                      "\%OUT_PKTS"
#define NF9_STR_IPV6_SRC_ADDR                 "\%IPV6_SRC_ADDR"
#define NF9_STR_IPV6_DST_ADDR                 "\%IPV6_DST_ADDR"
#define NF9_STR_IPV6_SRC_MASK                 "\%IPV6_SRC_MASK"
#define NF9_STR_IPV6_DST_MASK                 "\%IPV6_DST_MASK"
#define NF9_STR_IPV6_FLOW_LABEL               "\%IPV6_FLOW_LABEL"
#define NF9_STR_ICMP_TYPE                     "\%ICMP_TYPE"
#define NF9_STR_MUL_IGMP_TYPE                 "\%MUL_IGMP_TYPE"
#define NF9_STR_SAMPLING_INTERVAL             "\%SAMPLING_INTERVAL"
#define NF9_STR_SAMPLING_ALGORITHM            "\%SAMPLING_ALGORITHM"
#define NF9_STR_FLOW_ACTIVE_TIMEOUT           "\%FLOW_ACTIVE_TIMEOUT"
#define NF9_STR_FLOW_INACTIVE_TIMEOUT         "\%FLOW_INACTIVE_TIMEOUT"
#define NF9_STR_ENGINE_TYPE                   "\%ENGINE_TYPE"
#define NF9_STR_ENGINE_ID                     "\%ENGINE_ID"
#define NF9_STR_TOTAL_BYTES_EXP               "\%TOTAL_BYTES_EXP"
#define NF9_STR_TOTAL_PKTS_EXP                "\%TOTAL_PKTS_EXP"
#define NF9_STR_TOTAL_FLOWS_EXP               "\%TOTAL_FLOWS_EXP"
#define NF9_STR_MPLS_TOP_LABEL_TYPE           "\%MPLS_TOP_LABEL_TYPE"
#define NF9_STR_MPLS_TOP_LABEL_IP_ADDR        "\%MPLS_TOP_LABEL_IP_ADDR"
#define NF9_STR_FLOW_SAMPLER_ID               "\%FLOW_SAMPLER_ID"
#define NF9_STR_FLOW_SAMPLER_MODE             "\%FLOW_SAMPLER_MODE"
#define NF9_STR_FLOW_SAMPLER_RANDOM_INTERVAL  "\%FLOW_SAMPLER_RANDOM_INTERVAL"
#define NF9_STR_DST_TOS                       "\%DST_TOS"
#define NF9_STR_SRC_MAC                       "\%SRC_MAC"
#define NF9_STR_DST_MAC                       "\%DST_MAC"
#define NF9_STR_SRC_VLAN                      "\%SRC_VLAN"
#define NF9_STR_DST_VLAN                      "\%DST_VLAN"
#define NF9_STR_IP_PROTOCOL_VERSION           "\%IP_PROTOCOL_VERSION"
#define NF9_STR_DIRECTION                     "\%DIRECTION"
#define NF9_STR_IPV6_NEXT_HOP                 "\%IPV6_NEXT_HOP"
#define NF9_STR_BGP_IPV6_NEXT_HOP             "\%BGP_IPV6_NEXT_HOP"
#define NF9_STR_IPV6_OPTION_HEADERS           "\%IPV6_OPTION_HEADERS"
#define NF9_STR_MPLS_LABEL_1                  "\%MPLS_LABEL_1"
#define NF9_STR_MPLS_LABEL_2                  "\%MPLS_LABEL_2"
#define NF9_STR_MPLS_LABEL_3                  "\%MPLS_LABEL_3"
#define NF9_STR_MPLS_LABEL_4                  "\%MPLS_LABEL_4"
#define NF9_STR_MPLS_LABEL_5                  "\%MPLS_LABEL_5"
#define NF9_STR_MPLS_LABEL_6                  "\%MPLS_LABEL_6"
#define NF9_STR_MPLS_LABEL_7                  "\%MPLS_LABEL_7"
#define NF9_STR_MPLS_LABEL_8                  "\%MPLS_LABEL_8"
#define NF9_STR_MPLS_LABEL_9                  "\%MPLS_LABEL_9"
#define NF9_STR_MPLS_LABEL_10                 "\%MPLS_LABEL_10"
/* Flowset custom fields strings */
#define NF9_STR_TCP_NB_ACK                    "\%TCP_ACK"      
#define NF9_STR_TCP_NB_PUSH                   "\%TCP_PUSH"
#define NF9_STR_TCP_NB_RESET                  "\%TCP_RESET"
#define NF9_STR_TCP_NB_SYN                    "\%TCP_SYN"
#define NF9_STR_TCP_NB_FIN                    "\%TCP_FIN"

/* Default template */
#define NF9_SOFTFLOWD_DEFAULT_TEMPLATE NF9_STR_IPV4_SRC_ADDR" "NF9_STR_IPV4_DST_ADDR" "NF9_STR_LAST_SWITCHED" "NF9_STR_FIRST_SWITCHED" "NF9_STR_IN_BYTES" "NF9_STR_IN_PKTS" "NF9_STR_INPUT_SNMP" "NF9_STR_OUTPUT_SNMP" "NF9_STR_L4_SRC_PORT" "NF9_STR_L4_DST_PORT" "NF9_STR_PROTOCOL" "NF9_STR_TCP_FLAGS" "NF9_STR_IP_PROTOCOL_VERSION" "NF9_STR_TOS

/* Limits */
#define NF9_SOFTFLOWD_MAX_NB_RECORDS 100
#define NF9_SOFTFLOWD_STRING_TEMPLATE_MAX 256

/* Netflow v.9 headers */
struct NF9_HEADER {
	u_int16_t version,
                  flows;
	u_int32_t uptime_ms,
                  time_sec;
	u_int32_t package_sequence,
                  source_id;
} __packed;
struct NF9_FLOWSET_HEADER_COMMON {
	u_int16_t flowset_id,
                  length;
} __packed;


struct NF9_TEMPLATE_FLOWSET_HEADER {
	struct NF9_FLOWSET_HEADER_COMMON c;
	u_int16_t template_id,
                  count;
} __packed;
struct NF9_OPTION_TEMPLATE_FLOWSET_HEADER {
	struct NF9_FLOWSET_HEADER_COMMON c;
	u_int16_t template_id,
                  scope_length,
                  option_length;
} __packed;
struct NF9_DATA_FLOWSET_HEADER {
	struct NF9_FLOWSET_HEADER_COMMON c;
} __packed;


struct NF9_TEMPLATE_FLOWSET_RECORD {
	u_int16_t type, length;
} __packed;


/* Stuff pertaining to the templates that softflowd uses */
struct NF9_SOFTFLOWD_TEMPLATE {
	struct NF9_TEMPLATE_FLOWSET_HEADER h;
	struct NF9_TEMPLATE_FLOWSET_RECORD r[NF9_SOFTFLOWD_MAX_NB_RECORDS];
} __packed;

#define NF9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS	1
#define NF9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS	2
struct NF9_SOFTFLOWD_OPTION_TEMPLATE {
	struct NF9_OPTION_TEMPLATE_FLOWSET_HEADER h;
	struct NF9_TEMPLATE_FLOWSET_RECORD s[NF9_SOFTFLOWD_OPTION_TEMPLATE_SCOPE_RECORDS];
	struct NF9_TEMPLATE_FLOWSET_RECORD r[NF9_SOFTFLOWD_OPTION_TEMPLATE_NRECORDS];
} __packed;

/* softflowd data flowset types */
/*struct NF9_SOFTFLOWD_DATA_COMMON {
	u_int32_t last_switched,
                  first_switched;
	u_int32_t bytes,
                  packets;
	u_int32_t if_index_in,
                  if_index_out;
	u_int16_t src_port,
                  dst_port;
	u_int8_t  protocol,
                  tcp_flags,
                  ipproto,
                  tos;
} __packed;


struct NF9_SOFTFLOWD_DATA_V4 {
	u_int32_t src_addr, dst_addr;
	struct NF9_SOFTFLOWD_DATA_COMMON c;
} __packed;

struct NF9_SOFTFLOWD_DATA_V6 {
	u_int8_t src_addr[16], dst_addr[16];
	struct NF9_SOFTFLOWD_DATA_COMMON c;
} __packed;
*/
struct NF9_SOFTFLOWD_OPTION_DATA {
	struct NF9_FLOWSET_HEADER_COMMON c;
	u_int32_t scope_ifidx;
	u_int32_t sampling_interval;
	u_int8_t sampling_algorithm;
	u_int8_t padding[3];
} __packed;

/* Local data: templates and counters */
#define NF9_SOFTFLOWD_MAX_PACKET_SIZE	        512
#define NF9_SOFTFLOWD_V4_TEMPLATE_ID	        1024
#define NF9_SOFTFLOWD_V6_TEMPLATE_ID            2048
#define NF9_SOFTFLOWD_OPTION_TEMPLATE_ID	256

#define NF9_DEFAULT_TEMPLATE_INTERVAL	16

#define NF9_OPTION_SCOPE_SYSTEM    1
#define NF9_OPTION_SCOPE_INTERFACE 2
#define NF9_OPTION_SCOPE_LINECARD  3
#define NF9_OPTION_SCOPE_CACHE     4
#define NF9_OPTION_SCOPE_TEMPLATE  5

#define NF9_SAMPLING_ALGORITHM_DETERMINISTIC 1
#define NF9_SAMPLING_ALGORITHM_RANDOM        2

static struct NF9_SOFTFLOWD_TEMPLATE *v4_template = NULL;
static struct NF9_SOFTFLOWD_TEMPLATE *v6_template = NULL;
static struct NF9_SOFTFLOWD_OPTION_TEMPLATE *option_template = NULL;
static struct NF9_SOFTFLOWD_OPTION_DATA *option_data = NULL;
static int nf9_pkts_until_template = -1;

void nf9_init_template(char *str_template)
{
        if(strlen(str_template) > NF9_SOFTFLOWD_STRING_TEMPLATE_MAX) {
          fprintf(stderr,"The template has too many characters");
        }
        char str_template_tokenized[NF9_SOFTFLOWD_STRING_TEMPLATE_MAX];
        strncpy(str_template_tokenized,str_template,NF9_SOFTFLOWD_STRING_TEMPLATE_MAX);

        v4_template = malloc(sizeof(struct NF9_SOFTFLOWD_TEMPLATE));
        v6_template = malloc(sizeof(struct NF9_SOFTFLOWD_TEMPLATE));
        bzero(v4_template, sizeof(v4_template));
        bzero(v6_template, sizeof(v6_template));

        int count = 0;
	v4_template->h.template_id = htons(NF9_SOFTFLOWD_V4_TEMPLATE_ID);

        char *pch  = strtok(str_template_tokenized," \t\n\v\f\r");
        while(pch != NULL) {
          if(count == NF9_SOFTFLOWD_MAX_NB_RECORDS) {
            fprintf(stderr, "The template has too many entries.");
            exit(-1);
          }
          if (strcmp(pch,NF9_STR_IN_BYTES)== 0) {
	    v4_template->r[count].type = htons(NF9_IN_BYTES);
	    v4_template->r[count].length = htons(4);//Default value
          } else if (strcmp(pch,NF9_STR_IN_PKTS)== 0) {
	    v4_template->r[count].type = htons(NF9_IN_PACKETS);
	    v4_template->r[count].length = htons(4);//Default value
          /*
           *} else if (strcmp(pch,NF9_STR_FLOWS)== 0) {
	   *  v4_template->r[count].type = htons(NF9_FLOWS);
	   *  v4_template->r[count].length = htons(4);//Default value
           */
          } else if (strcmp(pch,NF9_STR_PROTOCOL)== 0) {
	    v4_template->r[count].type = htons(NF9_PROTOCOL);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_TOS)== 0) {
	    v4_template->r[count].type = htons(NF9_TOS);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_TCP_FLAGS)== 0) {
	    v4_template->r[count].type = htons(NF9_TCP_FLAGS);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_L4_SRC_PORT)== 0) {
	    v4_template->r[count].type = htons(NF9_L4_SRC_PORT);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_IPV4_SRC_ADDR)== 0) {
	    v4_template->r[count].type = htons(NF9_IPV4_SRC_ADDR);
	    v4_template->r[count].length = htons(4);
          } else if (strcmp(pch,NF9_STR_SRC_MASK)== 0) {
	    v4_template->r[count].type = htons(NF9_SRC_MASK);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_INPUT_SNMP)== 0) {
	    v4_template->r[count].type = htons(NF9_INPUT_SNMP);
	    v4_template->r[count].length = htons(2);//Default value
          } else if (strcmp(pch,NF9_STR_L4_DST_PORT)== 0) {
	    v4_template->r[count].type = htons(NF9_L4_DST_PORT);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_IPV4_DST_ADDR)== 0) {
	    v4_template->r[count].type = htons(NF9_IPV4_DST_ADDR);
	    v4_template->r[count].length = htons(4);
          } else if (strcmp(pch,NF9_STR_DST_MASK)== 0) {
	    v4_template->r[count].type = htons(NF9_DST_MASK);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_OUTPUT_SNMP)== 0) {
	    v4_template->r[count].type = htons(NF9_OUTPUT_SNMP);
	    v4_template->r[count].length = htons(2);//Default value
          /*
           *} else if (strcmp(pch,NF9_STR_IPV4_NEXT_HOP)== 0) {
	   *  v4_template->r[count].type = htons(NF9_IPV4_NEXT_HOP);
	   *  v4_template->r[count].length = htons(4);
           */
          } else if (strcmp(pch,NF9_STR_SRC_AS)== 0) {
	    v4_template->r[count].type = htons(NF9_SRC_AS);
	    v4_template->r[count].length = htons(2);//Default value
          } else if (strcmp(pch,NF9_STR_DST_AS)== 0) {
	    v4_template->r[count].type = htons(NF9_DST_AS);
	    v4_template->r[count].length = htons(2);//Default value
          /*
           *} else if (strcmp(pch,NF9_STR_BGP_IPV4_NEXT_HOP)== 0) {
	   *  v4_template->r[count].type = htons(NF9_BGP_IPV4_NEXT_HOP);
	   *  v4_template->r[count].length = htons(4);
           *} else if (strcmp(pch,NF9_STR_MUL_DST_PKTS)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MUL_DST_PKTS);
	   *  v4_template->r[count].length = htons(4);//Default value
           *} else if (strcmp(pch,NF9_STR_MUL_DST_BYTES)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MUL_DST_BYTES);
	   *  v4_template->r[count].length = htons(4);//Default value
           */
          } else if (strcmp(pch,NF9_STR_LAST_SWITCHED)== 0) {
	    v4_template->r[count].type = htons(NF9_LAST_SWITCHED);
	    v4_template->r[count].length = htons(4);
          } else if (strcmp(pch,NF9_STR_FIRST_SWITCHED)== 0) {
	    v4_template->r[count].type = htons(NF9_FIRST_SWITCHED);
	    v4_template->r[count].length = htons(4);
          } else if (strcmp(pch,NF9_STR_OUT_BYTES)== 0) {
	    v4_template->r[count].type = htons(NF9_OUT_BYTES);
	    v4_template->r[count].length = htons(4);//Default value
          } else if (strcmp(pch,NF9_STR_OUT_PKTS)== 0) {
	    v4_template->r[count].type = htons(NF9_OUT_PKTS);
	    v4_template->r[count].length = htons(4);//Default value
          } else if (strcmp(pch,NF9_STR_IPV6_SRC_ADDR)== 0) {
	    v4_template->r[count].type = htons(NF9_IPV6_SRC_ADDR);
	    v4_template->r[count].length = htons(16);
          } else if (strcmp(pch,NF9_STR_IPV6_DST_ADDR)== 0) {
	    v4_template->r[count].type = htons(NF9_IPV6_DST_ADDR);
	    v4_template->r[count].length = htons(16);
          } else if (strcmp(pch,NF9_STR_IPV6_SRC_MASK)== 0) {
	    v4_template->r[count].type = htons(NF9_IPV6_SRC_MASK);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_IPV6_DST_MASK)== 0) {
	    v4_template->r[count].type = htons(NF9_IPV6_DST_MASK);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_IPV6_FLOW_LABEL)== 0) {
	    v4_template->r[count].type = htons(NF9_IPV6_FLOW_LABEL);
	    v4_template->r[count].length = htons(3);
          } else if (strcmp(pch,NF9_STR_ICMP_TYPE)== 0) {
	    v4_template->r[count].type = htons(NF9_ICMP_TYPE);
	    v4_template->r[count].length = htons(2);
          /*
           *} else if (strcmp(pch,NF9_STR_MUL_IGMP_TYPE)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MUL_IGMP_TYPE);
	   *  v4_template->r[count].length = htons(2);
           */
          } else if (strcmp(pch,NF9_STR_SAMPLING_INTERVAL)== 0) {
	    v4_template->r[count].type = htons(NF9_SAMPLING_INTERVAL);
	    v4_template->r[count].length = htons(4);
          } else if (strcmp(pch,NF9_STR_SAMPLING_ALGORITHM)== 0) {
	    v4_template->r[count].type = htons(NF9_SAMPLING_ALGORITHM);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_FLOW_ACTIVE_TIMEOUT)== 0) {
	    v4_template->r[count].type = htons(NF9_FLOW_ACTIVE_TIMEOUT);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_FLOW_INACTIVE_TIMEOUT)== 0) {
	    v4_template->r[count].type = htons(NF9_FLOW_INACTIVE_TIMEOUT);
	    v4_template->r[count].length = htons(2);
          /*
           *} else if (strcmp(pch,NF9_STR_ENGINE_TYPE)== 0) {
	   *  v4_template->r[count].type = htons(NF9_ENGINE_TYPE);
	   *  v4_template->r[count].length = htons(1);
           *} else if (strcmp(pch,NF9_STR_ENGINE_ID)== 0) {
	   *  v4_template->r[count].type = htons(NF9_ENGINE_ID);
	   *  v4_template->r[count].length = htons(1);
           */
          } else if (strcmp(pch,NF9_STR_TOTAL_BYTES_EXP)== 0) {
	    v4_template->r[count].type = htons(NF9_TOTAL_BYTES_EXP);
	    v4_template->r[count].length = htons(4);//Default value
          } else if (strcmp(pch,NF9_STR_TOTAL_PKTS_EXP)== 0) {
	    v4_template->r[count].type = htons(NF9_TOTAL_PKTS_EXP);
	    v4_template->r[count].length = htons(4);//Default value
          } else if (strcmp(pch,NF9_STR_TOTAL_FLOWS_EXP)== 0) {
	    v4_template->r[count].type = htons(NF9_TOTAL_FLOWS_EXP);
	    v4_template->r[count].length = htons(4);//Default value
          /*
           *} else if (strcmp(pch,NF9_STR_MPLS_TOP_LABEL_TYPE)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_TOP_LABEL_TYPE);
	   *  v4_template->r[count].length = htons(1);
           *} else if (strcmp(pch,NF9_STR_MPLS_TOP_LABEL_IP_ADDR)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_TOP_LABEL_IP_ADDR);
	   *  v4_template->r[count].length = htons(4);
           *} else if (strcmp(pch,NF9_STR_FLOW_SAMPLER_ID)== 0) {
	   *  v4_template->r[count].type = htons(NF9_FLOW_SAMPLER_ID);
	   *  v4_template->r[count].length = htons(1);
           *} else if (strcmp(pch,NF9_STR_FLOW_SAMPLER_MODE)== 0) {
	   *  v4_template->r[count].type = htons(NF9_FLOW_SAMPLER_MODE);
	   *  v4_template->r[count].length = htons(1);
           *} else if (strcmp(pch,NF9_STR_FLOW_SAMPLER_RANDOM_INTERVAL)== 0) {
	   *  v4_template->r[count].type = htons(NF9_FLOW_SAMPLER_RANDOM_INTERVAL);
	   *  v4_template->r[count].length = htons(4);
           */
          } else if (strcmp(pch,NF9_STR_DST_TOS)== 0) {
	    v4_template->r[count].type = htons(NF9_DST_TOS);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_SRC_MAC)== 0) {
	    v4_template->r[count].type = htons(NF9_SRC_MAC);
	    v4_template->r[count].length = htons(6);
          } else if (strcmp(pch,NF9_STR_DST_MAC)== 0) {
	    v4_template->r[count].type = htons(NF9_DST_MAC);
	    v4_template->r[count].length = htons(6);
          } else if (strcmp(pch,NF9_STR_SRC_VLAN)== 0) {
	    v4_template->r[count].type = htons(NF9_SRC_VLAN);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_DST_VLAN)== 0) {
	    v4_template->r[count].type = htons(NF9_DST_VLAN);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_IP_PROTOCOL_VERSION)== 0) {
	    v4_template->r[count].type = htons(NF9_IP_PROTOCOL_VERSION);
	    v4_template->r[count].length = htons(1);
          } else if (strcmp(pch,NF9_STR_DIRECTION)== 0) {
	    v4_template->r[count].type = htons(NF9_DIRECTION);
	    v4_template->r[count].length = htons(1);
          /*
           *} else if (strcmp(pch,NF9_STR_IPV6_NEXT_HOP)== 0) {
	   *  v4_template->r[count].type = htons(NF9_IPV6_NEXT_HOP);
	   *  v4_template->r[count].length = htons(16);
           *} else if (strcmp(pch,NF9_STR_BGP_IPV6_NEXT_HOP)== 0) {
	   *  v4_template->r[count].type = htons(NF9_BGP_IPV6_NEXT_HOP);
	   *  v4_template->r[count].length = htons(16);
           */
          } else if (strcmp(pch,NF9_STR_IPV6_OPTION_HEADERS)== 0) {
	    v4_template->r[count].type = htons(NF9_IPV6_OPTION_HEADERS);
	    v4_template->r[count].length = htons(4);
          /*
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_1)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_1);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_2)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_2);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_3)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_3);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_4)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_4);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_5)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_5);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_6)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_6);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_7)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_7);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_8)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_8);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_9)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_9);
	   *  v4_template->r[count].length = htons(3);
           *} else if (strcmp(pch,NF9_STR_MPLS_LABEL_10)== 0) {
	   *  v4_template->r[count].type = htons(NF9_MPLS_LABEL_10);
	   *  v4_template->r[count].length = htons(3);
           */
          } else if (strcmp(pch,NF9_STR_TCP_NB_ACK)== 0) {
	    v4_template->r[count].type = htons(NF9_TCP_NB_ACK);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_TCP_NB_PUSH)== 0) {
	    v4_template->r[count].type = htons(NF9_TCP_NB_PUSH);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_TCP_NB_RESET)== 0) {
	    v4_template->r[count].type = htons(NF9_TCP_NB_RESET);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_TCP_NB_SYN)== 0) {
	    v4_template->r[count].type = htons(NF9_TCP_NB_SYN);
	    v4_template->r[count].length = htons(2);
          } else if (strcmp(pch,NF9_STR_TCP_NB_FIN)== 0) {
	    v4_template->r[count].type = htons(NF9_TCP_NB_FIN);
	    v4_template->r[count].length = htons(2);
          } else {
            fprintf(stderr,"Malformed template. %s is not a valid field type !\n",pch);
            exit(1);
          }
          count++;

          pch = strtok(NULL," \t\n\v\f\r");
        }

	v4_template->h.c.flowset_id = htons(NF9_TEMPLATE_FLOWSET_ID);
	v4_template->h.c.length = htons(count*4+4);
        v4_template->h.template_id = htons(NF9_SOFTFLOWD_V4_TEMPLATE_ID);
        v4_template->h.count = htons(count);

        /*TODO: v6_template */
}

static void
nf9_init_option( u_int16_t ifidx,
                 struct OPTION *option) {
        option_template = malloc(sizeof(struct NF9_SOFTFLOWD_OPTION_TEMPLATE));
        option_template = malloc(sizeof(struct NF9_SOFTFLOWD_OPTION_DATA));

	bzero(&option_template, sizeof(option_template));
	option_template->h.c.flowset_id = htons(NF9_OPTIONS_FLOWSET_ID);
	option_template->h.c.length = htons(sizeof(option_template));
	option_template->h.template_id = htons(NF9_SOFTFLOWD_OPTION_TEMPLATE_ID);
	option_template->h.scope_length = htons(sizeof(option_template->s));
	option_template->h.option_length = htons(sizeof(option_template->r));
	option_template->s[0].type = htons(NF9_OPTION_SCOPE_INTERFACE);
	option_template->s[0].length = htons(sizeof(option_data->scope_ifidx));
	option_template->r[0].type = htons(NF9_SAMPLING_INTERVAL);
	option_template->r[0].length = htons(sizeof(option_data->sampling_interval));
	option_template->r[1].type = htons(NF9_SAMPLING_ALGORITHM);
	option_template->r[1].length = htons(sizeof(option_data->sampling_algorithm));

	bzero(&option_data, sizeof(option_data));
	option_data->c.flowset_id = htons(NF9_SOFTFLOWD_OPTION_TEMPLATE_ID);
	option_data->c.length = htons(sizeof(option_data));
	option_data->scope_ifidx = htonl(ifidx);
	option_data->sampling_interval = htonl(option->sample);
	option_data->sampling_algorithm = NF9_SAMPLING_ALGORITHM_DETERMINISTIC;
}




/* copy the flows into the packet */
static int
nf_flow_to_flowset( const struct FLOW *flow,
                    u_char *packet,
                    u_int len,
                    u_int16_t ifidx,
                    const struct timeval *system_boot_time,
                    u_int *len_used) {

        char buffer_in[512];
        char buffer_out[512];
        int offset = 0;
        int i;
        for(i=0; i<ntohs(v4_template->h.count);i++) {
          switch(ntohs(v4_template->r[i].type)) {
            case NF9_IN_BYTES                    :
              *((int*)(buffer_in  + offset)) = htonl(flow->octets[0]);
	      *((int*)(buffer_out + offset)) = htonl(flow->octets[1]);
              break;
            case NF9_IN_PACKETS                  :
              *((int*)(buffer_in  + offset)) = htonl(flow->packets[0]);
	      *((int*)(buffer_out + offset)) = htonl(flow->packets[1]);
              break;
            case NF9_FLOWS                       : //TODO
              break;
            case NF9_PROTOCOL                    :
              *(buffer_in  + offset) = flow->protocol;
	      *(buffer_out + offset) = flow->protocol;
                break;
            case NF9_TOS                         :
              *(buffer_in  + offset) = flow->tos[0];
	      *(buffer_out + offset) = flow->tos[1];
              break;
            case NF9_TCP_FLAGS                   :
              *(buffer_in  + offset) = flow->tcp_flags[0];
	      *(buffer_out + offset) = flow->tcp_flags[1];
              break;
            case NF9_L4_SRC_PORT                 :
              *((short*)(buffer_in  + offset)) = flow->port[0];
              *((short*)(buffer_out + offset)) = flow->port[1];
              break;
            case NF9_IPV4_SRC_ADDR               :
              if(flow->af == AF_INET) {
                memcpy(buffer_in  + offset, &flow->addr[0].v4, 4);
	        memcpy(buffer_out + offset, &flow->addr[1].v4, 4);
              } else {
                bzero(buffer_in  + offset, 4);
                bzero(buffer_out + offset, 4);
              }
              break;
            case NF9_SRC_MASK                    : //We do not use a mask
              *(buffer_in  + offset) = 32;
              *(buffer_out + offset) = 32;
              break;
            case NF9_INPUT_SNMP                  : //No routing
              bzero(buffer_in  + offset, 2);
              bzero(buffer_out + offset, 2);
              break;
            case NF9_L4_DST_PORT                 :
              *((short*)(buffer_in  + offset)) = flow->port[1];
              *((short*)(buffer_out + offset)) = flow->port[0];
              break;
            case NF9_IPV4_DST_ADDR               :
              if(flow->af == AF_INET) {
	        memcpy(buffer_in + offset,  &flow->addr[1].v4, 4);
	        memcpy(buffer_out + offset, &flow->addr[0].v4, 4);
              } else {
                bzero(buffer_in  + offset, 4);
                bzero(buffer_out + offset, 4);
              }
              break;
            case NF9_DST_MASK                    : //We do not use a mask
              *(buffer_in  + offset) = 32;
              *(buffer_out + offset) = 32;
              break;
            case NF9_OUTPUT_SNMP                 : //No routing
              bzero(buffer_in  + offset, 2);
              bzero(buffer_out + offset, 2);
              break;
            case NF9_IPV4_NEXT_HOP               : //No routing
              bzero(buffer_in  + offset, 4);
              bzero(buffer_out + offset, 4);
              break;
            case NF9_SRC_AS                      : //No routing
              bzero(buffer_in  + offset, 2);
              bzero(buffer_out + offset, 2);
              break;
            case NF9_DST_AS                      :
              bzero(buffer_in  + offset, 2);
              bzero(buffer_out + offset, 2);
              break;
            case NF9_BGP_IPV4_NEXT_HOP           : //No routing
              break;
            case NF9_MUL_DST_PKTS                : //No multicast
              break;
            case NF9_MUL_DST_BYTES               : //No multicast
              break;
            case NF9_LAST_SWITCHED               :
	      *((int*)(buffer_in  + offset)) = htonl(timeval_sub_ms(&flow->flow_last, system_boot_time));
	      *((int*)(buffer_out + offset)) = htonl(timeval_sub_ms(&flow->flow_last, system_boot_time));
              break;
            case NF9_FIRST_SWITCHED              :
	      *((int*)(buffer_in  + offset)) = htonl(timeval_sub_ms(&flow->flow_start, system_boot_time));
	      *((int*)(buffer_out + offset)) = htonl(timeval_sub_ms(&flow->flow_start, system_boot_time));
              break;
            case NF9_OUT_BYTES                   :
              *((int*)(buffer_in  + offset)) = htonl(flow->octets[1]);
	      *((int*)(buffer_out + offset)) = htonl(flow->octets[0]);
              break;
            case NF9_OUT_PKTS                    :
              *((int*)(buffer_in  + offset)) = htonl(flow->packets[1]);
	      *((int*)(buffer_out + offset)) = htonl(flow->packets[0]);
              break;
            case NF9_IPV6_SRC_ADDR               :
	      memcpy(buffer_in + offset,  &flow->addr[0].v6, 16);
	      memcpy(buffer_out + offset, &flow->addr[1].v6, 16);
              break;
            case NF9_IPV6_DST_ADDR               :
	      memcpy(buffer_in + offset,  &flow->addr[1].v6, 16);
	      memcpy(buffer_out + offset, &flow->addr[0].v6, 16);
              break;
            case NF9_IPV6_SRC_MASK               :
              *(buffer_in  + offset) = 128;
              *(buffer_out + offset) = 128;
              break;
            case NF9_IPV6_DST_MASK               :
              *(buffer_in  + offset) = 128;
              *(buffer_out + offset) = 128;
              break;
            case NF9_IPV6_FLOW_LABEL             :
              *((int*)(buffer_in  + offset)) = flow->ip6_flowlabel[0];
              *((int*)(buffer_out + offset)) = flow->ip6_flowlabel[1];
              break;
            case NF9_ICMP_TYPE                   : //TODO
              bzero(buffer_in  + offset, 2);
              bzero(buffer_out + offset, 2);
              break;
            case NF9_MUL_IGMP_TYPE               :
              break;
            case NF9_SAMPLING_INTERVAL           : //TODO
              bzero(buffer_in  + offset, 4);
              bzero(buffer_out + offset, 4);
              break;
            case NF9_SAMPLING_ALGORITHM          : //TODO
              *(buffer_in  + offset)  = 0;
              *(buffer_out + offset)  = 0;
              break;
            case NF9_FLOW_ACTIVE_TIMEOUT         : //TODO
              bzero(buffer_in  + offset, 2);
              bzero(buffer_out + offset, 2);
              break;
            case NF9_FLOW_INACTIVE_TIMEOUT       : //TODO
              bzero(buffer_in  + offset, 2);
              bzero(buffer_out + offset, 2);
              break;
            case NF9_ENGINE_TYPE                 :
              break;
            case NF9_ENGINE_ID                   :
              break;
            case NF9_TOTAL_BYTES_EXP             :
              bzero(buffer_in  + offset, 4);
              bzero(buffer_out + offset, 4);
              break;
            case NF9_TOTAL_PKTS_EXP              :
              bzero(buffer_in  + offset, 4);
              bzero(buffer_out + offset, 4);
              break;
            case NF9_TOTAL_FLOWS_EXP             :
              bzero(buffer_in  + offset, 4);
              bzero(buffer_out + offset, 4);
              break;
            case NF9_MPLS_TOP_LABEL_TYPE         :
              break;
            case NF9_MPLS_TOP_LABEL_IP_ADDR      :
              break;
            case NF9_FLOW_SAMPLER_ID             :
              break;
            case NF9_FLOW_SAMPLER_MODE           :
              break;
            case NF9_FLOW_SAMPLER_RANDOM_INTERVAL:
              break;
            case NF9_DST_TOS		         :
              *(buffer_in  + offset) = flow->tos[1];
	      *(buffer_out + offset) = flow->tos[0];
              break;
            case NF9_SRC_MAC			 : //TODO
              bzero(buffer_in  + offset, 6);
              bzero(buffer_out + offset, 6);
              break;
            case NF9_DST_MAC		   	 : //TODO
              bzero(buffer_in  + offset, 6);
              bzero(buffer_out + offset, 6);
              break;
            case NF9_SRC_VLAN			 :
              *((short*)(buffer_in  + offset)) = htons(flow->vlanid);
	      *((short*)(buffer_out + offset)) = htons(flow->vlanid);
              break;
            case NF9_DST_VLAN			 :
              *((short*)(buffer_in  + offset)) = htons(flow->vlanid);
	      *((short*)(buffer_out + offset)) = htons(flow->vlanid);
              break;
            case NF9_IP_PROTOCOL_VERSION	 :
              *(buffer_in  + offset)  = 4;
              *(buffer_out + offset)  = 4;
              break;
            case NF9_DIRECTION			 :
              *(buffer_in  + offset)  = 0;
              *(buffer_out + offset)  = 0;
              break;
            case NF9_IPV6_NEXT_HOP	         : //No routing
              break;
            case NF9_BGP_IPV6_NEXT_HOP	         :
              break;
            case NF9_IPV6_OPTION_HEADERS         :
              bzero(buffer_in  + offset, 4);
              bzero(buffer_out + offset, 4);
              break;
            case NF9_MPLS_LABEL_1                :
              break;
            case NF9_MPLS_LABEL_2                :
              break;
            case NF9_MPLS_LABEL_3                :
              break;
            case NF9_MPLS_LABEL_4                :
              break;
            case NF9_MPLS_LABEL_5                :
              break;
            case NF9_MPLS_LABEL_6                :
              break;
            case NF9_MPLS_LABEL_7                :
              break;
            case NF9_MPLS_LABEL_8                :
              break;
            case NF9_MPLS_LABEL_9                :
              break;
            case NF9_MPLS_LABEL_10               :
              break;
            case NF9_TCP_NB_ACK                  :
              *((short*)(buffer_in  + offset)) = htons(flow->tcp_ack_nb[0]);
              *((short*)(buffer_out + offset)) = htons(flow->tcp_ack_nb[1]);
              break;
            case NF9_TCP_NB_PUSH                 :
              *((short*)(buffer_in  + offset)) = htons(flow->tcp_push_nb[0]);
              *((short*)(buffer_out + offset)) = htons(flow->tcp_push_nb[1]);
              break;
            case NF9_TCP_NB_RESET                :
              *((short*)(buffer_in  + offset)) = htons(flow->tcp_reset_nb[0]);
              *((short*)(buffer_out + offset)) = htons(flow->tcp_reset_nb[1]);
              break;
            case NF9_TCP_NB_SYN                  :
              *((short*)(buffer_in  + offset)) = htons(flow->tcp_syn_nb[0]);
              *((short*)(buffer_out + offset)) = htons(flow->tcp_syn_nb[1]);
              break;
            case NF9_TCP_NB_FIN                :
              *((short*)(buffer_in  + offset)) = htons(flow->tcp_fin_nb[0]);
              *((short*)(buffer_out + offset)) = htons(flow->tcp_fin_nb[1]);
              break;
          }
          offset += ntohs(v4_template->r[i].length);
        }



        /*if(flow->af == AF_INET6) {
          return 0;
        }



	union {
		struct NF9_SOFTFLOWD_DATA_V4 d4;
		struct NF9_SOFTFLOWD_DATA_V6 d6;
	} d[2];
	struct NF9_SOFTFLOWD_DATA_COMMON *dc[2];


	u_int freclen, ret_len, nflows;

	bzero(d, sizeof(d));
	*len_used = nflows = ret_len = 0;
	switch (flow->af) {
	case AF_INET:
		freclen = sizeof(struct NF9_SOFTFLOWD_DATA_V4);
		memcpy(&d[0].d4.src_addr, &flow->addr[0].v4, 4);
		memcpy(&d[0].d4.dst_addr, &flow->addr[1].v4, 4);
		memcpy(&d[1].d4.src_addr, &flow->addr[1].v4, 4);
		memcpy(&d[1].d4.dst_addr, &flow->addr[0].v4, 4);
		dc[0] = &d[0].d4.c;
		dc[1] = &d[1].d4.c;
		dc[0]->ipproto = dc[1]->ipproto = 4;
		break;
	case AF_INET6:
		freclen = sizeof(struct NF9_SOFTFLOWD_DATA_V6);
		memcpy(&d[0].d6.src_addr, &flow->addr[0].v6, 16);
		memcpy(&d[0].d6.dst_addr, &flow->addr[1].v6, 16);
		memcpy(&d[1].d6.src_addr, &flow->addr[1].v6, 16);
		memcpy(&d[1].d6.dst_addr, &flow->addr[0].v6, 16);
		dc[0] = &d[0].d6.c;
		dc[1] = &d[1].d6.c;
		dc[0]->ipproto = dc[1]->ipproto = 6;
		break;
	default:
		return (-1);
	}

	dc[0]->first_switched = dc[1]->first_switched =
	    htonl(timeval_sub_ms(&flow->flow_start, system_boot_time));
	dc[0]->last_switched = dc[1]->last_switched =
	    htonl(timeval_sub_ms(&flow->flow_last, system_boot_time));
	dc[0]->bytes = htonl(flow->octets[0]);
	dc[1]->bytes = htonl(flow->octets[1]);
	dc[0]->packets = htonl(flow->packets[0]);
	dc[1]->packets = htonl(flow->packets[1]);
	dc[0]->if_index_in = dc[0]->if_index_out = htonl(ifidx);
	dc[1]->if_index_in = dc[1]->if_index_out = htonl(ifidx);
	dc[0]->src_port = dc[1]->dst_port = flow->port[0];
	dc[1]->src_port = dc[0]->dst_port = flow->port[1];
	dc[0]->protocol = dc[1]->protocol = flow->protocol;
	dc[0]->tcp_flags = flow->tcp_flags[0];
	dc[1]->tcp_flags = flow->tcp_flags[1];
	dc[0]->tos = flow->tos[0];
	dc[1]->tos = flow->tos[1];

        */


	u_int freclen, ret_len, nflows;
	*len_used = nflows = ret_len = 0;
        if (flow->octets[0] > 0) {
		if (ret_len + offset > len)
			return (-1);
		memcpy(packet + ret_len, buffer_in, offset);
		ret_len += offset;
		nflows++;
	}
	if (flow->octets[1] > 0) {
		if (ret_len + offset > len)
			return (-1);
		memcpy(packet + ret_len, buffer_out, offset);
		ret_len += offset;
		nflows++;
	}

	*len_used = ret_len;

	return (nflows);
}


















/*
 * Given an array of expired flows, send netflow v9 report packets
 * Returns number of packets sent or -1 on error
 */
int
send_netflow_v9(  struct FLOW **flows,
                  int num_flows,
                  int nfsock,
		  u_int16_t ifidx,
                  struct FLOWTRACKPARAMETERS *param,
		  int verbose_flag)
{
	struct NF9_HEADER *nf9;
	struct NF9_DATA_FLOWSET_HEADER *dh;
	struct timeval now;
	u_int offset, last_af, i, j, num_packets, inc, last_valid;
	socklen_t errsz;
	int err, r;
	u_char packet[NF9_SOFTFLOWD_MAX_PACKET_SIZE];
	struct timeval *system_boot_time = &param->system_boot_time;
	u_int64_t *flows_exported = &param->flows_exported;
	u_int64_t *packets_sent = &param->packets_sent;
	struct OPTION *option = &param->option;

	gettimeofday(&now, NULL);

	if (nf9_pkts_until_template == -1) {
                if(v4_template == NULL || v6_template == NULL) {
                        nf9_init_template(NF9_SOFTFLOWD_DEFAULT_TEMPLATE);
                }
		nf9_pkts_until_template = 0;
		if (option != NULL && option->sample > 1 && option_template == NULL) {
			nf9_init_option(ifidx, option);
		}
	}

	last_valid = num_packets = 0;
	for (j = 0; j < num_flows;) {
		bzero(packet, sizeof(packet));
		nf9 = (struct NF9_HEADER *)packet;

		nf9->version = htons(9);
		nf9->flows = 0; /* Filled as we go, htons at end */
		nf9->uptime_ms = htonl(timeval_sub_ms(&now, system_boot_time));
		nf9->time_sec = htonl(time(NULL));
		nf9->source_id = 0;
		offset = sizeof(*nf9);

		/* Refresh template headers if we need to */
		if (nf9_pkts_until_template <= 0) {
			memcpy(packet + offset, &(v4_template->h), sizeof(v4_template->h));
			offset += sizeof(v4_template->h);
			memcpy(packet + offset, v4_template->r, ntohs(v4_template->h.count) * 4);
                        offset += ntohs(v4_template->h.count) * 4;
                        nf9->flows++;

                        /*memcpy(packet + offset, v6_template,
			    sizeof(v6_template));
			offset += sizeof(v6_template);
			nf9->flows++;*/
			if (option != NULL && option->sample > 1){
				memcpy(packet + offset, option_template,
				       sizeof(option_template));
				offset += sizeof(option_template);
				nf9->flows++;
				memcpy(packet + offset, option_data,
				       sizeof(option_data));
				offset += sizeof(option_data);
				nf9->flows++;
			}

			nf9_pkts_until_template = NF9_DEFAULT_TEMPLATE_INTERVAL;
		}

		dh = NULL;
		last_af = 0;
		for (i = 0; i + j < num_flows; i++) {
			if (dh == NULL || flows[i + j]->af != last_af) {
				if (dh != NULL) {
					if (offset % 4 != 0) {
						/* Pad to multiple of 4 */
						dh->c.length += 4 - (offset % 4);
						offset += 4 - (offset % 4);
					}
					/* Finalise last header */
					dh->c.length = htons(dh->c.length);
				}
				if (offset + sizeof(*dh) > sizeof(packet)) {
					/* Mark header is finished */
					dh = NULL;
					break;
				}
				dh = (struct NF9_DATA_FLOWSET_HEADER *)
				    (packet + offset);
				dh->c.flowset_id =
				    (flows[i + j]->af == AF_INET) ?
				    v4_template->h.template_id :
				    v6_template->h.template_id;
				last_af = flows[i + j]->af;
				last_valid = offset;
				dh->c.length = sizeof(*dh); /* Filled as we go */
				offset += sizeof(*dh);
			}

			r = nf_flow_to_flowset( flows[i + j],
                                                packet + offset,
			                        sizeof(packet) - offset,
                                                ifidx,
                                                system_boot_time,
                                                &inc);
			if (r <= 0) {
				/* yank off data header, if we had to go back */
				if (last_valid)
					offset = last_valid;
				break;
			}
			offset += inc;
			dh->c.length += inc;
			nf9->flows += r;
			last_valid = 0; /* Don't clobber this header now */
			if (verbose_flag) {
				logit(LOG_DEBUG, "Flow %d/%d: "
				    "r %d offset %d type %04x len %d(0x%04x) "
				    "flows %d", r, i, j, offset,
				    dh->c.flowset_id, dh->c.length,
				    dh->c.length, nf9->flows);
			}
		}
		/* Don't finish header if it has already been done */
		if (dh != NULL) {
			if (offset % 4 != 0) {
				/* Pad to multiple of 4 */
				dh->c.length += 4 - (offset % 4);
				offset += 4 - (offset % 4);
			}
			/* Finalise last header */
			dh->c.length = htons(dh->c.length);
		}
		param->records_sent += nf9->flows;
		nf9->flows = htons(nf9->flows);
		nf9->package_sequence = htonl((u_int32_t)((*packets_sent + num_packets + 1) & 0x00000000ffffffff));

		if (verbose_flag)
			logit(LOG_DEBUG, "Sending flow packet len = %d", offset);
		errsz = sizeof(err);
		/* Clear ICMP errors */
		getsockopt(nfsock, SOL_SOCKET, SO_ERROR, &err, &errsz);
		if (send(nfsock, packet, (size_t)offset, 0) == -1)
			return (-1);
		num_packets++;
		nf9_pkts_until_template--;

		j += i;
	}

	*flows_exported += j;
	return (num_packets);
}

void
netflow9_resend_template(void)
{
	if (nf9_pkts_until_template > 0)
		nf9_pkts_until_template = 0;
}
