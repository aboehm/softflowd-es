/*
 * Copyright 2016 Alexander Böhm <alxndr.boehm@gmail.com> All rights reserved.
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
#include "convtime.h"
#include "softflowd.h"
#include <sys/time.h>
#include "elasticsearch.h"

/* defined in softflowd.c to enable verbose output */
int verbose_flag;

/* Format a time */
static const char *
index_from_timestamp(struct timeval* t, const char* index_prefix)
{
	struct tm *tm;
	char buf[32];
	static char ret[256];

	tm = gmtime(&t->tv_sec);
	strftime(buf, sizeof(buf), "%Y.%m.%d", tm);
	snprintf(ret, sizeof(ret), "%s-%s", index_prefix, buf);

	return (ret);
}

/* Format a time */
static const char *
format_time_usec(struct timeval* t)
{
	struct tm *tm;
	char buf[32];
	static char ret[32];

	tm = gmtime(&t->tv_sec);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);
	snprintf(ret, sizeof(ret), "%s.%06ld", buf, t->tv_usec);

	return (ret);
}

/* Get a unique id from a flow  */ 
static const char*
flow_uid(struct FLOW* flow, int in_flow, struct timeval * now)
{
	static char ret[256];
	char addr1[64], addr2[64];

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));

	snprintf(ret, sizeof(ret), "%"PRIu64"_%s_%s",
		flow->flow_seq,
		format_time_usec(now),
		in_flow ? "in" : "out"
	    );

	return (ret);
}

static const char *
proto2str(u_int8_t proto)
{
	static char buf[8];

	switch (proto) {
		case IPPROTO_ICMP: return "ICMP";
		case IPPROTO_IGMP: return "IGMP";
		case IPPROTO_IPIP: return "IPIP";
		case IPPROTO_TCP: return "TCP";
		case IPPROTO_EGP: return "EGP";
		case IPPROTO_PUP: return "PUP";
		case IPPROTO_UDP: return "UDP";
		case IPPROTO_IDP: return "IDP";
		case IPPROTO_TP: return "TP";
		case IPPROTO_DCCP: return "DCCP";
		case IPPROTO_IPV6: return "IPV6";
		case IPPROTO_RSVP: return "RSVP";
		case IPPROTO_GRE: return "GRE";
		case IPPROTO_ESP: return "ESP";
		case IPPROTO_AH: return "AH";
		case IPPROTO_MTP: return "MTP";
		case IPPROTO_ENCAP: return "ENCAP";
		case IPPROTO_PIM: return "PIM";
		case IPPROTO_COMP: return "COMP";
		case IPPROTO_SCTP: return "SCTP";
		case IPPROTO_UDPLITE: return "UDPLITE";
		case IPPROTO_RAW: return "RAW";
		case IPPROTO_ICMPV6: return "ICMPV6";
		case IPPROTO_IP: return "IP";
		default: snprintf(buf, sizeof(buf), "%u", proto); break;
	}
	
	return buf;
}

static const char *
af2str(int family)
{
	static char buf[32];

	switch (family) {
	case AF_UNSPEC:		return "unspecified";
	case AF_BRIDGE:		return "BRIDGE";
	case AF_DECnet:		return "DECnet";
	case AF_INET:		return "IP";
	case AF_INET6:		return "IPv6";
	case AF_IPX:		return "IPX";
	case AF_X25:		return "X25";
	case AF_AX25:		return "AX25";
	case AF_ATMPVC:		return "ATMPVC";
	case AF_APPLETALK:	return "AppleTALK";
	default:		snprintf(buf, sizeof(buf), "UNKNOWN(%u)", family); break;
	}

	return buf;
}

static const char *
format_flow_es_bulk(struct FLOW *flow, int expired, const char* es_index, const char* es_doc_type)
{
	char addr1[64], addr2[64];
	static char buf[MAX_LEN_ES_BULK];
	struct timeval now;
	
	gettimeofday(&now, NULL);

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));

	snprintf(buf, sizeof(buf),
		"{ \"index\": { \"_index\" : \"%s\", \"_type\" : \"%s\", \"_id\": \"%s\" }\n"
		"{"
		" \"timestamp\": \"%s\" "
		", \"seq\":%"PRIu64" "
		", \"type\": \"softflow\" "
		", \"src_addr\": \"%s:%hu\", \"src_ip\": \"%s\", \"src_port\": %u "
		", \"dst_addr\": \"%s:%hu\", \"dst_ip\": \"%s\", \"dst_port\": %u "
		", \"proto\": \"%s\" "
		", \"octets\": %u "
		", \"packets\": %u "
		", \"start\": \"%s\" "
		", \"finish\": \"%s\" "
		", \"tcp_flags\": \"%02x\" "
		", \"flowlabel\": \"%08x\" "
		", \"expired\": %s "
		", \"protocol_family\": \"%s\" "
		"}\n"
		"{ \"index\": { \"_index\" : \"%s\", \"_type\" : \"%s\", \"_id\": \"%s\" }\n"
		"{"
		" \"timestamp\": \"%s\" "
		", \"seq\":%"PRIu64" "
		", \"src_addr\": \"%s:%hu\", \"src_ip\": \"%s\", \"src_port\": %u "
		", \"dst_addr\": \"%s:%hu\", \"dst_ip\": \"%s\", \"dst_port\": %u "
		", \"proto\": \"%s\" "
		", \"octets\": %u "
		", \"packets\": %u "
		", \"start\": \"%s\" "
		", \"finish\": \"%s\" "
		", \"tcp_flags\": \"%02x\" "
		", \"flowlabel\": \"%08x\" "
		", \"expired\": %s "
		", \"protocol_family\": \"%s\" "
		"}",
		index_from_timestamp(&now, es_index), es_doc_type, flow_uid(flow, 1, &now),
		format_time_usec(&now),
		flow->flow_seq,
		addr1, ntohs(flow->port[0]), addr1, ntohs(flow->port[0]),
		addr2, ntohs(flow->port[1]), addr2, ntohs(flow->port[1]),
		proto2str(flow->protocol),
		flow->octets[0], flow->packets[0], 
		format_time_usec(&flow->flow_start),
		format_time_usec(&flow->flow_last),
		flow->tcp_flags[0],
		flow->ip6_flowlabel[0],
		expired ? "true" : "false",
		af2str(flow->af),
		es_index, es_doc_type, flow_uid(flow, 0, &now),
		format_time_usec(&now),
		flow->flow_seq,
		addr2, ntohs(flow->port[1]), addr2, ntohs(flow->port[1]),
		addr1, ntohs(flow->port[0]), addr1, ntohs(flow->port[0]),
		proto2str(flow->protocol),
		flow->octets[1], flow->packets[1], 
		format_time_usec(&flow->flow_start),
		format_time_usec(&flow->flow_last),
		flow->tcp_flags[1],
		flow->ip6_flowlabel[1],
		expired ? "true" : "false",
		af2str(flow->af)
	);

	return (buf);
}

size_t es_write_callback_nothing(char *ptr, size_t size, size_t nmemb, void *userdata)
{
}

struct ES_CON*
setup_elasticsearch(const char* url, const char* index, const char* doc_type)
{
	char es_url[1024];
	struct ES_CON* con;

	con = malloc(sizeof(struct ES_CON));
	if (!con)
		return NULL;

	con->curl = curl_easy_init();
	if (!con->curl) {
		free(con);
		return NULL;
	}

	// set url of ES
	snprintf(es_url, sizeof(es_url), "%s/_bulk", url, index);
	curl_easy_setopt(con->curl, CURLOPT_URL, es_url);

	// set headers
	con->headers = curl_slist_append(con->headers, "Content-Type: application/json; charset=UTF-8");
	con->headers = curl_slist_append(con->headers, "User-Agent: softflowd");
	curl_easy_setopt(con->curl, CURLOPT_HTTPHEADER, con->headers);

	// we want to post data
	curl_easy_setopt(con->curl, CURLOPT_POST, 1L);
	// no need for response output	
	curl_easy_setopt(con->curl, CURLOPT_WRITEFUNCTION, &es_write_callback_nothing);
	
	strncpy(con->url, es_url, sizeof(con->url));
	strncpy(con->index, index, sizeof(con->index));
	strncpy(con->doc_type, doc_type, sizeof(con->doc_type));

	return con;
}

void
cleanup_elasticsearch(struct ES_CON* con) {
	if (con) {
		if (con->curl)
			curl_easy_cleanup(con->curl);

		if (con->headers)
			curl_slist_free_all(con->headers);

		free(con);
	}
}

int
log2elasticserch(struct ES_CON* con, struct FLOW *flow, int expired) {
	const char* bulk = format_flow_es_bulk(flow, expired, con->index, con->doc_type);

	if (verbose_flag)
		printf("es bulk: %s\n", bulk);

	curl_easy_setopt(con->curl, CURLOPT_POSTFIELDS, bulk);
	curl_easy_perform(con->curl);

	return 0;
}
