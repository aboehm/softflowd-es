#include "convtime.h"
#include "softflowd.h"
#include <sys/time.h>
#include "elasticsearch.h"

extern int verbose_flag;

/* Get a unique id from a flow  */ 
static const char*
flow_uid(struct FLOW* flow)
{
	static char buf[128];
	char buf_time[64];
	struct tm *tm;
	char addr1[64], addr2[64];

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));

	tm = gmtime(&flow->flow_start.tv_sec);
	strftime(buf_time, sizeof(buf_time),
		"%Y%m%dT%H%M%S", tm);

	snprintf(buf, sizeof(buf), "%s%05hu%s%05hu%s", 
		addr1, ntohs(flow->port[0]),	
		addr1, ntohs(flow->port[1]),
		buf_time
	    );

	return (buf);
}

static const char *
format_flow_json(struct FLOW *flow, int expired)
{
	char addr1[64], addr2[64], stime[32], ftime[32], etime[32];
	static char buf[MAX_LEN_FLOW_JSON];

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));

	snprintf(stime, sizeof(ftime), "%s", 
	    format_time(flow->flow_start.tv_sec));
	snprintf(ftime, sizeof(ftime), "%s", 
	    format_time(flow->flow_last.tv_sec));

	snprintf(buf, sizeof(buf),
		"{"
		" \"seq\":%"PRIu64" "
		", \"type\": \"softflow\" "
		", \"src_addr\": \"%s:%hu\" "
		", \"src_ip\": \"%s\" "
		", \"src_port\": %u "
		", \"dst_addr\": \"%s:%hu\" "
		", \"dst_ip\": \"%s\" "
		", \"dst_port\": %u "
		", \"proto\": %u "
		", \"octets\": %u "
		", \"packets\": %u "
		", \"start\": \"%s.%03ld\" "
		", \"finish\": \"%s.%03ld\" "
		", \"tcp_flags\": \"%02x\" "
		", \"flowlabel\": \"%08x\" "
		", \"expired\": %s "
		"}\n"
		" \"seq\":%"PRIu64" "
		", \"src_addr\": \"%s:%hu\" "
		", \"dst_addr\": \"%s:%hu\" "
		", \"proto\": %u "
		", \"octets\": %u "
		", \"packets\": %u "
		", \"start\": \"%s.%03ld\" "
		", \"finish\": \"%s.%03ld\" "
		", \"tcp_flags\": \"%02x\" "
		", \"flowlabel\": \"%08x\" "
		", \"expired\": %s "
		"}",
		flow->flow_seq,
		addr1, ntohs(flow->port[0]), addr1, ntohs(flow->port[0]),
		addr2, ntohs(flow->port[1]), addr2, ntohs(flow->port[1]),
		(int)flow->protocol, 
		flow->octets[0], flow->packets[0], 
		stime, (flow->flow_start.tv_usec + 500) / 1000, 
		ftime, (flow->flow_last.tv_usec + 500) / 1000,
		flow->tcp_flags[0],
		flow->ip6_flowlabel[0],
		expired ? "true" : "false",
		flow->flow_seq,
		addr1, ntohs(flow->port[0]), addr2, ntohs(flow->port[1]),
		(int)flow->protocol, 
		flow->octets[1], flow->packets[1], 
		stime, (flow->flow_start.tv_usec + 500) / 1000, 
		ftime, (flow->flow_last.tv_usec + 500) / 1000,
		flow->tcp_flags[1],
		flow->ip6_flowlabel[1],
		expired ? "true" : "false"
	);

	return (buf);
}

static const char *
proto2string(u_int8_t proto)
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
format_flow_es_bulk(struct FLOW *flow, int expired, const char* es_index, const char* es_doc_type)
{
	char addr1[64], addr2[64], stime[32], ftime[32], etime[32], tstime[32];
	static char buf[MAX_LEN_FLOW_JSON];
	struct timeval now;
	
	gettimeofday(&now, NULL);

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));

	snprintf(stime, sizeof(ftime), "%s", 
		format_time(flow->flow_start.tv_sec));
	snprintf(ftime, sizeof(ftime), "%s", 
		format_time(flow->flow_last.tv_sec));
	snprintf(tstime, sizeof(tstime), "%s.%03ld", 
		format_time(now.tv_sec), now.tv_usec);

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
		", \"start\": \"%s.%03ld\" "
		", \"finish\": \"%s.%03ld\" "
		", \"tcp_flags\": \"%02x\" "
		", \"flowlabel\": \"%08x\" "
		", \"expired\": %s "
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
		", \"start\": \"%s.%03ld\" "
		", \"finish\": \"%s.%03ld\" "
		", \"tcp_flags\": \"%02x\" "
		", \"flowlabel\": \"%08x\" "
		", \"expired\": %s "
		"}",
		es_index, es_doc_type, flow_uid(flow),
		tstime,
		flow->flow_seq,
		addr1, ntohs(flow->port[0]), addr1, ntohs(flow->port[0]),
		addr2, ntohs(flow->port[1]), addr2, ntohs(flow->port[1]),
		proto2string(flow->protocol),
		flow->octets[0], flow->packets[0], 
		stime, (flow->flow_start.tv_usec + 500) / 1000, 
		ftime, (flow->flow_last.tv_usec + 500) / 1000,
		flow->tcp_flags[0],
		flow->ip6_flowlabel[0],
		expired ? "true" : "false",
		es_index, es_doc_type, flow_uid(flow),
		tstime,
		flow->flow_seq,
		addr1, ntohs(flow->port[0]), addr1, ntohs(flow->port[0]),
		addr2, ntohs(flow->port[1]), addr2, ntohs(flow->port[1]),
		proto2string(flow->protocol),
		flow->octets[1], flow->packets[1], 
		stime, (flow->flow_start.tv_usec + 500) / 1000, 
		ftime, (flow->flow_last.tv_usec + 500) / 1000,
		flow->tcp_flags[1],
		flow->ip6_flowlabel[1],
		expired ? "true" : "false"
	);

	return (buf);
}

size_t es_write_callback_nothing(char *ptr, size_t size, size_t nmemb, void *userdata) {
}

struct ES_CON*
setup_elasticsearch(const char* url, const char* index, const char* doc_type) {
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

static int
log2elasticserch(struct ES_CON* con, struct FLOW *flow, int expired) {
	const char* bulk = format_flow_es_bulk(flow, expired, con->index, con->doc_type);

	if (verbose_flag)
		printf("es bulk: %s\n", bulk);

	curl_easy_setopt(con->curl, CURLOPT_POSTFIELDS, bulk);
	curl_easy_perform(con->curl);

	return 0;
}

static void
dump_flows_es(struct FLOWTRACK *ft, struct ES_CON* es, FILE* out)
{
	struct EXPIRY *expiry;
	time_t now;
	long proceeded_flows = 0;

	now = time(NULL);

	EXPIRY_FOREACH(expiry, EXPIRIES, &ft->expiries) {
		if (!log2elasticserch(es, expiry->flow, (long int) expiry->expires_at - now < 0))
			proceeded_flows++;
	}

	if (es) {
		fprintf(out, "%u flows to %s (index: %s) proceeded\n",
			proceeded_flows, es->url, es->index);
	} else {
		fprintf(out, "no elasticsearch server specified\n");
	}

}
