#ifndef __ELASTICSEARCH_H__
#define __ELASTICSEARCH_H__

#include <curl/curl.h>

#define MAX_LEN_ES_BULK 16*1024
struct ES_CON {
	CURL *curl;
	char url[512];
	char index[64];
	char doc_type[64];
	struct curl_slist *headers;
};

struct ES_CON* setup_elasticsearch(const char* url, const char* index, const char* doc_type);
int log2elasticserch(struct ES_CON* con, struct FLOW *flow, int expired);
void cleanup_elasticsearch(struct ES_CON* con);

#endif // __ELASTICSEARCH_H__
