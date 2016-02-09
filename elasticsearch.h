#ifndef __ELASTICSEARCH_H__
#define __ELASTICSEARCH_H__

#include <curl/curl.h>

#define MAX_LEN_FLOW_JSON 4096
struct ES_CON {
	CURL *curl;
	char url[512];
	char index[64];
	char doc_type[64];
	struct curl_slist *headers;
};

void cleanup_elasticsearch(struct ES_CON* con);
struct ES_CON* setup_elasticsearch(const char* url, const char* index, const char* doc_type);

#endif // __ELASTICSEARCH_H__
