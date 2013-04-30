/*
 * config.c
 *
 *  Created on: Apr 28, 2013
 *      Author: grey
 */
#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include "config.h"

struct parsed_config
parse_config(char* config_file_path) {
	//http://www.hyperrealm.com/libconfig/libconfig_manual.html
	int port;
	char* db_path;
	int db_path_len;

	config_t cfg;
	struct parsed_config parsed = {0};
	parsed.is_valid=1;

	config_init(&cfg);


	if(!config_read_file(&cfg, config_file_path)) {
		fprintf(stderr, "Error reading config file at: %d - %s\n",
			//config_error_file(&cfg),
			config_error_line(&cfg),
			config_error_text(&cfg));
		config_destroy(&cfg);
		parsed.is_valid=0;
	}

	if(parsed.is_valid){
		if(config_lookup_int(&cfg, CONFIG_LABEL_PORT_NUM, &port) == CONFIG_TRUE) {
			parsed.port=port;
		} else {
			parsed.is_valid=0;
		}

		if(config_lookup_string(&cfg, CONFIG_LABEL_DB_PATH, (const char**)&db_path) == CONFIG_TRUE) {
			// copy to our own buffer, the original one gets destroyed by config_destroy()
			db_path_len=strlen(db_path);
			if(db_path_len) {
				parsed.db_path=malloc(db_path_len+1);
				strncpy(parsed.db_path, db_path, db_path_len);
				parsed.db_path[db_path_len]=0;
			} else {
				parsed.is_valid=0;
			}
		} else {
			parsed.is_valid=0;
		}
	}

	config_destroy(&cfg);
	return parsed;
}

void
free_config_strings(struct parsed_config* config) {
	if(config->db_path)
		free(config->db_path);
	config->db_path=0;
}
