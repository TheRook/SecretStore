/*
 * config.h
 *
 *  Created on: Apr 28, 2013
 *      Author: grey
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define CONFIG_LABEL_PORT_NUM "listen_port"
#define CONFIG_LABEL_DB_PATH "db_path"

struct parsed_config {
	int is_valid;
	int port;
	char* db_path;
};

struct parsed_config
parse_config(char* config_file_path);
void
free_config_strings(struct parsed_config* config);

#endif /* CONFIG_H_ */
