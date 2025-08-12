/*
 *
 * COPYRIGHT:
 *
 * This software is Copyright (c) 2011-2025 NETWAYS GmbH, William Preston
 *                                <support@netways.de>
 *
 * (Except where explicitly superseded by other copyright notices)
 *
 *
 * LICENSE:
 *
 * This work is made available to you under the terms of Version 2 of
 * the GNU General Public License. A copy of that license should have
 * been provided with this software, but in any event can be snarfed
 * from http://www.fsf.org.
 *
 * This work is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 or visit their web page on the internet at
 * http://www.fsf.org.
 *
 *
 * CONTRIBUTION SUBMISSION POLICY:
 *
 * (The following paragraph is not intended to limit the rights granted
 * to you to modify and distribute this software under the terms of
 * the GNU General Public License and is only of importance to you if
 * you choose to contribute your changes and enhancements to the
 * community by submitting them to NETWAYS GmbH.)
 *
 * By intentionally submitting any modifications, corrections or
 * derivatives to this work, or any other work intended for use with
 * this Software, to NETWAYS GmbH, you confirm that
 * you are the copyright holder for those contributions and you grant
 * NETWAYS GmbH a nonexclusive, worldwide, irrevocable,
 * royalty-free, perpetual, license to use, copy, create derivative
 * works based on those contributions, and sublicense and distribute
 * those contributions and any derivatives thereof.
 *
 *
 *
 */

#include <net-snmp/net-snmp-config.h>

#include <limits.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

/* getenv */
#include <stdlib.h>

#define MAX_ITEMS       1024
#define MAX_STRING      4096
#define MEMCPY(a, b, c) memcpy(a, b, (sizeof(a) > c) ? c : sizeof(a))
#define TERMSTR(a, b)   a[(((sizeof(a) - 1) < b) ? (sizeof(a) - 1) : b)] = '\0'

/* default timeout is 30s */
#define DFLT_TIMEOUT 30000000UL

struct OIDStruct {
	oid name[MAX_OID_LEN];
	size_t name_len;
};

struct table_list {
	int type;
	int index;
	struct cisco_env_table *table;
	struct table_list *next;
};

struct cisco_env_table {
	int index;
	char descr[60];
	int value;
	int low;
	int high; /* threshold for temp */
	int last;
	int state;
	int source;
};

netsnmp_session *start_session(char * /*community*/, char * /*hostname*/);
netsnmp_session *start_session_v3(char * /*user*/, char * /*auth_proto*/, char * /*auth_pass*/,
								  char * /*priv_proto*/, char * /*priv_pass*/, char * /*hostname*/);
int usage(char * /*progname*/);
int addstr(char ** /*strp*/, size_t * /*strs*/, const char * /*format*/, ...);
int parseoids(int /*i*/, char * /*oid_list*/, struct OIDStruct * /*query*/);
void strcpy_nospaces(char * /*dest*/, char * /*src*/);
int addval(int env, int index, int var, netsnmp_variable_list * /*result*/);

struct table_list *table_listp = 0;

unsigned long timeout = DFLT_TIMEOUT;

typedef struct {
	char *hostname;
	char *community;
	char *user;
	char *auth_proto;
	char *auth_pass;
	char *priv_proto;
	char *priv_pass;
} check_cisco_health_config;

check_cisco_health_config check_cisco_health_config_init() {
	check_cisco_health_config result = {
		.hostname = NULL,
		.community = strdup("public"),
		.user = NULL,
		.auth_proto = NULL,
		.auth_pass = NULL,
		.priv_proto = NULL,
		.priv_pass = NULL,
	};
	return result;
}

typedef struct {
	int errorcode;
	check_cisco_health_config config;
} opt_parse_wrapper;

opt_parse_wrapper parse_commandline(int argc, char *argv[]) {
	opt_parse_wrapper result = {
		.config = check_cisco_health_config_init(),
		.errorcode = 0,
	};

	/* parse options */
	int opt;
	while ((opt = getopt(argc, argv, "c:h:j:J:k:K:t:u:?")) != -1) {
		switch (opt) {
		case 'c':
			result.config.community = optarg;
			break;
		case 'h':
			result.config.hostname = optarg;
			break;
		case 'j':
			result.config.auth_proto = optarg;
			break;
		case 'J':
			result.config.auth_pass = optarg;
			break;
		case 'k':
			result.config.priv_proto = optarg;
			break;
		case 'K':
			result.config.priv_pass = optarg;
			break;
		case 't':
			timeout = strtol(optarg, NULL, 10) * 1000UL;
			break;
		case 'u':
			result.config.user = optarg;
			break;
		case '?':
		default:
			exit(usage(argv[0]));
		}
	}

	if (!(result.config.hostname && (result.config.community || result.config.user))) {
		result.errorcode = 1;
		printf("Missing either hostname or community or user\n\n");
	}

	return result;
}

int main(int argc, char *argv[]) {
	opt_parse_wrapper conf_wrap = parse_commandline(argc, argv);

	if (conf_wrap.errorcode != 0) {
		exit(usage(argv[0]));
	}

	const check_cisco_health_config config = conf_wrap.config;

	/* set the MIB variable if it is unset to avoid net-snmp warnings */
	if (getenv("MIBS") == NULL) {
		setenv("MIBS", "", 1);
	}

	netsnmp_session *snmp_session;

	if (config.user) {
		/* use snmpv3 */
		snmp_session = start_session_v3(config.user, config.auth_proto, config.auth_pass,
										config.priv_proto, config.priv_pass, config.hostname);
	} else {
		snmp_session = start_session(config.community, config.hostname);
	}

	static char *cisco_env[] = {".1.3.6.1.4.1.9.9.13.1"};
	static char *cisco_env_tables[] = {".1.3.6.1.4.1.9.9.13.1.2", ".1.3.6.1.4.1.9.9.13.1.3",
									   ".1.3.6.1.4.1.9.9.13.1.4", ".1.3.6.1.4.1.9.9.13.1.5"};

	/* allocate the space for the OIDs */
	struct OIDStruct *OIDp =
		(struct OIDStruct *)calloc((sizeof(cisco_env) / sizeof(char *)), sizeof(*OIDp));
	struct OIDStruct *OIDtable =
		(struct OIDStruct *)calloc((sizeof(cisco_env_tables) / sizeof(char *)), sizeof(*OIDtable));

	/* parse the table oids for comparison later */
	for (size_t i = 0; i < (sizeof(cisco_env_tables) / sizeof(char *)); i++) {
		OIDtable[i].name_len = MAX_OID_LEN;
		if (!snmp_parse_oid(cisco_env_tables[i], OIDtable[i].name, &OIDtable[i].name_len)) {
			snmp_perror(cisco_env_tables[i]);
			SOCK_CLEANUP;
			exit(1);
		}
	}

	int index = 0;
	int count = 0;
	int endoftable = 0;
	struct OIDStruct lastOid; /* save the last OID retrieved in case our bulk
								 get was insufficient */
	while (endoftable == 0) {
		netsnmp_pdu *pdu;
		if (count == 0) {
			pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
			pdu->non_repeaters = 0;
			pdu->max_repetitions = MAX_ITEMS;

			for (size_t i = 0; i < (sizeof(cisco_env) / sizeof(char *)); i++) {
				OIDp[i].name_len = MAX_OID_LEN;
				if (!snmp_parse_oid(cisco_env[i], OIDp[i].name, &OIDp[i].name_len)) {
					snmp_perror(cisco_env[i]);
					SOCK_CLEANUP;
					exit(1);
				}
				snmp_add_null_var(pdu, OIDp[i].name, OIDp[i].name_len);
			}
		} else {
			/* we have not received all of the table */

			pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
			pdu->non_repeaters = 0;
			pdu->max_repetitions = MAX_ITEMS;

			snmp_add_null_var(pdu, lastOid.name, lastOid.name_len);
		}

		netsnmp_pdu *response;
		int status = snmp_synch_response(snmp_session, pdu, &response);

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
			netsnmp_variable_list *vars = response->variables;

			for (; vars; vars = vars->next_variable) {
				count++;
				/*
				 * if the next OID is shorter
				 * or if the next OID doesn't begin with our base OID
				 * then we have reached the end of the table :-)
				 * print_variable(vars->name, vars->name_length, vars);
				 */

				/* save the OID in case we need additional packets */
				memcpy(lastOid.name, vars->name, (vars->name_length * sizeof(oid)));
				lastOid.name_len = vars->name_length;
				/* print_objid(lastOid.name, lastOid.name_len); */
				if (vars->name_length < OIDp[0].name_len ||
					(memcmp(OIDp[0].name, vars->name, OIDp[0].name_len * sizeof(oid)))) {
#ifdef DEBUG
					printf("reached end of table\n");
#endif
					endoftable++;
					break;
				}

				for (size_t i = 0; i < (sizeof(cisco_env_tables) / sizeof(char *)); i++) {
					if (!memcmp(OIDtable[i].name, vars->name, OIDtable[i].name_len * sizeof(oid))) {
						index = (int)vars->name[(vars->name_length - 1)];
						int var = (int)vars->name[(vars->name_length - 2)];
						addval(i, index, var, vars);
					}
				}
			}

		} else {
			/*
			 * FAILURE: print what went wrong!
			 */

			if (status == STAT_SUCCESS) {
				printf("Error in packet\nReason: %s\n", snmp_errstring(response->errstat));
			} else if (status == STAT_TIMEOUT) {
				printf("Timeout: No response from %s.\n", config.hostname);
			} else {
				snmp_sess_perror("snmp_bulkget", snmp_session);
			}
			exit(2);
		}
		/*
		 * Clean up:
		 *   free the response.
		 */
		if (response) {
			snmp_free_pdu(response);
		}
	}

	free(OIDp);

	int warnflag = 0;
	int errorflag = 0;
	char outstr[MAX_STRING] = {};
	char *outstrp = outstr;
	size_t outstrsize = sizeof(outstr);
	char extstr[MAX_STRING] = {};
	char *extstrp = extstr;
	size_t extstrsize = sizeof(extstr);
	char perfstr[MAX_STRING];
	perfstr[0] = 0;
	char *perfstrp = perfstr;
	size_t perfstrsize = sizeof(perfstr);
	static char *table_names[] = {"Voltage", "Temperature", "Fan", "PSU"};
	for (struct table_list *ptr = table_listp; ptr; ptr = ptr->next) {
		switch (ptr->table->state) {
		case 1:
			addstr(&extstrp, &extstrsize, "[OK] %s(%s)", table_names[ptr->type], ptr->table->descr);
			if ((ptr->type == 0 || ptr->type == 1) && (ptr->table->value > 0)) {
				addstr(&extstrp, &extstrsize, " is %d%c\n", ptr->table->value,
					   (ptr->type ? 'C' : 'V'));
				/* now add perfdata */
				addstr(&perfstrp, &perfstrsize, " %s_%d=%d%c", table_names[ptr->type], ptr->index,
					   ptr->table->value, ptr->type ? 'C' : 'V');
			} else {
				addstr(&extstrp, &extstrsize, " is normal\n");
			}
			break;
		case 2:
			warnflag++;
			addstr(&outstrp, &outstrsize, " %s in state warning", ptr->table->descr);
			addstr(&extstrp, &extstrsize, "[WARNING] %s(%s)", table_names[ptr->type],
				   ptr->table->descr);
			if (ptr->type == 0 || ptr->type == 1) {
				addstr(&extstrp, &extstrsize, " is %d%c\n", ptr->table->value,
					   (ptr->type ? 'C' : 'V'));
			} else {
				addstr(&extstrp, &extstrsize, " in state warning\n");
			}
			break;
		case 3:
		case 4:
			errorflag++;
			addstr(&outstrp, &outstrsize, " %s in state critical", ptr->table->descr);
			addstr(&extstrp, &extstrsize, "[CRITICAL] %s(%s)", table_names[ptr->type],
				   ptr->table->descr);
			if (ptr->type == 0 || ptr->type == 1) {
				addstr(&extstrp, &extstrsize, " is %d%c\n", ptr->table->value,
					   (ptr->type ? 'C' : 'V'));
			} else {
				addstr(&extstrp, &extstrsize, " in state critical\n");
			}
			break;
		case 5:
			/* PSU not present */
			break;
		default:
			addstr(&extstrp, &extstrsize, "[OK] %s(%s) in state unknown\n", table_names[ptr->type],
				   ptr->table->descr);
			ptr->table->value = 0;
			break;
		}
	}

	if (errorflag) {
		printf("CRITICAL:");
	} else if (warnflag) {
		printf("WARNING:");
	} else if (table_listp) {
		printf("OK: All components within tolerances");
	} else {
		printf("OK: No environmental module found for this device");
	}

	printf("%s | %s\n%s", outstr, perfstr, extstr);

	snmp_close(snmp_session);

	SOCK_CLEANUP;
	return ((errorflag) ? 2 : ((warnflag) ? 1 : 0));
}

netsnmp_session *start_session(char *community, char *hostname) {
	/*
	 * Initialize the SNMP library
	 */
	init_snmp("snmp_bulkget");

	/* setup session to hostname */
	netsnmp_session session = {};
	snmp_sess_init(&session);
	session.peername = hostname;

	/* bulk gets require V2c or later */
	session.version = SNMP_VERSION_2c;

	session.community = (u_char *)community;
	/*session->community = "public"; */
	session.community_len = strlen(community);
	session.timeout = timeout;

	/*
	 * Open the session
	 */
	SOCK_STARTUP;
	netsnmp_session *result_session = snmp_open(&session); /* establish the session */

	if (!result_session) {
		snmp_sess_perror("snmp_bulkget", &session);
		SOCK_CLEANUP;
		exit(1);
	}

	return (result_session);
}

netsnmp_session *start_session_v3(char *user, char *auth_proto, char *auth_pass, char *priv_proto,
								  char *priv_pass, char *hostname) {
	init_snmp("snmp_bulkget");

	netsnmp_session session = {};
	snmp_sess_init(&session);
	session.peername = hostname;

	session.version = SNMP_VERSION_3;

	session.securityName = user;
	session.securityModel = SNMP_SEC_MODEL_USM;
	session.securityNameLen = strlen(user);

	if (priv_proto && priv_pass) {
		if (!strcmp(priv_proto, "AES")) {
			session.securityPrivProto =
				snmp_duplicate_objid(usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN);
			session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
		} else if (!strcmp(priv_proto, "DES")) {
			session.securityPrivProto =
				snmp_duplicate_objid(usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN);
			session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
		} else {
			printf("Unknown priv protocol %s\n", priv_proto);
			exit(3);
		}
		session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		session.securityPrivKeyLen = USM_PRIV_KU_LEN;
	} else {
		session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
		session.securityPrivKeyLen = 0;
	}

	if (auth_proto && auth_pass) {
		if (!strcmp(auth_proto, "SHA")) {
			session.securityAuthProto =
				snmp_duplicate_objid(usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN);
			session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
		} else if (!strcmp(auth_proto, "MD5")) {
			session.securityAuthProto =
				snmp_duplicate_objid(usmHMACMD5AuthProtocol, USM_AUTH_PROTO_MD5_LEN);
			session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		} else {
			printf("Unknown auth protocol %s\n", auth_proto);
			exit(3);
		}
		session.securityAuthKeyLen = USM_AUTH_KU_LEN;
	} else {
		session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
		session.securityAuthKeyLen = 0;
		session.securityPrivKeyLen = 0;
	}

	if ((session.securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) ||
		(session.securityLevel == SNMP_SEC_LEVEL_AUTHNOPRIV)) {
		if (generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
						(unsigned char *)auth_pass, strlen(auth_pass), session.securityAuthKey,
						&session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			printf("Error generating AUTH sess\n");
		}
		if (session.securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) {
			if (generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
							(unsigned char *)priv_pass, strlen(priv_pass), session.securityPrivKey,
							&session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
				printf("Error generating PRIV sess\n");
			}
		}
	}

	session.timeout = timeout;

	/*
	 * Open the session
	 */
	SOCK_STARTUP;
	netsnmp_session *result_session = snmp_open(&session); /* establish the session */

	if (!result_session) {
		snmp_sess_perror("snmp_bulkget", &session);
		SOCK_CLEANUP;
		exit(1);
	}

	return (result_session);
}

int usage(char *progname) {
	printf("Usage: %s -h <hostname>", progname);
	printf("\n");
	printf(" -c\t\tcommunity (default public)\n");
	printf(" -j\t\tSNMPv3 Auth Protocol (SHA|MD5)\n");
	printf(" -J\t\tSNMPv3 Auth Phrase\n");
	printf(" -k\t\tSNMPv3 Privacy Protocol (AES|DES)\n");
	printf(" -K\t\tSNMPv3 Privacy Phrase\n");
	printf(" -t\t\tsets the SNMP timeout (in ms)\n");
	printf(" -u\t\tSNMPv3 User\n");
	printf("\n");
	return 3;
}

int addstr(char **strp, size_t *strs, const char *format, ...) {
	va_list val;
	size_t written;

	va_start(val, format);

	written = vsnprintf(*strp, *strs, format, val);
	va_end(val);

	if (written >= *strs) {
		/* buffer full */
		*strs = 0;
		return (1);
	}

	*strs = (*strs - written);
	*strp = (*strp + written);
	return (0);
}
int addval(int env, int index, int var, netsnmp_variable_list *result) {
	struct table_list *ptr;
	struct table_list *last = 0;
	enum {
		VOLT = 0,
		TEMP = 1,
		FAN = 2,
		PSU = 3
	};

	/* check if there is already a value */
	for (ptr = table_listp; ptr; ptr = ptr->next) {
		if (ptr->type == env && ptr->index == index) {
			break;
		}
		last = ptr;
	}
	if (!ptr) {
		ptr = (struct table_list *)malloc(sizeof(struct table_list));
		ptr->table = (struct cisco_env_table *)malloc(sizeof(struct cisco_env_table));
		ptr->next = 0;
		ptr->type = env;
		ptr->index = index;
		if (last) {
			last->next = ptr;
		} else {
			table_listp = ptr;
		}
	}

	switch (env) {
	case VOLT:
		switch (var) {
		case 2:
			MEMCPY(ptr->table->descr, result->val.string, result->val_len);
			TERMSTR(ptr->table->descr, result->val_len);
			break;
		case 3:
			ptr->table->value = *(result->val.integer);
			break;
		case 4:
			ptr->table->low = *(result->val.integer);
			break;
		case 5:
			ptr->table->high = *(result->val.integer);
			break;
		case 7:
			ptr->table->state = *(result->val.integer);
			break;
		}
		break;
	case TEMP:
		switch (var) {
		case 2:
			MEMCPY(ptr->table->descr, result->val.string, result->val_len);
			TERMSTR(ptr->table->descr, result->val_len);
			break;
		case 3:
			ptr->table->value = *(result->val.integer);
			break;
		case 4:
			ptr->table->high = *(result->val.integer);
			break;
		case 6:
			ptr->table->state = *(result->val.integer);
			break;
		}
		break;
	case FAN:
		switch (var) {
		case 2:
			MEMCPY(ptr->table->descr, result->val.string, result->val_len);
			TERMSTR(ptr->table->descr, result->val_len);
			break;
		case 3:
			ptr->table->state = *(result->val.integer);
			break;
		}
		break;
	case PSU:
		switch (var) {
		case 2:
			MEMCPY(ptr->table->descr, result->val.string, result->val_len);
			TERMSTR(ptr->table->descr, result->val_len);
			break;
		case 3:
			ptr->table->state = *(result->val.integer);
			break;
		case 4:
			ptr->table->source = *(result->val.integer);
			break;
		}
		break;
	default:
		break;
	}
	return (0);
}
int parseoids(int i, char *oid_list, struct OIDStruct *query) {
	/* parse oid list */

	/* read each OID from our array and add it to the pdu request */
	query[i].name_len = MAX_OID_LEN;
	if (!snmp_parse_oid(oid_list, query[i].name, &query[i].name_len)) {
		snmp_perror(oid_list);
		SOCK_CLEANUP;
		exit(1);
	}
	return (0);
}

/* only use for strings we already know the size of */
void strcpy_nospaces(char *dest, char *src) {
	static unsigned char allowed[256] =
		"_________________________________!_#_%__()*+,-.-0123456789___=_?@"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^__abcdefghijklmnopqrstuvwxyz{_}________"
		"______________________________________________________________________"
		"____________________________________________________";

	while (*src) {
		*(dest++) = allowed[(unsigned char)*(src++)];
	}
	*dest = 0;
}
