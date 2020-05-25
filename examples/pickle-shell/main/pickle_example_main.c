/* Pickle Shell: A TCL like language */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "assert.h"
#include "driver/uart.h"
#include "errno.h"
#include "esp_console.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_spi_flash.h"
#include "esp_system.h"
#include "esp_vfs_dev.h"
#include "esp_vfs_fat.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "linenoise/linenoise.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "pickle.h"
#include "sdkconfig.h"
#include "esp_event.h"

#define UNUSED(X) ((void)(X))
#define EOL "\r\n"
#define ok(i, ...)    pickle_result_set(i, PICKLE_OK,    __VA_ARGS__)
#define error(i, ...) pickle_result_set(i, PICKLE_ERROR, __VA_ARGS__)

static const char *TAG = "pickle";

/* NB. This allocator can be use to get memory statistics (printed atexit) or test allocation failures */
static void *allocator(void *arena, void *ptr, const size_t oldsz, const size_t newsz) {
	UNUSED(arena);
	if (newsz == 0) { free(ptr); return NULL; }
	if (newsz > oldsz) return realloc(ptr, newsz);
	return ptr;
}

static int release(pickle_t *i, void *ptr) {
	void *arena = NULL;
	allocator_fn fn = NULL;
	const int r1 = pickle_allocator_get(i, &fn, &arena);
	if (fn)
		fn(arena, ptr, 0, 0);
	return fn ? r1 : PICKLE_ERROR;
}

static void *reallocator(pickle_t *i, void *ptr, size_t sz) {
	void *arena = NULL;
	allocator_fn fn = NULL;
	if (pickle_allocator_get(i, &fn, &arena) != PICKLE_OK)
		abort();
	void *r = fn(arena, ptr, 0, sz);
	if (!r) {
		release(i, ptr);
		return NULL;
	}
	return r;
}

static char *slurp(pickle_t *i, FILE *input, size_t *length, char *class) {
	char *m = NULL;
	const size_t bsz = class ? 80 : 4096;
	size_t sz = 0;
	if (length)
		*length = 0;
	for (;;) {
		if ((m = reallocator(i, m, sz + bsz + 1)) == NULL)
			return NULL;
		if (class) {
			size_t j = 0;
			int ch = 0, done = 0;
			for (; ((ch = fgetc(input)) != EOF) && j < bsz; ) {
				m[sz + j++] = ch;
				if (strchr(class, ch)) {
					done = 1;
					break;
				}
			}
			sz += j;
			if (done || ch == EOF)
				break;
		} else {
			size_t inc = fread(&m[sz], 1, bsz, input);
			sz += inc;
			if (inc != bsz)
				break;
		}
	}
	m[sz] = '\0'; /* ensure NUL termination */
	if (length)
		*length = sz;
	return m;
}

static int commandGets(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 1)
		return error(i, "Invalid command %s", argv[0]);
	size_t length = 0;
	char *line = slurp(i, (FILE*)pd, &length, "\n");
	if (!line)
		return error(i, "Out Of Memory");
	if (!length) {
		release(i, line);
		if (ok(i, "EOF") != PICKLE_OK)
			return PICKLE_ERROR;
		return PICKLE_BREAK;
	}
	const int r = ok(i, "%s", line);
	release(i, line);
	return r;
}

static int commandPuts(pickle_t *i, int argc, char **argv, void *pd) {
	FILE *out = pd;
	if (argc != 1 && argc != 2 && argc != 3)
		return error(i, "Invalid command %s -nonewline? string?", argv[0]);
	if (argc == 1)
		return fputc('\n', out) < 0 ? PICKLE_ERROR : PICKLE_OK;
	if (argc == 2)
		return fprintf(out, "%s\n", argv[1]) < 0 ? PICKLE_ERROR : PICKLE_OK;
	if (!strcmp(argv[1], "-nonewline"))
		return fputs(argv[2], out) < 0 ? PICKLE_ERROR : PICKLE_OK;
	return error(i, "Invalid option %s", argv[1]);
}

static int commandGetEnv(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2)
		return error(i, "Invalid command %s string", argv[0]);
	const char *env = getenv(argv[1]);
	return ok(i, env ? env : "");
}

static int commandExit(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2 && argc != 1)
		return error(i, "Invalid command %s number?", argv[0]);
	const char *code = argc == 2 ? argv[1] : "0";
	exit(atoi(code));
	return PICKLE_ERROR; /* unreachable */
}

static int commandClock(pickle_t *i, const int argc, char **argv, void *pd) {
	UNUSED(pd);
	time_t ts = 0;
	if (argc < 2)
		return error(i, "Invalid command %s subcommand...", argv[0]);
	if (!strcmp(argv[1], "clicks")) {
		const long t = (((double)(clock()) / (double)CLOCKS_PER_SEC) * 1000.0);
		return ok(i, "%ld", t);
	}
	if (!strcmp(argv[1], "seconds"))
		return ok(i, "%ld", (long)time(&ts));
	if (!strcmp(argv[1], "format")) {
		const int gmt = 1;
		char buf[512] = { 0 };
		char *fmt = argc == 4 ? argv[3] : "%a %b %d %H:%M:%S %Z %Y";
		int tv = 0;
		if (argc != 3 && argc != 4)
			return error(i, "Invalid subcommand");
		if (sscanf(argv[2], "%d", &tv) != 1)
			return error(i, "Invalid number: %s", argv[2]);
		ts = tv;
		struct tm *timeinfo = (gmt ? gmtime : localtime)(&ts);
		strftime(buf, sizeof buf, fmt, timeinfo);
		return ok(i, "%s", buf);
	}
	return error(i, "Invalid command %s subcommand...", argv[0]);
}

static int commandSource(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 1 && argc != 2)
		return error(i, "Invalid command %s string?", argv[0]);
	errno = 0;
	FILE *file = argc == 1 ? pd : fopen(argv[1], "rb");
	if (!file)
		return error(i, "Could not open file '%s' for reading: %s", argv[1], strerror(errno));

	char *program = slurp(i, file, NULL, NULL);
	if (file != pd)
		fclose(file);
	if (!program)
		return error(i, "Out Of Memory");

	const int r = pickle_eval(i, program);
	release(i, program);
	return r;
}

/*static int commandConsole(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2)
		return pickle_set_result_error_arity(i, 2, argc, argv);
	int ret = 0;
	esp_err_t err = esp_console_run(argv[1], &ret);
	if (err == ESP_ERR_NOT_FOUND) {
        	return ok(i, "Invalid command");
        } else if (err == ESP_ERR_INVALID_ARG) {
        	// command was empty
        } else if (err == ESP_OK && ret != ESP_OK) {
        	return ok(i, "Command returned non-zero error code: 0x%x (%s)\n", ret, esp_err_to_name(ret));
        } else if (err != ESP_OK) {
		return ok(i, "Invalid internal state: %s", esp_err_to_name(err));
        }
	return ok(i, "");
}*/

static int convert(pickle_t *i, const char *s, int *d) {
	assert(i);
	assert(d);
	if (sscanf(s, "%d", d) != 1)
		return error(i, "Invalid number %s", d);
	return PICKLE_OK;
}

/* ======================= WiFi ======================= */
#define JOIN_TIMEOUT_MS (10000)

static EventGroupHandle_t wifi_event_group;
const int CONNECTED_BIT = BIT0;

//#define DEFAULT_SCAN_LIST_SIZE CONFIG_EXAMPLE_SCAN_LIST_SIZE
#define DEFAULT_SCAN_LIST_SIZE (8u)

static const char *auth(const int mode) {
	switch (mode) {
	case  WIFI_AUTH_OPEN:             return  "OPEN";
	case  WIFI_AUTH_WEP:              return  "WEP";
	case  WIFI_AUTH_WPA_PSK:          return  "WPA_PSK";
	case  WIFI_AUTH_WPA2_PSK:         return  "WPA2_PSK";
	case  WIFI_AUTH_WPA_WPA2_PSK:     return  "WPA_WPA2_PSK";
	case  WIFI_AUTH_WPA2_ENTERPRISE:  return  "WPA2_ENTERPRISE";
	}
	return "unknown";
}

static const char *cipher(const int type) {
	switch (type) {
	case WIFI_CIPHER_TYPE_NONE: return "NONE";
	case WIFI_CIPHER_TYPE_WEP40: return "WEP40";
	case WIFI_CIPHER_TYPE_WEP104: return "WEP104";
	case WIFI_CIPHER_TYPE_TKIP: return "TKIP";
	case WIFI_CIPHER_TYPE_CCMP: return "CCMP";
	case WIFI_CIPHER_TYPE_TKIP_CCMP: return "TKIP_CCMP";
	}
	return "UNKNOWN";
}

static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		esp_wifi_connect();
		xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
	}
}

static void wifi_initialize(void) {
	esp_log_level_set("wifi", ESP_LOG_ERROR);
	static bool initialized = false;
	if (initialized)
		return;
	ESP_ERROR_CHECK(esp_netif_init());
	wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
	assert(ap_netif);
	esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
	assert(sta_netif);
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
	ESP_ERROR_CHECK( esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event_handler, NULL) );
	ESP_ERROR_CHECK( esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL) );
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
	ESP_ERROR_CHECK( esp_wifi_start() );
	initialized = true;
}

static int commandWiFiScan(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 1)
		return error(i, "Invalid command %s: expected no args", argv[0]);
#if 0
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
	assert(sta_netif);

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());
#else
	wifi_initialize();
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
#endif
	uint16_t number = DEFAULT_SCAN_LIST_SIZE;
	wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
	uint16_t ap_count = 0;
	memset(ap_info, 0, sizeof(ap_info));

#if 0
	wifi_scan_config_t scan_config = {
		.show_hidden = false,
		.scan_type = WIFI_SCAN_TYPE_PASSIVE,
		.scan_time = {
			.active = 200,
			.passive = 500,
		},
	};
	ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
#else
	ESP_ERROR_CHECK(esp_wifi_scan_start(NULL, true));
#endif
	ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
	ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
	ESP_LOGI(TAG, "Total APs scanned = %u", ap_count);
	for (int i = 0; (i < DEFAULT_SCAN_LIST_SIZE) && (i < ap_count); i++) {
		wifi_ap_record_t *rec = &ap_info[i];
		ESP_LOGI(TAG, "SSID \t\t%s", rec->ssid);
		ESP_LOGI(TAG, "RSSI \t\t%d", rec->rssi);
		ESP_LOGI(TAG, "AUTH \t\t%s", auth(rec->authmode));
		if (rec->authmode != WIFI_AUTH_WEP) {
			ESP_LOGI(TAG, "Cipher(pairwise) \t\t%s", cipher(rec->pairwise_cipher));
			ESP_LOGI(TAG, "Cipher(group)    \t\t%s", cipher(rec->group_cipher));
		}
		ESP_LOGI(TAG, "Channel \t\t%d\n", rec->primary);
	}
	return PICKLE_OK;
}

static int commandWiFiStatus(pickle_t *i, int argc, char **argv, void *pd) {
	/* TODO: Read connect/scanning/station/AP/disconnect, and other WiFi information */
	return PICKLE_OK;
}

static int commandWiFiDisconnect(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 1)
		return error(i, "Invalid command %s: expected no args", argv[0]);
	esp_wifi_disconnect();
	return PICKLE_OK;
}

static bool wifi_join(const char *ssid, const char *pass, int timeout_ms) {
	wifi_initialize();
	wifi_config_t wifi_config = { 0 };
	/* Note: we can also set the BSSID and Channel (if known) as part of
	 * the 'sta' structure. */
	strlcpy((char *) wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
	if (pass) {
		strlcpy((char *) wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));
	}

	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
	ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
	ESP_ERROR_CHECK( esp_wifi_connect() );

	const int bits = xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, pdFALSE, pdTRUE, timeout_ms / portTICK_PERIOD_MS);
	return (bits & CONNECTED_BIT) != 0;
}

static int commandWiFiJoin(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 2 && argc != 3 && argc != 4)
		return error(i, "Invalid command %s", argv[0]);

	int timeout_ms = 10000;
	if (argc == 4) {
		sscanf(argv[3], "%d", &timeout_ms);
		if (convert(i, argv[3], &timeout_ms) != PICKLE_OK)
			return PICKLE_ERROR;
	}

	char *ssid = argv[1];
	char *password = argc >= 3 ? argv[2] : "";
	printf("ssid(%s), password(%s), timeout(%d)" EOL, ssid, password, timeout_ms);
	const int connected = wifi_join(ssid, password, timeout_ms);
	if (!connected)
		return error(i, "WiFi timeout");
	return ok(i, "Connected");
}

static int commandWiFi(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc < 2)
		return error(i, "Invalid command %s: expect status|join|disconnect|scan", argv[0]);
	if (!strcmp(argv[1], "status"))
		return commandWiFiStatus(i, argc - 1, argv + 1, pd);
	if (!strcmp(argv[1], "join") || !strcmp(argv[1], "connect"))
		return commandWiFiJoin(i, argc - 1, argv + 1, pd);
	if (!strcmp(argv[1], "disconnect"))
		return commandWiFiDisconnect(i, argc - 1, argv + 1, pd);
	//if (!strcmp(argv[1], "wps"))
	//	return commandWiFiWPS(i, argc - 1, argv + 1, pd);
	if (!strcmp(argv[1], "scan"))
		return commandWiFiScan(i, argc - 1, argv + 1, pd);
	return error(i, "Invalid subcommand %s", argv[1]);
}

/* ======================= WiFi ======================= */

/* ======================= Logging ==================== */

static int logging_level(const char *l, esp_log_level_t *e) {
	assert(l);
	assert(e);

	struct logging_string {
		char *name;
		esp_log_level_t level;
	} s[] = {
		{ "none",    ESP_LOG_NONE, },
		{ "error",   ESP_LOG_ERROR, },
		{ "warn",    ESP_LOG_WARN, },
		{ "warning", ESP_LOG_WARN, },
		{ "debug",   ESP_LOG_DEBUG, },
		{ "info",    ESP_LOG_INFO, },
		{ "verbose", ESP_LOG_VERBOSE, },
	};
	*e = ESP_LOG_NONE;
	for (size_t j = 0; j < (sizeof (s) / sizeof s[0]); j++)
		if (!strcmp(l, s[j].name)) {
			*e = s[j].level;
			return 0;
		}
	return -1;
}

static int commandLogging(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 3)
		return error(i, "Invalid command %s: expected logging level", argv[0]);
	esp_log_level_t level = ESP_LOG_NONE;
	if (logging_level(argv[2], &level) < 0)
		return error(i, "Invalid logging level %s", argv[1]);
	esp_log_level_set(argv[1], ESP_LOG_ERROR);
	return PICKLE_OK;
}

/* ======================= Logging ==================== */

static int make_a_pickle(pickle_t **ret, FILE *in, FILE *out) {
	assert(ret);
	assert(in);
	assert(out);
	*ret = NULL;
	pickle_t *i = NULL;
	if (pickle_tests(allocator, NULL)   != PICKLE_OK) goto fail;
	if (pickle_new(&i, allocator, NULL) != PICKLE_OK) goto fail;
	//if (setArgv(i, argc, argv)  != PICKLE_OK) goto fail;

	typedef struct {
		const char *name; pickle_func_t func; void *data;
	} commands_t;

	const commands_t cmds[] = {
		{ "gets",    commandGets,      in     },
		{ "puts",    commandPuts,      out    },
		{ "getenv",  commandGetEnv,    NULL   },
		{ "exit",    commandExit,      NULL   },
		{ "source",  commandSource,    NULL   },
		{ "wifi",    commandWiFi,      NULL   },
		{ "logging", commandLogging,   NULL   },
		{ "clock",   commandClock,     NULL   },
		//{ "system", commandConsole, NULL   },
	};

	for (size_t j = 0; j < sizeof (cmds) / sizeof (cmds[0]); j++)
		if (pickle_command_register(i, cmds[j].name, cmds[j].func, cmds[j].data) != PICKLE_OK)
			goto fail;

	*ret = i;
	return 0;
fail:
	pickle_delete(i);
	*ret = NULL;
	return -1;
}

/* TODO: Handle dumb terminal like original console program */
static void initialize_console(void) {
	/* Drain stdout before reconfiguring it */
	fflush(stdout);
	fsync(fileno(stdout));

	/* Disable buffering on stdin */
	setvbuf(stdin, NULL, _IONBF, 0);

	/* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
	esp_vfs_dev_uart_set_rx_line_endings(ESP_LINE_ENDINGS_CR);
	/* Move the caret to the beginning of the next line on '\n' */
	esp_vfs_dev_uart_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);

	/* Configure UART. Note that REF_TICK is used so that the baud rate remains
	* correct while APB frequency is changing in light sleep mode.
	*/
	const uart_config_t uart_config = {
		.baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.source_clk = UART_SCLK_REF_TICK,
	};
	/* Install UART driver for interrupt-driven reads and writes */
	ESP_ERROR_CHECK( uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM, 256, 0, 0, NULL, 0) );
	ESP_ERROR_CHECK( uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config) );

	/* Tell VFS to use UART driver */
	esp_vfs_dev_uart_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);

	/* Initialize the console */
	esp_console_config_t console_config = {
		.max_cmdline_args = 8,
		.max_cmdline_length = 256,
#if CONFIG_LOG_COLORS
		.hint_color = atoi(LOG_COLOR_CYAN)
#endif
	};
	ESP_ERROR_CHECK( esp_console_init(&console_config) );

	linenoiseSetMultiLine(1);
	//linenoiseSetCompletionCallback(&esp_console_get_completion);
	//linenoiseSetHintsCallback((linenoiseHintsCallback*) &esp_console_get_hint);
	linenoiseHistorySetMaxLen(100);
	linenoiseAllowEmpty(true);

#if CONFIG_STORE_HISTORY
	/* Load command history from filesystem */
	//linenoiseHistoryLoad(HISTORY_PATH);
#endif

   /* esp_console_register_help_command();
    register_system();
    register_wifi();
    register_nvs();*/
}

static int pickle_shell(void) {
	initialize_console();
	pickle_t *i = NULL;
	char prompt[32] = "[S] pickle> ";
	const char *rstr = ""; /* do not free */

	FILE *in = stdin, *out = stdout;
	if (make_a_pickle(&i, in, out) < 0)
		goto fail;

	while (true) {
		if (rstr[0]) {
			if (fputs(rstr, out) < 0) goto fail;
			if (fputs(EOL, out) < 0) goto fail;
			if (fflush(out) < 0) goto fail;
		}
		char *line = linenoise(prompt); /* linenoise should really accept either a FILE* or a filedes... */
		if (line == NULL)
			break;
		if (fputs(EOL, out) < 0) goto fail;
		if (fflush(out) < 0) goto fail;
		if (line[0]) {
			linenoiseHistoryAdd(line);
			/* Save command history to filesystem */
			//linenoiseHistorySave(HISTORY_PATH);
		}
		const int r = pickle_eval(i, line);
		if (pickle_result_get(i, &rstr) != PICKLE_OK)
			goto fail;
		linenoiseFree(line);
		snprintf(prompt, sizeof prompt, "[%d] pickle> ", r);
	}
	esp_console_deinit();
	return pickle_delete(i) == PICKLE_OK ? 0 : -1;
fail:
	esp_console_deinit();
	pickle_delete(i);
	return -1;
}

static void initialize_nvs(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK( nvs_flash_erase() );
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

void app_main(void)
{
    initialize_nvs();
    printf("Pickle Shell: How do you like those pickles?\n");

    pickle_shell();

    printf("Restarting now.\n");
    fflush(stdout);
    esp_restart();

#if 0
    /* Print chip information */
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU cores, WiFi%s%s, ",
            CONFIG_IDF_TARGET,
            chip_info.cores,
            (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
            (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");

    printf("silicon revision %d, ", chip_info.revision);

    printf("%dMB %s flash\n", spi_flash_get_chip_size() / (1024 * 1024),
            (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    printf("Free heap: %d\n", esp_get_free_heap_size());

    for (int i = 10; i >= 0; i--) {
        printf("Restarting in %d seconds...\n", i);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    printf("Restarting now.\n");
    fflush(stdout);
    esp_restart();
#endif
}
