/* Pickle Shell: A TCL like language */
#include "driver/uart.h"
#include "esp_console.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_spi_flash.h"
#include "esp_system.h"
#include "esp_vfs_dev.h"
#include "esp_vfs_fat.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "linenoise/linenoise.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "pickle.h"
#include "sdkconfig.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define UNUSED(X) ((void)(X))
#define EOL "\r\n"
#define ok(i, ...)    pickle_result_set(i, PICKLE_OK,    __VA_ARGS__)
#define error(i, ...) pickle_result_set(i, PICKLE_ERROR, __VA_ARGS__)
#define DEFAULT_WIFI_TIME_OUT_MS (10 * 1000ul)

static const char *TAG = "pickle";

typedef struct { long allocs, frees, reallocs, total; } heap_t;

/* TODO: Use limited memory pool (<64KiB) so we do not consume all system resources */
static void *allocator(void *arena, void *ptr, const size_t oldsz, const size_t newsz) {
	assert(arena);
	heap_t *h = arena;
	if (newsz == 0) { if (ptr) h->frees++; free(ptr); return NULL; }
	if (newsz > oldsz) { h->reallocs += !!ptr; h->allocs++; h->total += newsz; return realloc(ptr, newsz); }
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

static int commandHeap(pickle_t *i, int argc, char **argv, void *pd) {
	heap_t *h = pd;
	if (argc != 2)
		return error(i, "Invalid command %s", argv[0]);
	if (!strcmp(argv[1], "frees"))         return ok(i, "%ld", h->frees);
	if (!strcmp(argv[1], "allocations"))   return ok(i, "%ld", h->allocs);
	if (!strcmp(argv[1], "total"))         return ok(i, "%ld", h->total);
	if (!strcmp(argv[1], "reallocations")) return ok(i, "%ld", h->reallocs);
	return error(i, "Invalid command %s", argv[0]);
}

static int convert(pickle_t *i, const char *s, int *d) {
	assert(i);
	assert(d);
	if (sscanf(s, "%d", d) != 1)
		return error(i, "Invalid number %s", d);
	return PICKLE_OK;
}

/* ======================= WiFi ======================= */

/* TODO: Move to a structure */
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
	case WIFI_CIPHER_TYPE_NONE:      return "NONE";
	case WIFI_CIPHER_TYPE_WEP40:     return "WEP40";
	case WIFI_CIPHER_TYPE_WEP104:    return "WEP104";
	case WIFI_CIPHER_TYPE_TKIP:      return "TKIP";
	case WIFI_CIPHER_TYPE_CCMP:      return "CCMP";
	case WIFI_CIPHER_TYPE_TKIP_CCMP: return "TKIP_CCMP";
	}
	return "UNKNOWN";
}

/* TODO: Handle more events */
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
	wifi_initialize();
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	uint16_t number = DEFAULT_SCAN_LIST_SIZE;
	wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
	uint16_t ap_count = 0;
	memset(ap_info, 0, sizeof(ap_info));

	/* TODO: allow scan configuration to be set */
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
	/* TODO: Return scan results */
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

static bool wifi_join(const char *ssid, const char *pass, int timeout_ms, int bssid_known, uint8_t bssid[6]) {
	wifi_initialize();
	wifi_config_t wifi_config = { 0 };
	strlcpy((char *) wifi_config.sta.ssid,     ssid, sizeof(wifi_config.sta.ssid));
	strlcpy((char *) wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));
	wifi_config.sta.bssid_set = !!bssid_known;
	memcpy(wifi_config.sta.bssid, bssid, 6);

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_connect());

	const int bits = xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, pdFALSE, pdTRUE, timeout_ms / portTICK_PERIOD_MS);
	return (bits & CONNECTED_BIT) != 0;
}

static int commandWiFiJoin(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 2 && argc != 3 && argc != 4 && argc != 5)
		return error(i, "Invalid command %s: expected ssid password? timeout? bssid?", argv[0]);
	int timeout_ms = DEFAULT_WIFI_TIME_OUT_MS;
	if (argc == 4)
		if (convert(i, argv[3], &timeout_ms) != PICKLE_OK)
			return PICKLE_ERROR;
	char *ssid = argv[1];
	char *password = argc >= 3 ? argv[2] : "";
	uint8_t bssid[6] = { 0 };
	const int connected = wifi_join(ssid, password, timeout_ms, 0, bssid);
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
	esp_log_level_set(argv[1], level);
	return PICKLE_OK;
}

static int commandSystemInfo(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc < 2)
		return error(i, "Invalid command %s", argv[0]);
	if (!strcmp("reset", argv[1]))
		return ok(i, "%d", (int) esp_reset_reason());
	esp_chip_info_t chip_info;
	esp_chip_info(&chip_info);
	if (!strcmp("flash", argv[1]))
		return ok(i, "%lu", (unsigned long)(spi_flash_get_chip_size()));
	if (!strcmp("flash-internal", argv[1]))
		return ok(i, "%c", chip_info.features & CHIP_FEATURE_EMB_FLASH ? '1' : '0');
	if (!strcmp("target", argv[1]))
		return ok(i, "%s", CONFIG_IDF_TARGET);
	if (!strcmp("cores", argv[1]))
		return ok(i, "%d", chip_info.cores);
	if (!strcmp("bt", argv[1]))
		return ok(i, "%c", chip_info.features & CHIP_FEATURE_BT ? '1' : '0');
	if (!strcmp("ble", argv[1]))
		return ok(i, "%c", chip_info.features & CHIP_FEATURE_BLE ? '1' : '0');
	if (!strcmp("silicon", argv[1]))
		return ok(i, "%d", chip_info.revision);
	return error(i, "Invalid subcommand %s", argv[1]);
}

static int commandLinenoise(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc < 2)
		return error(i, "Invalid command %s", argv[0]);
	if (!strcmp("clear", argv[1])) {
		linenoiseClearScreen();
		return PICKLE_OK;
	}
	if (argc < 3)
		return error(i, "Invalid command %s", argv[0]);
	if (!strcmp("multiline", argv[1])) {
		int on = 0;	
		if (convert(i, argv[2], &on) < 0)
			return PICKLE_ERROR;
		linenoiseSetMultiLine(!!on);
		return PICKLE_OK;
	}
	if (!strcmp("history-length", argv[1])) {
		int len = 0;	
		if (convert(i, argv[2], &len) < 0)
			return PICKLE_ERROR;
		if (len > 256 || len < 0)
			error(i, "History length too large %d", len);
		linenoiseHistorySetMaxLen(len);
		return PICKLE_OK;
	}
	if (!strcmp("empty", argv[1])) {
		int on = 0;	
		if (convert(i, argv[2], &on) < 0)
			return PICKLE_ERROR;
		linenoiseAllowEmpty(!!on);
		return PICKLE_OK;
	}
	if (!strcmp("dumb", argv[1])) {
		int on = 0;	
		if (convert(i, argv[2], &on) < 0)
			return PICKLE_ERROR;
		linenoiseSetDumbMode(!!on);
		return PICKLE_OK;
	}
	/*if (!strcmp("mask", argv[1])) { // Not implemented in this version of linenoise
		int on = 0;	
		if (convert(i, argv[2], &on) < 0)
			return PICKLE_ERROR;
		on ? linenoiseMaskModeEnable() : linenoiseMaskModeDisable();
		return PICKLE_OK;
	}*/
	if (!strcmp("history-save", argv[1])) {
		if (linenoiseHistorySave(argv[2]) < 0)
			return error(i, "failed to save history to file %s", argv[2]);
		return PICKLE_OK;
	}
	if (!strcmp("history-load", argv[1])) {
		if (linenoiseHistoryLoad(argv[2]) < 0)
			return error(i, "failed to load history to file %s", argv[2]);
		return PICKLE_OK;
	}
	return error(i, "Invalid subcommand %s", argv[1]);
}

/* ======================= Logging ==================== */

static int make_a_pickle(pickle_t **ret, heap_t *h, FILE *in, FILE *out) {
	assert(ret);
	assert(h);
	assert(in);
	assert(out);
	*ret = NULL;
	pickle_t *i = NULL;
	if (pickle_tests(allocator, h)   != PICKLE_OK) goto fail;
	if (pickle_new(&i, allocator, h) != PICKLE_OK) goto fail;
	//if (pickle_set_var_args(i, "argv", argc, argv)  != PICKLE_OK) goto fail;

	typedef struct {
		const char *name; pickle_func_t func; void *data;
	} commands_t;

	const commands_t cmds[] = {
		/* generic components                   */
		{ "gets",      commandGets,       in     },
		{ "puts",      commandPuts,       out    },
		{ "getenv",    commandGetEnv,     NULL   },
		{ "exit",      commandExit,       NULL   },
		{ "source",    commandSource,     NULL   },
		{ "clock",     commandClock,      NULL   },
		{ "heap",      commandHeap,       h      },
		/* esp32s2 specific components           */
		{ "wifi",      commandWiFi,       NULL   },
		{ "logging",   commandLogging,    NULL   },
		{ "sysinf",    commandSystemInfo, NULL   },
		{ "linenoise", commandLinenoise,  NULL   },
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

static void initialize_console(void) {
	fflush(stdout);
	fsync(fileno(stdout));
	setvbuf(stdin, NULL, _IONBF, 0);
	esp_vfs_dev_uart_set_rx_line_endings(ESP_LINE_ENDINGS_CR);
	esp_vfs_dev_uart_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);

	/* Configure UART. Note that REF_TICK is used so that the baud rate remains
	* correct while APB frequency is changing in light sleep mode. */
	const uart_config_t uart_config = {
		.baud_rate  = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
		.data_bits  = UART_DATA_8_BITS,
		.parity     = UART_PARITY_DISABLE,
		.stop_bits  = UART_STOP_BITS_1,
		.source_clk = UART_SCLK_REF_TICK,
	};
	/* Install UART driver for interrupt-driven reads and writes */
	ESP_ERROR_CHECK(uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM, 256, 0, 0, NULL, 0));
	ESP_ERROR_CHECK(uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config));
	esp_vfs_dev_uart_use_driver(CONFIG_ESP_CONSOLE_UART_NUM); /* Tell VFS to use UART driver */

	linenoiseSetMultiLine(1);
	/* Could use 'info commands' for this */
	//linenoiseSetCompletionCallback(&esp_console_get_completion);
	linenoiseHistorySetMaxLen(100);
	linenoiseAllowEmpty(true);

	/*if (linenoiseProbe()) { // zero indicates success
		printf("\nDumb Terminal Mode!\n");
		linenoiseSetDumbMode(1);
	}*/
}

/* TODO: Store an equivalent file on flash and load it up using source */
static int pickle_shell(void) {
	initialize_console();
	pickle_t *i = NULL;
	heap_t h = { 0, };
	char prompt[32] = "[S] pickle> ";
	const char *rstr = ""; /* do not free */
	FILE *in = stdin, *out = stdout;
	if (make_a_pickle(&i, &h, in, out) < 0)
		goto fail;

	for (;;) {
		if (rstr[0]) {
			if (fputs(rstr, out) < 0) goto fail;
			if (fputs(EOL, out) < 0) goto fail;
			if (fflush(out) < 0) goto fail;
		}
		char *line = linenoise(prompt);
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
	return pickle_delete(i) == PICKLE_OK ? 0 : -1;
fail:
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
	printf("Pickle Shell: How do you like these pickles?\n");
	pickle_shell();
	printf("Restarting now.\n");
	fflush(stdout);
	esp_restart();
}
