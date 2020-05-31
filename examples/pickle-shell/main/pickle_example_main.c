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
#include "esp_https_ota.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "linenoise/linenoise.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "pickle.h"
#include "sdkconfig.h"
#include <assert.h>
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define UNUSED(X) ((void)(X))
#define ok(i, ...)    pickle_result_set(i, PICKLE_OK,    __VA_ARGS__)
#define error(i, ...) pickle_result_set(i, PICKLE_ERROR, __VA_ARGS__)
#define DEFAULT_WIFI_TIME_OUT_MS (10 * 1000ul)

static const char *TAG = "pickle";

typedef struct { long allocs, frees, reallocs, total; } heap_t;

/* TODO: (Optionally) Use limited memory pool (<64KiB) so we do not consume all system resources */
static void *allocator(void *arena, void *ptr, const size_t oldsz, const size_t newsz) {
	assert(arena);
	heap_t *h = arena;
	if (newsz == 0) { 
		if (ptr) 
			h->frees++; 
		free(ptr); 
		return NULL; 
	}
	if (newsz > oldsz) { 
		h->reallocs += !!ptr; 
		h->allocs++; 
		h->total += newsz; 
		return realloc(ptr, newsz); 
	}
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

/* ======================= ESP32 Specific Functions ======================= */

//#define DEFAULT_SCAN_LIST_SIZE CONFIG_EXAMPLE_SCAN_LIST_SIZE
#define DEFAULT_SCAN_LIST_SIZE (8u)
#define CONNECTED_BIT (BIT0)

typedef struct {
	wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
	uint16_t ap_count;
	EventGroupHandle_t event;
	bool initialized;
} wifi_t;

static wifi_t wifi = {
	.initialized = false,
};

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

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	wifi_t *w = arg;
	assert(w);
	if (event_base == WIFI_EVENT) {
		switch (event_id) {
		case WIFI_EVENT_STA_DISCONNECTED:
			esp_wifi_connect();
			xEventGroupClearBits(w->event, CONNECTED_BIT);
			break;
		case WIFI_EVENT_WIFI_READY: 
		case WIFI_EVENT_SCAN_DONE:
		case WIFI_EVENT_STA_START:
		case WIFI_EVENT_STA_STOP: 
		case WIFI_EVENT_STA_CONNECTED: 
		case WIFI_EVENT_STA_AUTHMODE_CHANGE:  
		default:
			break;
		}
		return;
	} 
	if (event_base == IP_EVENT) {
		switch (event_id) {
		case IP_EVENT_STA_GOT_IP:
			xEventGroupSetBits(w->event, CONNECTED_BIT);
			break;
		case IP_EVENT_STA_LOST_IP: /* handle? */
		case IP_EVENT_AP_STAIPASSIGNED:
		case IP_EVENT_GOT_IP6: /* handle? */
		/* do not care */
		case IP_EVENT_ETH_GOT_IP:
		case IP_EVENT_PPP_GOT_IP:
		case IP_EVENT_PPP_LOST_IP:
		default:
			break;
		}
		return;
	}
}

static void wifi_initialize(wifi_t *w) {
	assert(w);
	if (w->initialized)
		return;
	esp_log_level_set("wifi", ESP_LOG_ERROR);
	ESP_ERROR_CHECK(esp_netif_init());
	w->event = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
	assert(ap_netif);
	esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
	assert(sta_netif);
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event_handler, &wifi));
	ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, &wifi));
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
	ESP_ERROR_CHECK(esp_wifi_start());
	w->initialized = true;
}

static const char *yes(int d) {
	return d ? "yes" : "no";
}

static int WiFiScanPrint(pickle_t *i, wifi_t *w) {
	assert(i);
	assert(w);
	w->ap_count = 0;
	ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&w->ap_count));
	printf("Max AP records %u\n", DEFAULT_SCAN_LIST_SIZE);
	printf("APs scanned    %u\n", w->ap_count);
	for (int i = 0; (i < DEFAULT_SCAN_LIST_SIZE) && (i < w->ap_count); i++) {
		wifi_ap_record_t *r = &w->ap_info[i];
		uint8_t *b = r->bssid;
		printf("SSID              %s\n", r->ssid);
		printf("BSSID             %02x:%02x:%02x:%02x:%02x:%02x\n", b[0], b[1], b[2], b[3], b[4], b[5]);
		printf("RSSI              %d\n", r->rssi);
		printf("AUTH              %s\n", auth(r->authmode));
		if (r->authmode != WIFI_AUTH_WEP) {
			printf("Cipher(pairwise)  %s\n", cipher(r->pairwise_cipher));
			printf("Cipher(group)     %s\n", cipher(r->group_cipher));
		}
		printf("Channel primary   %d\n", r->primary);
		printf("Channel secondary %d\n", (int)r->second);
		printf("Supported 11b     %s\n", yes(r->phy_11b));
		printf("Supported 11g     %s\n", yes(r->phy_11g));
		printf("Supported 11n     %s\n", yes(r->phy_11n));
		printf("Enabled low rate  %s\n", yes(r->phy_lr));
		printf("Supported WPS     %s\n", yes(r->wps));
		printf("\n");
	}
	return PICKLE_OK;
}

enum { ALL, SSID, RSSI, AUTH, BSSID, P11B, P11G, P11N, PLR, PWPS, ATERROR };

static int WiFiLookupAttr(const char *name) {
	assert(name);
	static const char *attrs[] = {
		[ALL]  = "all",  [SSID]  = "ssid",  [RSSI] = "rssi",
		[AUTH] = "auth", [BSSID] = "bssid", [P11B] = "11b",
		[P11G] = "11g",  [P11N]  = "11n",   [PLR]  = "lr",
		[PWPS] = "wps",
	};
	int i = ATERROR;
	for (int j = 0; (size_t)j < sizeof(attrs) / sizeof(attrs[0]); j++)
		if (!strcmp(name, attrs[j])) {
			i = j;
			break;
		}
	return i;
}

static int WiFiScanGet(pickle_t *i, wifi_t *w, int op, unsigned recno) {
	assert(i);
	assert(w);
	w->ap_count = 0;
	ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&w->ap_count));
	if (w->ap_count == 0 || recno >= w->ap_count || recno >= DEFAULT_SCAN_LIST_SIZE)
		return error(i, "recno > %u", MIN(w->ap_count, DEFAULT_SCAN_LIST_SIZE));
	wifi_ap_record_t *r = &w->ap_info[recno];
	uint8_t *b = r->bssid;
	/* TODO: Lock access to this record and prevent further scans until lock released */
	switch (op) {
	case ALL:
		return ok(i, "{ssid {%s}} {rssi %d} {auth %s} {bssid %02x:%02x:%02x:%02x:%02x:%02x} {11b %s} {11g %s} {11n %s} {lr %s} {wps %s}", 
				r->ssid, r->rssi, auth(r->authmode),
				b[0], b[1], b[2], b[3], b[4], b[5],
				yes(r->phy_11b), yes(r->phy_11g), yes(r->phy_11n), yes(r->phy_lr), yes(r->wps));
	case SSID:  return ok(i, "%s", r->ssid);
	case RSSI:  return ok(i, "%d", r->rssi);
	case AUTH:  return ok(i, "%s", auth(r->authmode));
	case BSSID: return ok(i, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
	case P11B:  return ok(i, "%s", yes(r->phy_11b));
	case P11G:  return ok(i, "%s", yes(r->phy_11g));
	case P11N:  return ok(i, "%s", yes(r->phy_11n));
	case PLR:   return ok(i, "%s", yes(r->phy_lr));
	case PWPS:  return ok(i, "%s", yes(r->wps));
	case ATERROR:
	default:
		return error(i, "Invalid attribute %d", op);
	}
	return error(i, "unreachable");
}

static int WiFiScan(pickle_t *i, wifi_t *w, wifi_scan_config_t *cfg) {
	assert(i);
	assert(w);
	assert(cfg);
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	uint16_t number = DEFAULT_SCAN_LIST_SIZE;
	memset(w->ap_info, 0, sizeof(w->ap_info));
	w->ap_count = 0;
	/* TODO: Make a non blocking version */
	ESP_ERROR_CHECK(esp_wifi_scan_start(cfg, true));
	ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, w->ap_info));
	return ok(i, "%d", (int)number);
}

static int commandWiFiScan(pickle_t *i, int argc, char **argv, void *pd) {
	assert(pd);
	wifi_t *w = pd;
	wifi_initialize(w);
	wifi_scan_config_t cfg = {
		.show_hidden = false,
		.scan_type = WIFI_SCAN_TYPE_PASSIVE,
		//.scan_time = { .active = 200, .passive = 500, },
	};

	if (argc == 1 || !strcmp("initiate", argv[1]))
		return WiFiScan(i, w, &cfg);

	if (!strcmp("print", argv[1]))
		return WiFiScanPrint(i, w);

	if (!strcmp("get", argv[1])) {
		if (argc != 3 && argc != 4)
			return error(i, "Invalid subcommand %s: expected {recno|attr recno}", argv[1]);
		int recno = 0;
		if (convert(i, argc == 3 ? argv[2] : argv[3], &recno) != PICKLE_OK)
			return PICKLE_ERROR;
		return WiFiScanGet(i, w, WiFiLookupAttr(argc == 3 ? "all" : argv[2]), recno);
	}

	return error(i, "Invalid subcommand %s -- expected {|initiate|print|get #}", argv[0]);
}

/* TODO: If we have non-blocking version of scan/join, then we need a way
 * to get the status of those operations */
static int commandWiFiStatus(pickle_t *i, int argc, char **argv, void *pd) {
	assert(pd);
	wifi_t *w = pd;
	if (argc != 1)
		return error(i, "Invalid command %s: expected no args", argv[0]);
	if (w->event == NULL)
		return ok(i, "-1");
	const EventBits_t b = xEventGroupGetBits(w->event);
	return ok(i, "%d", (int)!!(b & CONNECTED_BIT));
}

static int commandWiFiDisconnect(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 1)
		return error(i, "Invalid command %s: expected no args", argv[0]);
	esp_wifi_disconnect();
	return PICKLE_OK;
}

static bool WiFiJoin(wifi_t *w, const char *ssid, const char *pass, int timeout_ms, int bssid_known, uint8_t bssid[6]) {
	assert(w);
	wifi_initialize(w);
	wifi_config_t wifi_config = { 0 };
	strlcpy((char *) wifi_config.sta.ssid,     ssid, sizeof(wifi_config.sta.ssid));
	strlcpy((char *) wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));
	wifi_config.sta.bssid_set = !!bssid_known;
	memcpy(wifi_config.sta.bssid, bssid, 6);

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_connect());

	/* TODO: No timeout here, we can query/wait elsewhere, perhaps using vwait? Note that
	 * if a scan is ongoing or another join is happening we should return
	 * an error or wait, depending on mode. We could also have a 'wait
	 * forever' option. */
	const int bits = xEventGroupWaitBits(w->event, CONNECTED_BIT, pdFALSE, pdTRUE, timeout_ms / portTICK_PERIOD_MS);
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
	const int connected = WiFiJoin(pd, ssid, password, timeout_ms, 0, bssid);
	if (!connected)
		return error(i, "WiFi timeout");
	return ok(i, "Connected");
}

static int commandWiFi(pickle_t *i, int argc, char **argv, void *pd) {
	assert(pd);
	wifi_t *w = pd;
	if (argc < 2)
		return error(i, "Invalid command %s: expect status|join|disconnect|scan", argv[0]);
	if (!strcmp(argv[1], "status"))
		return commandWiFiStatus(i, argc - 1, argv + 1, w);
	if (!strcmp(argv[1], "join") || !strcmp(argv[1], "connect"))
		return commandWiFiJoin(i, argc - 1, argv + 1, w);
	if (!strcmp(argv[1], "disconnect"))
		return commandWiFiDisconnect(i, argc - 1, argv + 1, pd);
	//if (!strcmp(argv[1], "wps"))
	//	return commandWiFiWPS(i, argc - 1, argv + 1, w);
	if (!strcmp(argv[1], "scan"))
		return commandWiFiScan(i, argc - 1, argv + 1, w);
	return error(i, "Invalid subcommand %s", argv[1]);
}

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
	if (!strcmp("heap-current", argv[1]))
		return ok(i, "%lu", (unsigned long)esp_get_free_heap_size());
	if (!strcmp("heap-max", argv[1]))
		return ok(i, "%lu", (unsigned long)esp_get_minimum_free_heap_size());
	if (!strcmp("stack-high", argv[1]))
		return ok(i, "%lu", (unsigned long)uxTaskGetStackHighWaterMark(NULL));
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
	if (!strcmp("line", argv[1])) {
		char *line = linenoise(argc < 3 ? "> " : argv[2]);
		if (!line)
			return pickle_result_set(i, PICKLE_BREAK, "EOF");
		const int r = ok(i, "%s", line);
		linenoiseFree(line);
		return r;
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

static int commandRandom(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 1)
		return error(i, "Invalid command %s", argv[0]);
	/* NOTE: we could return an error if the WiFi module is not enabled, or
	 * we could just enable it, the entropy source comes from the radio
	 * (WiFI or Bluetooth) front ends */
	return ok(i, "%ld", (long)esp_random());
}

static int commandOta(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 2 && argc != 4)
		return error(i, "Invalid command %s -- expected {URL|URL username password}", argv[0]);
	esp_http_client_config_t config = {
		.url = argv[1],
		.cert_pem = NULL, /*TODO: set this '(char *)server_cert_pem_start, */
		.username = argc == 4 ? argv[2] : NULL,
		.password = argc == 4 ? argv[3] : NULL,
	};
	esp_err_t ret = esp_https_ota(&config);
	return ok(i, "%d", ret == ESP_OK ? 0 : -1);
}

static int commandErrno(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 1 && argc != 2)
		return error(i, "Invalid command %s -- expected number?", argv[0]);
	if (argc == 1)
		return ok(i, "%d", errno);
	int e = 0;
	if (convert(i, argv[1], &e) != PICKLE_OK)
		return PICKLE_ERROR;
	return ok(i, "%s", strerror(e));
}

/* Half-inched from <https://git.musl-libc.org/cgit/musl/tree/src/stdio/__fmodeflags.c> */
static int fmodeflags(const char *mode) {
	assert(mode);
	int flags = O_WRONLY;
	if (strchr(mode, '+')) flags = O_RDWR;
	else if (*mode == 'r') flags = O_RDONLY;
	else flags = O_WRONLY;
	if (strchr(mode, 'x')) flags |= O_EXCL;
	/*if (strchr(mode, 'e')) flags |= O_CLOEXEC; // not implemented */
	if (*mode != 'r') flags |= O_CREAT;
	if (*mode == 'w') flags |= O_TRUNC;
	if (*mode == 'a') flags |= O_APPEND;
	return flags;
}

/* View: <https://sourceware.org/newlib/> for more information on these system calls */
static int commandOpen(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 3 && argc != 4)
		return error(i, "Invalid command %s -- expected path flags mode?", argv[0]);
	int mode = S_IRWXU | S_IRWXG | S_IRWXO;
	if (argc == 4) {
		/* TODO: Handle user permissions */
	}
	if (!strchr("rwa", argv[2][0]))
		return error(i, "Invalid flags %s", argv[2]);
	const int flags = fmodeflags(argv[2]);

	errno = 0;
	int fd = open(argv[1], flags, mode);
	if (fd < 0)
		return error(i, "Could not open file '%s' in mode %s: %s", argv[1], argv[2], strerror(errno));
	return ok(i, "%d", fd);
}

static int commandClose(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2)
		return error(i, "Invalid command %s -- expected fd", argv[0]);
	int fd = -1;
	if (convert(i, argv[1], &fd) != PICKLE_OK)
		return PICKLE_ERROR;
	errno = 0;
	if (close(fd) < 0)
		return error(i, "Close failed %d: %s", fd, strerror(errno));
	return PICKLE_OK;
}

/* NOTE: We could deal with binary data by reading and writing base64 encoded
 * data, or by reading and writing single bytes at a time and converting the
 * result to and from an integer value, either way it will be inefficient */

static int commandRead(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 3)
		return error(i, "Invalid command %s -- expected fd bytes", argv[0]);
	int fd = -1, bytes = 0;
	if (convert(i, argv[1], &fd) != PICKLE_OK)
		return PICKLE_ERROR;
	if (convert(i, argv[2], &bytes) != PICKLE_OK)
		return PICKLE_ERROR;
	if (bytes < 0 || bytes > 256)
		return error(i, "byte count invalid %d", bytes);
	errno = 0;
	char s[256+1] = { 0 };
	const int rode = read(fd, s, bytes);
	if (rode < 0)
		return error(i, "read failed %d: %s got %s", fd, strerror(errno), s);
	s[rode] = '\0';
	if (memchr(s, 0, rode))
		return error(i, "contains binary data");
	return ok(i, "%d {%s}", rode, s);
}

static int commandWrite(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 3)
		return error(i, "Invalid command %s -- expected fd string", argv[0]);
	int fd = -1;
	if (convert(i, argv[1], &fd) != PICKLE_OK)
		return PICKLE_ERROR;
	errno = 0;
	const int slen = strlen(argv[2]);
	const int wrote = write(fd, argv[2], slen);
	if (wrote < 0 || wrote != slen)
		return error(i, "only wrote %d bytes: %s", wrote, strerror(errno));
	return ok(i, "%d", wrote);
}

static int commandSeek(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 4)
		return error(i, "Invalid command %s -- expected fd position {set|current|end}", argv[0]);
	int fd = -1, pos = 0;
	if (convert(i, argv[1], &fd) != PICKLE_OK)
		return PICKLE_ERROR;
	if (convert(i, argv[2], &pos) != PICKLE_OK)
		return PICKLE_ERROR;
	if (pos < 0)
		return error(i, "position invalid %d", pos);
	int mode = 0;
	if (!strcmp("set", argv[3]))
		mode = SEEK_SET;
	else if (!strcmp("current", argv[3]))
		mode = SEEK_CUR;
	else if (!strcmp("end", argv[3]))
		mode = SEEK_END;
	else
		return error(i, "Invalid whence %s", argv[3]);
	errno = 0;
	const int r = lseek(fd, pos, mode);
	if (r < 0)
		return error(i, "lseek failed: %s", strerror(errno));
	return ok(i, "%d", r);
}

static int statReturn(pickle_t *i, struct stat *st) {
	assert(i);
	assert(st);
	const char *mode = "unknown";
	switch (st->st_mode & S_IFMT) {
	case S_IFBLK:  mode = "block-device";     break;
	case S_IFCHR:  mode = "character-device"; break;
	case S_IFDIR:  mode = "directory";        break;
	case S_IFIFO:  mode = "FIFO/pipe";        break;
	case S_IFLNK:  mode = "symlink";          break;
	case S_IFREG:  mode = "regular-file";     break;
	case S_IFSOCK: mode = "socket";           break;
	}

	return ok(i, "inode=%ld mode=%s omode=%lo nlink=%ld uid=%ld gid=%ld rdev=%ld size=%ld blksize=%ld blocks=%ld atime=%ld mtime=%ld ctime=%ld", 
		(long)st->st_ino,
		mode,
		(long)st->st_mode,
		(long)st->st_nlink,
		(long)st->st_uid,
		(long)st->st_gid,
		(long)st->st_rdev,
		(long)st->st_size,
		(long)st->st_blksize,
		(long)st->st_blocks,
		(long)st->st_atime,
		(long)st->st_mtime,
		(long)st->st_ctime);
}

static int commandStat(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2)
		return error(i, "Invalid command %s -- expected file", argv[0]);
	struct stat st;
	memset(&st, 0, sizeof st);
	errno = 0;
	if (stat(argv[1], &st) < 0)
		return error(i, "stat on file '%s' failed: %s", argv[1], strerror(errno));
	return statReturn(i, &st);
}

static int commandFStat(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2)
		return error(i, "Invalid command %s -- expected file", argv[0]);
	int fd = -1;
	if (convert(i, argv[1], &fd) != PICKLE_OK)
		return PICKLE_ERROR;
	struct stat st;
	memset(&st, 0, sizeof st);
	errno = 0;
	if (fstat(fd, &st) < 0)
		return error(i, "stat on filedes '%d' failed: %s", fd, strerror(errno));
	return statReturn(i, &st);
}

static int commandRename(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 3)
		return error(i, "Invalid command %s -- expected src dst", argv[0]);
	errno = 0;
	const int st = rename(argv[1], argv[2]);
	if (st < 0)
		return error(i, "renaming file '%s' to '%s' failed: %s", argv[1], argv[2], strerror(errno));
	return PICKLE_OK;
}

static int commandUnlink(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2)
		return error(i, "Invalid command %s -- expected path", argv[0]);
	struct stat st;
	memset(&st, 0, sizeof st);
	errno = 0;
	if (stat(argv[1], &st) < 0)
		return error(i, "stat on file '%s' failed: %s", argv[1], strerror(errno));
	errno = 0;
	if (unlink(argv[1]) < 0) /* BUG: There seems to be a bug in unlink on a path that does not exist */
		return error(i, "unlink of path '%s' failed: %s", strerror(errno));
	return PICKLE_OK;
}

static int commandLink(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 3)
		return error(i, "Invalid command %s -- expected path path", argv[0]);
	errno = 0;
	if (link(argv[1], argv[2]) < 0)
		return error(i, "link '%s' '%s' failed: %s", strerror(errno));
	return PICKLE_OK;
}

/* BUG: Does not work - causes system to crash */
static inline int commandUtime(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 4)
		return error(i, "Invalid command %s -- expected path time(s) time(s)", argv[0]);
	int actime = 0, modtime = 0;
	if (convert(i, argv[2], &actime) != PICKLE_OK)
		return PICKLE_ERROR;
	if (convert(i, argv[3], &modtime) != PICKLE_OK)
		return PICKLE_ERROR;
	struct utimbuf u = { .actime = actime, .modtime = modtime };
	errno = 0;
	if (utime(argv[1], &u) < 0)
		return error(i, "Setting time to acc=%d mod=%d on file '%s' failed: %s", actime, modtime, strerror(errno));
	return PICKLE_OK;
}

static int commandDf(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 1 && argc != 2)
		return error(i, "Invalid command %s -- partition-number?", argv[0]);
	int partitions = 0, r = PICKLE_OK, which = -1;
	if (argc == 2)
		if (convert(i, argv[1], &which) != PICKLE_OK)
			return PICKLE_ERROR;
	esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, NULL);
	for (; it != NULL; it = esp_partition_next(it)) {
		if (partitions++ == which) {
			const esp_partition_t *p = esp_partition_get(it);
			r = ok(i, "%s %d %d %d %d %d", p->label, (int)p->type, (int)p->subtype, (int)p->address, (int)p->size, (int)p->encrypted);
			break;
		}
	}
	esp_partition_iterator_release(it);
	return argc == 1 ? ok(i, "%d", partitions) : r;
}

/* ======================= ESP32 Specific Functions ======================= */

/* ======================= Pickle Shell Setup       ======================= */

static int make_a_pickle(pickle_t **ret, heap_t *h, FILE *in, FILE *out) {
	assert(ret);
	assert(h);
	assert(in);
	assert(out);
	*ret = NULL;
	pickle_t *i = NULL;
	if (pickle_tests(allocator, h)   != PICKLE_OK) goto fail;
	if (pickle_new(&i, allocator, h) != PICKLE_OK) goto fail;
	if (pickle_var_set_args(i, "argv", 1, (char*[]){"pickle"})  != PICKLE_OK) goto fail;

	typedef struct {
		const char *name;
		pickle_func_t func;
		void *data;
	} commands_t;

	const commands_t cmds[] = {
		/* generic components                   */
		{ "gets",      commandGets,       in,    },
		{ "puts",      commandPuts,       out,   },
		{ "getenv",    commandGetEnv,     NULL,  },
		{ "exit",      commandExit,       NULL,  },
		{ "source",    commandSource,     NULL,  },
		{ "clock",     commandClock,      NULL,  },
		{ "heap",      commandHeap,       h,     },
		/* esp32s2 specific components           */
		{ "wifi",      commandWiFi,       &wifi, },
		{ "logging",   commandLogging,    NULL,  },
		{ "sysinf",    commandSystemInfo, NULL,  },
		{ "linenoise", commandLinenoise,  NULL,  },
		{ "random",    commandRandom,     NULL,  },
		{ "ota",       commandOta,        NULL,  },
		{ "errno",     commandErrno,      NULL,  },

		{ "open",      commandOpen,       NULL,  },
		{ "close",     commandClose,      NULL,  },
		{ "read",      commandRead,       NULL,  },
		{ "write",     commandWrite,      NULL,  },
		{ "seek",      commandSeek,       NULL,  },
		{ "stat",      commandStat,       NULL,  },
		{ "fstat",     commandFStat,      NULL,  },
		{ "frename",   commandRename,     NULL,  },
		{ "unlink",    commandUnlink,     NULL,  },
		{ "link",      commandLink,       NULL,  },
		//{ "utime",     commandUtime,      NULL,  },

		{ "df",        commandDf,         NULL,  },
	};

	for (size_t j = 0; j < sizeof (cmds) / sizeof (cmds[0]); j++)
		if (pickle_command_register(i, cmds[j].name, cmds[j].func, cmds[j].data) != PICKLE_OK)
			goto fail;
	*ret = i;
	return 0;
fail:
	(void)pickle_delete(i);
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
			if (fputs("\n", out) < 0) goto fail;
			if (fflush(out) < 0) goto fail;
		}
		char *line = linenoise(prompt);
		if (line == NULL)
			break;
		if (fputs("\n", out) < 0) goto fail;
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

static void nvs_initialize(void) {
	esp_err_t err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		err = nvs_flash_init();
	}
	ESP_ERROR_CHECK(err);
}

/* TODO: If we provide the right commands to the interpreter, we could remove this */
static wl_handle_t fs_initialize(const char *base_path) {
	assert(base_path);
	ESP_LOGI(TAG, "FAT FS Mount");
	wl_handle_t handle = WL_INVALID_HANDLE;
	const esp_vfs_fat_mount_config_t mount_config = {
		.max_files              = 8,
		.format_if_mount_failed = true,
		.allocation_unit_size   = CONFIG_WL_SECTOR_SIZE
	};
	/* "storage" comes from the name in 'partitions_pickle.csv' */
	esp_err_t err = esp_vfs_fat_spiflash_mount(base_path, "storage", &mount_config, &handle);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
		return WL_INVALID_HANDLE;
	}
	return handle;
}

static void fs_deinitialize(const char *base_path, wl_handle_t handle) {
	ESP_LOGI(TAG, "FAT FS Unmount");
	if (handle == WL_INVALID_HANDLE)
		return;
	ESP_ERROR_CHECK(esp_vfs_fat_spiflash_unmount(base_path, handle));
}

static const char *base_path = "/spiflash";

static void file_example(void) {
	ESP_LOGI(TAG, "Opening file");
	FILE *f = fopen("/spiflash/hello.txt", "wb");
	if (f == NULL) {
		ESP_LOGE(TAG, "Failed to open file for writing");
		return;
	}
	fprintf(f, "written using ESP-IDF %s\n", esp_get_idf_version());
	fclose(f);
	ESP_LOGI(TAG, "File written");

	ESP_LOGI(TAG, "Reading file");
	f = fopen("/spiflash/hello.txt", "rb");
	if (f == NULL) {
		ESP_LOGE(TAG, "Failed to open file for reading");
		return;
	}
	char line[128];
	fgets(line, sizeof(line), f);
	fclose(f);
	char *pos = strchr(line, '\n');
	if (pos) {
		*pos = '\0';
	}
	ESP_LOGI(TAG, "Read from file: '%s'", line);
}

void app_main(void) {
	nvs_initialize();
	wl_handle_t h = fs_initialize(base_path);
	if (0)
		file_example();
	ESP_LOGI(TAG, "Pickle Shell: How do you like these pickles?");
	pickle_shell();
	ESP_LOGI(TAG, "Restarting now.");
	fflush(stdout);
	fs_deinitialize(base_path, h);
	esp_restart();
}

