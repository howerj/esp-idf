/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <string.h>
#include "assert.h"
#include "driver/uart.h"
#include "errno.h"
#include "esp_console.h"
#include "esp_log.h"
#include "esp_spi_flash.h"
#include "esp_system.h"
#include "esp_vfs_dev.h"
#include "esp_vfs_fat.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "linenoise/linenoise.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "pickle.h"
#include "sdkconfig.h"

#define UNUSED(X) ((void)(X))
#define EOL "\r\n"

static void *allocator(void *arena, void *ptr, const size_t oldsz, const size_t newsz) {
	UNUSED(arena);
	if (newsz == 0) { free(ptr); return NULL; }
	if (newsz > oldsz) return realloc(ptr, newsz);
	return ptr;
}

static char *slurp(pickle_t *i, FILE *input, size_t *length, char *class) {
	char *m = NULL;
	const size_t bsz = class ? 4096 : 80;
	size_t sz = 0;
	if (length)
		*length = 0;
	for (;;) {
		if (pickle_reallocate(i, (void**)&m, sz + bsz + 1) != PICKLE_OK)
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
		return pickle_set_result_error_arity(i, 1, argc, argv);
	size_t length = 0;
	char *line = slurp(i, (FILE*)pd, &length, "\n");
	if (!line)
		return pickle_set_result_error(i, "Out Of Memory");
	if (!length) {
		if (pickle_free(i, (void**)&line) != PICKLE_OK)
			return PICKLE_ERROR;
		if (pickle_set_result(i, "EOF") != PICKLE_OK)
			return PICKLE_ERROR;
		return PICKLE_BREAK;
	}
	const int r = pickle_set_result(i, line);
	if (pickle_free(i, (void**)&line) != PICKLE_OK)
		return PICKLE_ERROR;
	return r;
}

static int commandPuts(pickle_t *i, int argc, char **argv, void *pd) {
	int r = PICKLE_OK;
	FILE *out = pd;
	if (argc != 1 && argc != 2 && argc != 3)
		return pickle_set_result_error_arity(i, 2, argc, argv);
	if (argc == 1) {
		r = fputs(EOL, out) < 0 ? PICKLE_ERROR : PICKLE_OK;
		goto flush;
	}
	if (argc == 2) {
		r = fprintf(out, "%s" EOL, argv[1]) < 0 ? PICKLE_ERROR : PICKLE_OK;
		goto flush;
	}
	if (!strcmp(argv[1], "-nonewline")) {
		r = fputs(argv[2], out) < 0 ? PICKLE_ERROR : PICKLE_OK;
		goto flush;
	}
	return pickle_set_result_error(i, "Invalid option %s", argv[1]);
flush:
	if (fflush(out) < 0)
		return PICKLE_ERROR;
	return r;
}

static int commandExit(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2 && argc != 1)
		return pickle_set_result_error_arity(i, 2, argc, argv);
	const char *code = argc == 2 ? argv[1] : "0";
	exit(atoi(code));
	return PICKLE_OK;
}

static int commandGetEnv(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2)
		return pickle_set_result_error_arity(i, 2, argc, argv);
	const char *env = getenv(argv[1]);
	return pickle_set_result_string(i, env ? env : "");
}

/*static int commandConsole(pickle_t *i, int argc, char **argv, void *pd) {
	UNUSED(pd);
	if (argc != 2)
		return pickle_set_result_error_arity(i, 2, argc, argv);
	int ret = 0;
	esp_err_t err = esp_console_run(argv[1], &ret);
	if (err == ESP_ERR_NOT_FOUND) {
        	return pickle_set_result(i, "Invalid command");
        } else if (err == ESP_ERR_INVALID_ARG) {
        	// command was empty
        } else if (err == ESP_OK && ret != ESP_OK) {
        	return pickle_set_result(i, "Command returned non-zero error code: 0x%x (%s)\n", ret, esp_err_to_name(ret));
        } else if (err != ESP_OK) {
		return pickle_set_result(i, "Invalid internal state: %s", esp_err_to_name(err));
        }
	return pickle_set_result_string(i, "");
}*/

static int commandSource(pickle_t *i, int argc, char **argv, void *pd) {
	if (argc != 1 && argc != 2)
		return pickle_set_result_error_arity(i, 2, argc, argv);
	errno = 0;
	FILE *file = argc == 1 ? pd : fopen(argv[1], "rb");
	if (!file)
		return pickle_set_result_error(i, "Could not open file '%s' for reading: %s", argv[1], strerror(errno));

	char *program = slurp(i, file, NULL, NULL);
	if (file != pd)
		fclose(file);
	if (!program)
		return pickle_set_result_error(i, "Out Of Memory");

	const int r = pickle_eval(i, program);
	if (pickle_free(i, (void**)&program) != PICKLE_OK)
		return PICKLE_ERROR;
	return r;
}

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
		const char *name; pickle_command_func_t func; void *data;
	} commands_t;

	const commands_t cmds[] = {
		{ "gets",   commandGets,   in     },
		{ "puts",   commandPuts,   out    },
		{ "getenv", commandGetEnv, NULL   },
		{ "exit",   commandExit,   NULL   },
		{ "source", commandSource, NULL   },
		//{ "system", commandConsole, NULL   },
	};

	for (size_t j = 0; j < sizeof (cmds) / sizeof (cmds[0]); j++)
		if (pickle_register_command(i, cmds[j].name, cmds[j].func, cmds[j].data) != PICKLE_OK)
			goto fail;

	*ret = i;
	return 0;
fail:
	pickle_delete(i);
	*ret = NULL;
	return -1;
}

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
		if (pickle_get_result_string(i, &rstr) != PICKLE_OK)
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

/*static void initialize_nvs(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK( nvs_flash_erase() );
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}*/

void app_main(void)
{
    //initialize_nvs();
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
