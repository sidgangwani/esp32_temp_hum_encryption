#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "freertos/event_groups.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "DHT.h"
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/unistd.h>
#include <sys/select.h>
#include "esp_deep_sleep.h"
#include "mbedtls/md.h"
#include "sdkconfig.h"
#include "esp_wifi.h"
#include <time.h>
#include <sys/time.h>
#include "lwip/err.h"
#include "lwip/sys.h"
#include "apps/sntp/sntp.h"
#include "esp_vfs.h"
#include "esp_vfs_dev.h"
#include "driver/uart.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#define GPIO_DEEP_SLEEP_DURATION     20
#define MAX_TEMPERATURE_CONSTRAINT	40
#define MIN_TEMPERATURE_CONSTRAINT	0
#define MAX_CHARACTER_LENGTH 150
#define MAX_BUFFER	2
#define MAX_ENCRYPT_VALUE_LENGTH	32
//Change Example_EPS_WIFI_SSID and EXAMPLE_ESP_WIFI_PASS to your SSID and Password
#define EXAMPLE_ESP_WIFI_SSID "WIFI Username"
#define EXAMPLE_ESP_WIFI_PASS "password"

static const char *TAG1 = "DHT";
static const char *TAG2 = "Wifi Station";
static const char *TAG3 = "UART";

RTC_DATA_ATTR static int flagStartOfExecution=0;	//Integer value to help keep track whether it is the first time that we are reading the data values or not

typedef struct
{
    int head;
    int tail;
    uint8_t dataBlocks[MAX_BUFFER][MAX_ENCRYPT_VALUE_LENGTH];
} circularBuffer;

RTC_DATA_ATTR static circularBuffer cBuff= {-1,-1};	//Circular Buffer which will keep track of resulting 256 bit encrypted temperature values

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about one event
 * - are we connected to the AP with an IP? */
const int WIFI_CONNECTED_BIT = BIT0;

//Prototypes for functions which are going to be used
static void obtain_time(void);
static void initialize_sntp(void);
static void wifi_init_sta(void);
static esp_err_t event_handler(void *ctx, system_event_t *event);
static void initializeCircularBuffer(circularBuffer* cBuff, uint8_t shaResult[MAX_ENCRYPT_VALUE_LENGTH]);
static void deletePreviousTempFromBuffer(circularBuffer* cBuff);
static void mbedtls_encryption_sha256(const char *payload, uint8_t shaResult[MAX_ENCRYPT_VALUE_LENGTH]);
static bool DHT_task(void *pvParameter, float *temp,  float *hum);
static int uart_select_task(void);

//Definitions for Functions
static void obtain_time(void)
{
    ESP_ERROR_CHECK( nvs_flash_init() );
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                        false, true, portMAX_DELAY);
    initialize_sntp();

    // wait for time to be set
    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;
    const int retry_count = 10;
    while(timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
        ESP_LOGI(TAG2, "Waiting for system time to be set... (%d/%d)", retry, retry_count);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        time(&now);
        localtime_r(&now, &timeinfo);
    }

    ESP_ERROR_CHECK( esp_wifi_stop() );
}

static void initialize_sntp(void)
{
    ESP_LOGI(TAG2, "Initializing SNTP");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
	switch(event->event_id) {
	    case SYSTEM_EVENT_STA_START:
	        esp_wifi_connect();
	        break;
	    case SYSTEM_EVENT_STA_GOT_IP:
	        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
	        break;
	    case SYSTEM_EVENT_STA_DISCONNECTED:
	        /* This is a workaround as ESP32 WiFi libraries don't currently
	           auto re-associate. */
	        esp_wifi_connect();
	        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
	        break;
	    default:
	        break;
	    }
	    return ESP_OK;
}

static void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL) );

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .password = EXAMPLE_ESP_WIFI_PASS
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG2, "wifi_init_sta finished.");
    ESP_LOGI(TAG2, "connect to ap SSID:%s password:%s",
    EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
}

/*
 * This function helps add the current temperature to the Buffer
 *
 * @return type is void
 */

static void initializeCircularBuffer(circularBuffer* cBuff, uint8_t shaResult[MAX_ENCRYPT_VALUE_LENGTH])
{
	if((cBuff->head==0 && cBuff->tail==MAX_BUFFER-1) || (cBuff->tail+1==cBuff->head))
	{
		printf("Circular Buffer is Full\n");
	}
	else
	{
		if(cBuff->tail==MAX_BUFFER-1)
		{
			cBuff->tail=0;
		}
		else
		{
			cBuff->tail++;
		}

		for(int i=0;i<MAX_ENCRYPT_VALUE_LENGTH;i++)
		{
			cBuff->dataBlocks[cBuff->tail][i]=shaResult[i];
		}
	 }

	 if(cBuff->head==-1)
	 {
	   cBuff->head=0;
	 }
}

/*
 * This function helps delete the previous temperature to the Buffer
 *
 * @return type is void
 */

static void deletePreviousTempFromBuffer(circularBuffer* cBuff)
{
	if(cBuff->head==-1)
	{
		printf("Circular Buffer is Empty\n");
	}
	 else
	 {
		if(cBuff->head==cBuff->tail)
		{
		   cBuff->head=cBuff->tail=-1;
		}
		else
		{
		   if(cBuff->head==MAX_BUFFER-1)
		   {
			  cBuff->head=0;
		   }
		   else
		   {
			  cBuff->head++;
		   }
		}
	 }
}

/*
 * This function helps to encrypt the string of floating point
 * value that is passed using the sha256 hashing algorithm
 *
 * @return type is void
 *
 */

static void mbedtls_encryption_sha256(const char *payload, uint8_t shaResult[MAX_ENCRYPT_VALUE_LENGTH])
{
	  mbedtls_md_context_t ctx;		//Structure variable used to maintain the internal state between other functions
	  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;	//Using sha256 algorithm

	  const size_t payloadLength = strlen(payload);	//Length of the input data

	  mbedtls_md_init(&ctx);		//Setting up the context value
	  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);	//Setting up the encryption process
	  mbedtls_md_starts(&ctx);		//Starting the encryption process
	  mbedtls_md_update(&ctx, (const unsigned char *) payload, payloadLength);	//Getting the encrypted value
	  mbedtls_md_finish(&ctx, shaResult);	//Storing the encrypted value into shaResult
	  mbedtls_md_free(&ctx);		//Clearing the context to be used for other values
}

/*
 * This function stores the temperature and humidity that the DHT22
 * sensor reads
 *
 * @return type is boolean to see if the temperature measured exceeds the
 * MAX_TEMPERATURE_CONSTRAINT or goes below the MIN_TEMPERATURE_CONSTRAINT
 *
 */

static bool DHT_task(void *pvParameter, float *temp,  float *hum)
{
	bool return_condition=true;		//Setting the return_condition to be true at the start

    setDHTgpio(GPIO_NUM_4);			//Setting the GPIO 4 to be the GPIO input for our DHT22 sensor

    ESP_LOGI(TAG1, "\n=== Reading DHT ===\n");
	int ret = readDHT();

	errorHandler(ret);				//Error Handling

	*temp=getTemperature();		//Reading Temperature
	*hum= getHumidity();				//Reading Humidity

	if(*temp>MAX_TEMPERATURE_CONSTRAINT || *temp< MIN_TEMPERATURE_CONSTRAINT)
	{
		return_condition=false;
	}

	return return_condition;
}

/*
 * This function helps receive message using UART 0
 *
 * @return type is integer based on what type of message is
 * read from UART 0
 *
 */

static int uart_select_task(void)
{
	int fd;

	if ((fd = open("/dev/uart/0", O_RDWR)) == -1) {
		ESP_LOGE(TAG3, "Cannot open UART");
		vTaskDelay(5000 / portTICK_PERIOD_MS);
		return 1;
	}

	char buffer[50];	//String received from UART
	int flag=0;			//Return Variable

	// We have a driver now installed so set up the read/write functions to use driver also.
	esp_vfs_dev_uart_use_driver(0);

	strcpy(buffer,"");

	while (flag==0) {
		int s;
		fd_set rfds;
		struct timeval tv = {
			.tv_sec = 10,	//Timeout Waiting Period
			.tv_usec = 0,
		};

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		s = select(fd + 1, &rfds, NULL, NULL, &tv);

		if (s < 0) {
			ESP_LOGE(TAG3, "Select failed: error number %d", errno);
			break;
		} else if (s == 0) {
			ESP_LOGI(TAG3, "Timeout has been reached and nothing has been received");
			flag=1;
		} else {
			if (FD_ISSET(fd, &rfds)) {
				char characterBuf;
				if (read(fd, &characterBuf, 1) > 0) {
					char cToStr[2];
					cToStr[0]=characterBuf;
					strcat(buffer,cToStr);
				} else {
					ESP_LOGE(TAG3, "UART read error");
					break;
				}
			} else {
				ESP_LOGE(TAG3, "No FD has been set in select()");
				break;
			}
		}

		//Setting the flag according to the type of message received
		if(strstr(strupr(buffer),"A,B,FAIL")!=NULL)
		{
			flag=1;
		}
		else if(strstr(strupr(buffer),"A,B,OK")!=NULL)
		{
			flag=2;
		}
		else if(strstr(strupr(buffer),"A,B,SYNC")!=NULL)
		{
			flag=3;
		}
	}
	close(fd);

	return flag;
}

void app_main()
{
    //Initialize NVS
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES)
	{
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);

	esp_log_level_set("*", ESP_LOG_INFO);
	ESP_LOGI(TAG2, "ESP_WIFI_MODE_STA");

	wifi_init_sta();

	 uart_config_t uart_config = {
	        .baud_rate = 115200,
	        .data_bits = UART_DATA_8_BITS,
	        .parity    = UART_PARITY_DISABLE,
	        .stop_bits = UART_STOP_BITS_1,
	        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
	    };

	 uart_driver_install(UART_NUM_0, 2*1024, 0, 0, NULL, 0);
	 uart_param_config(UART_NUM_0, &uart_config);

    /*
     * Reading Temperature and Humidity after waking up from deep sleep mode for a sleep duration of 20 seconds to save battery power
     */

    float hum=0.0;		//Float variable which will store the Humidity returned by the DHT22 sensor
    float temp=0.0;		//Float variable which will store the Temperature returned by the DHT22 sensor

    while(1)
    {
    	uint8_t shaResult[MAX_ENCRYPT_VALUE_LENGTH];	//Resulting current 256 bit encrypted data is stored here temporarily

    	bool condition=DHT_task(NULL,&temp, &hum);

    	char message[MAX_CHARACTER_LENGTH];		//Printing Message will be stored here
    	char payload[MAX_CHARACTER_LENGTH];
		char temporaryPayload[MAX_CHARACTER_LENGTH];

		int flagFromUART=0;

		time_t now;
		struct tm timeinfo;
		time(&now);
		localtime_r(&now, &timeinfo);

		// Is time set? If not, tm_year will be (1970 - 1900).
		if (timeinfo.tm_year < (2016 - 1900)) {
		   ESP_LOGI(TAG2, "Time is not set yet. Connecting to WiFi and getting time over NTP.");
		   obtain_time();
		   // update 'now' variable with current time
		   time(&now);
		}

		strcpy(message, "A, B, ");
		strcpy(payload,"UTC:");

		sprintf(temporaryPayload, "%ld", now);	//Storing the Time value into a string

		strcat(payload,temporaryPayload);

		if(temp>0)
		{
			strcat(payload, ",TEMP:+");
		}

		else
		{
			strcat(payload, ",TEMP:");
		}

		sprintf(temporaryPayload, "%.3f", temp);	//Storing the floating point Temperature value into a string

		strcat(payload,temporaryPayload);
		strcat(payload,"degC,HUM:");

		sprintf(temporaryPayload, "%.2f", hum);		//Storing the floating point Humidity value into a string

		strcat(payload,temporaryPayload);

		strcat(payload,"%");
		strcat(message,payload);
		strcat(message,", ");

		mbedtls_encryption_sha256(payload,shaResult);	//Encrypting the block value

    	if(flagStartOfExecution==0)
    	{
    		uint8_t shaResultHello[MAX_ENCRYPT_VALUE_LENGTH];

    		mbedtls_encryption_sha256("Hello",shaResultHello);

    		initializeCircularBuffer(&cBuff, shaResultHello);
    		initializeCircularBuffer(&cBuff, shaResult);	//Saving the current 256 bit encrypted block to the buffer

    		flagStartOfExecution=1;
    	}

    	else if(flagStartOfExecution==1)
    	{
    		deletePreviousTempFromBuffer(&cBuff);	//Saving previous 256 bit encrypted block value
    		initializeCircularBuffer(&cBuff, shaResult);	//Saving current 256 bit encrypted block value
    	}

		if(cBuff.tail<cBuff.head)		//Getting locations of previous block and current block in the buffer
		{
			for(int i=cBuff.head;i<MAX_BUFFER;i++)
			{
				for(int j= 0; j< sizeof(cBuff.dataBlocks[i]); j++)
				{
					sprintf(temporaryPayload,"%02x",(int)cBuff.dataBlocks[i][j]);		//Saving the encrypted block value
					strcat(message,temporaryPayload);
				}
				strcat(message,", ");
			}

			for(int i=0;i<=cBuff.tail;i++)
			{
				for(int j= 0; j< sizeof(cBuff.dataBlocks[i]); j++)
				{
					sprintf(temporaryPayload,"%02x",(int)cBuff.dataBlocks[i][j]);		//Saving the encrypted block value
					strcat(message,temporaryPayload);
				}
				if(i!=cBuff.tail)
				{
					strcat(message,", ");
				}
			}
		}

		else
		{
			for(int i=cBuff.head;i<=cBuff.tail;i++)		//Getting locations of previous block and current block in the buffer
			{
				for(int j= 0; j< sizeof(cBuff.dataBlocks[i]); j++)
				{
					sprintf(temporaryPayload,"%02x",(int)cBuff.dataBlocks[i][j]);		//Saving the encrypted block value
					strcat(message,temporaryPayload);
				}
				if(i!=cBuff.tail)
				{
					strcat(message,", ");
				}
			}
		}

		do{

			printf("\n%s\n\n",message);
			flagFromUART=uart_select_task();

			if(flagFromUART==1)
			{
				printf("Sending Same Message again\n");
			}

		}while(flagFromUART==1);


		if(flagFromUART==3)
		{
			flagStartOfExecution=0;

			//Calling deletePreviousFromBuffer 2 times to completely refresh the buffer and start from scratch
			deletePreviousTempFromBuffer(&cBuff);
			deletePreviousTempFromBuffer(&cBuff);

			printf("Starting the whole process again in 10 seconds\n");
		}
		else
		{
			printf("Sending new message in 10 seconds\n");
		}

		/*if(condition)
		{
			printf("Deep Sleep Started\n\n");
			esp_deep_sleep(1000000LL * GPIO_DEEP_SLEEP_DURATION);
		}*/

    	vTaskDelay(10000 / portTICK_RATE_MS);
    }
}
