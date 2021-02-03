# esp32_temp_hum_encryption

Efficient way to read data from DHT22 sensor when ESP32 is battery powered.

The ESP32 development board reads one state of data from the DHT22 Sensor and then goes into deep sleep mode for 20 seconds to save battery power.

The data recorded is encrypted using sha256 algorithm and the encrypted data is stored in a circular buffer. It stores 2 datasets in the circular buffer- one with previous data values and one with current data values. While communicating using UART if there is a fail or a sync message it sends out the previous data message values till the UART receives an OK message. On receiving the OK message it sends out the current data message. On sucessful completion of one full cycle. the previous data message is removed from buffer and the current data message is marked as the previous data message.

The circular buffer is stored in the flash memory of the ESP32 development board
