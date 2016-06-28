# node-red-contrib-nfc

NFC reader node for Node RED.  Requires an I2C-connected SL030 RFID/NFC reader.  Must be run as root (for access to the i2c bus in /dev/mem)

## Nodes

* **rpi rfid** Generates events when a tag is presented or removed.
* **rpi rfid read** Read a block from a Mifare tag
* **rpi rfid write** Write a block to a Mifare tag
* **rpi rfid read ndef** Read and decode any NDEF records in a Mifare or NTAG2xx tag
* **rpi rfid write ndef** Write NDEF records to a Mifare or NTAG2xx tag

