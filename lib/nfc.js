/**
 * Copyright 2014-2015 MCQN Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

module.exports = function(RED) {
    "use strict";
    var rfid_sl030 = require("rfid-sl030");
    var fs =  require('fs');
    var ndef = require('ndef');
    // Create a single RFID instance that all nodes can use
    var ourfid = new rfid_sl030.RFID_SL030();
    ourfid.init();

    if (!fs.existsSync("/dev/ttyAMA0")) { // unlikely if not on a Pi
        throw "Info : Ignoring Raspberry Pi specific node.";
    }

    function RFID(n) {
        RED.nodes.createNode(this,n);
        this.cardPresent = false;
        this.cardID = "";
        this.rfid = ourfid; 
        var node = this;

        node._interval = setInterval( function() {
            ourfid.init();
            var tag = node.rfid.selectTag();
            if (tag) {
                if (!node.cardPresent) {
                    node.cardID = tag.tagIDString;
                    var msg = {topic:"pi/rfid-presented", payload:node.cardID};
                    node.send(msg);
                }
                // else it's still the same card on the reader
                node.cardPresent = true;
            }
            else {
                if (node.cardPresent) {
                    // The card has just been removed
                    var msg = {topic:"pi/rfid-removed", payload:node.cardID};
                    node.send(msg);
                }
                node.cardPresent = false;
            }
        }, 250);

        node.on("close", function() {
            clearInterval(node._interval);
        });
    }

    function RFIDWrite(n) {
        RED.nodes.createNode(this,n);
        this.name = n.name;
        this.rfid = ourfid; 
        var node = this;

        this.on("input", function(msg) {
            if (msg != null) {
                if (msg.block != null && msg.payload) {
                    // We've got our pre-requisites
                    // Find an RFID tag first
                    this.rfid.init();
                    var tag = this.rfid.selectTag();
                    if (tag) {
                        // Tag found.  Authenticate with the block first
                        if (this.rfid.authenticate(this.rfid.sectorForBlock(msg.block))) {
                            // Authenticated.  Prepare the data to write
                            // Blocks on the MiFare 1K tags are 16 bytes long
                            var data = new Buffer(16);
                            data.fill(0);
                            data.write(msg.payload);
                            //console.log("About to write '"+msg.payload+"' to "+msg.block);
                            if (this.rfid.writeBlock(msg.block, data)) {
                                this.send(msg);
                            } else {
                                msg.payload = "Failed to write to RFID tag"; 
                                this.error(msg.payload, msg);
                            }
                        } else {
                            // Error, couldn't authenticate tag
                            msg.payload = "Couldn't authenticate RFID tag"; 
                            this.error(msg.payload, msg);
                        }
                    } else {
                        // Failed to find a tag
                        msg.payload = "No RFID tag found"; 
                        this.error(msg.payload, msg);
                    }
                } else {
                    msg.payload = "Missing either a msg.block or a msg.payload"; 
                    this.error(msg.payload, msg);
                }
            }
        });
    }

    function RFIDRead(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.rfid = ourfid;
        var node = this;

        this.on("input", function(msg) {
            if (msg != null && msg.hasOwnProperty("payload")) {
                this.rfid.init();
                var tag = this.rfid.selectTag();
                if (tag) {
                    if (tag.tagType == "Mifare Ultralight") {
                        // It's one of the tags from the Ultralight family
                        // which includes the NTAG203, etc.
                        var data = this.rfid.readPage(msg.block);
                        if (data != null) {
                            msg.payload = data.toString('hex');
                            this.send(msg);
                        } else {
                            msg.payload = "Couldn't read from RFID tag"; 
                            this.error(msg.payload, msg);
                        }
                    } else if (tag.tagType == "Mifare 1K") {
                        if (this.rfid.authenticate(this.rfid.sectorForBlock(msg.block))) {
                            var data = this.rfid.readBlock(msg.block);
                            if (data != null) {
                                msg.payload = data.toString('hex');
                                this.send(msg);
                            } else {
                                msg.payload = "Couldn't read from RFID tag"; 
                                this.error(msg.payload, msg);
                            }
                        } else {
                            msg.payload = "Couldn't authenticate RFID tag"; 
                            this.error(msg.payload, msg);
                        }
                    } else {
                        msg.payload = "Unrecognised tag type: "+tag.tagType; 
                        this.error(msg.payload, msg);
                    }
                } else {
                    msg.payload = "No RFID tag found"; 
                    this.error(msg.payload, msg);
                }
            } else {
                msg.payload = "Missing a msg.payload"; 
                this.error(msg.payload, msg);
            }
        });
    }

    function RFIDReadNDEF(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.rfid = ourfid;
        var node = this;

        this.on("input", function(msg) {
            if (msg != null) {
                this.rfid.init();
                var tag = this.rfid.selectTag();
                if (tag) {
                    // Find any ndefData...
                    var rawNDEF = null;
                    if (tag.tagType == "Mifare Ultralight") {
                        // It's one of the tags from the Ultralight family
                        // which includes the NTAG203, etc.

                        // Read in all the pages, assuming they all contain NDEF data
                        var ndefSectors = [];
                        // Read in the tag's capability container to work out
                        // its size
                        var data = this.rfid.readPage(3);
                        if (data != null) {
                            var page = 4; // skip the first four pages as they hold
                                          // general info on the tag
                            var pageCount = 0xFFFF; // Read until we hit an error
                            // ...unless we know how big this tag is...
                            if (data[2] == 0x12) {
                                pageCount = 36; // NTAG213, 144-byte
                            } else if (data[2] == 0x3E) {
                                pageCount = 124; // NTAG215, 496-byte
                            } else if (data[2] == 0x6D) {
                                pageCount = 218; // NTAG216, 872-byte
                            }
                            var data = null;
                            do {
                                data = this.rfid.readPage(page++);
                                ndefSectors.push(data);
                            } while ((page <= pageCount) && (data != null));
                            // If we end with a "null" last entry in ndefSectors
                            // then remove it
                            if (data == null) {
                                ndefSectors.pop();
                            }
                            rawNDEF = Buffer.concat(ndefSectors);
                        } else {
                            console.log("Couldn't read capability container of RFID tag");
                        }
                    } else if (tag.tagType == "Mifare 1K") {
                        var NDEFkey = new Buffer(6);
                        NDEFkey[0] = 0xD3;
                        NDEFkey[1] = 0xF7;
                        NDEFkey[2] = 0xD3;
                        NDEFkey[3] = 0xF7;
                        NDEFkey[4] = 0xD3;
                        NDEFkey[5] = 0xF7;
                        // This currently only works for MiFare Classic tags
                        // See http://www.nxp.com/documents/application_note/AN1304.pdf for details
                        // on how NDEF data is stored in Classic tags
                        // Read the MAD (Mifare Application Directory) in to find out where the
                        var mad = readMAD(this.rfid);
                        if (mad) {
                            // The MAD has two-bytes for each sector, explaining
                            // what application is using them.  Read in all the
                            // NDEF sectors and store them in an array of buffers
                            var ndefSectors = [];
                            // FIXME This assumes we're only using MAD1, and only
                            // FIXME using the first 1K of the tag
                            for (i = 1; i < 16; i++) {
                                if ((mad[i*2] == 0x03) && (mad[i*2+1] == 0xE1)) {
                                    // This sector contains NDEF data
                                    if (this.rfid.authenticate(i, NDEFkey)) {
                                        var block0 = this.rfid.readBlock(i<<2);
                                        var block1 = this.rfid.readBlock((i<<2)+1);
                                        var block2 = this.rfid.readBlock((i<<2)+2);
                                        ndefSectors.push(Buffer.concat([block0, block1, block2]));
                                    } else {
                                        console.log("Couldn't authenticate NDEF sector with NDEF key");
                                    }
                                }
                            }
                            rawNDEF = Buffer.concat(ndefSectors);
                        } else {
                            console.log("Couldn't authenticate RFID tag");
                        }
                    } else {
                        msg.payload = "Unrecognised tag type: "+tag.tagType; 
                        this.error(msg.payload, msg);
                    }

                    if (rawNDEF != null)
                    {
                        // Now we've got all the NDEF data, we need to parse it
                        var idx = 0;
                        var ndefRecords = [];
                        while (idx < rawNDEF.length) {
                            // Look for the initial TLV structure
                            var t = rawNDEF[idx++];
                            if (t != 0) {
                                // It's not a NULL TLV, see how long it is
                                var l = rawNDEF[idx++];
                                if (l == 0xFF) {
                                    // 3-byte length format, the next two 
                                    // bytes give our length
                                    l = rawNDEF[idx++] << 8 | rawNEF[idx++];
                                }
                                if (t == 0x03) {
                                    console.log("Found NDEF message");
                                    var message = [];
                                    while (l-- > 0) {
                                        message.push(rawNDEF[idx++]);
                                    }
                                    ndefRecords = ndefRecords.concat(ndef.decodeMessage(message));   
                                } else if (t == 0xFE) {
                                    // Terminator TLV block, so give up now
                                    console.log("Found terminator block");
                                    break;
                                } else {
                                    // Skip over l bytes to get to the next TLV
                                    console.log("Skipping "+t.toString(16)+" block, length "+l+" bytes");
                                    idx += l;
                                }
                            } else {
                                console.log("NULL TLV");
                            }
                        }
                        //console.log(ndefRecords);
                        for (i = 0; i < ndefRecords.length; i++) {
                            //var msg = {topic:"pi/rfid-ndef", payload:ndefRecords[i], ndef: ndefRecords[i]};
                            msg.topic="pi/rfid-ndef";
                            msg.payload=ndefRecords[i];
                            msg.ndef= ndefRecords[i];
                            this.send(msg);
                        }
                    }
                } else {
                    msg.payload = "No RFID tag found"; 
                    this.error(msg.payload, msg);
                }
            } else {
                msg.payload = "Missing a msg.payload"; 
                this.error(msg.payload, msg);
            }
        });
    }

    function RFIDWriteNDEF(n) {
        RED.nodes.createNode(this,n);
        this.name = n.name;
        this.rfid = ourfid; 
        var node = this;

        this.on("input", function(msg) {
            if (msg != null) {
                if (msg.payload) {
                    // We've got our pre-requisites
                    // Find an RFID tag first
                    this.rfid.init();
                    var tag = this.rfid.selectTag();
                    if (tag) {
                        // Tag found.
                        // Build up the NDEF records we'll send
                        // FIXME Cope with msg.payload not being an array of objs
                        var ndefRecords = [];
                        for (i = 0; i < msg.payload.length; i++) {
                            if (msg.payload[i].type == "Sp") {
                                // URL record
                                ndefRecords.push(ndef.uriRecord(msg.payload[i].value));
                            } else if (msg.payload[i].type == "T") {
                                // Text record
                                ndefRecords.push(ndef.textRecord(msg.payload[i].value));
                            }
                        }
                        if (ndefRecords.length) {
                            // Prep the NDEF message
                            var ndefMessage = ndef.encodeMessage(ndefRecords);
                            // Prepend the TLV value to put it into a Mifare Classic tag
                            // (Prepend in reverse order as unshift puts a byte at the start of the array)
                            if (ndefMessage.length >= 0xFF) {
                                // 3-byte length version
                                ndefMessage.unshift(ndefMessage.length & 0xff);
                                ndefMessage.unshift(ndefMessage.length >> 8);
                                ndefMessage.unshift(0xff);
                            } else {
                                ndefMessage.unshift(ndefMessage.length);
                            }
                            ndefMessage.unshift(0x03);
                            // Append a terminator block
                            ndefMessage.push(0xfe);
                            ndefMessage.push(0x00);

                            var ndefMsgBuffer = new Buffer(ndefMessage);
                            console.log(ndefMsgBuffer.toString('hex'));

                            if (tag.tagType == "Mifare Ultralight") {
                                // It's one of the tags from the Ultralight family
                                // which includes the NTAG203, etc.

                                // Read in the tag's capability container to 
                                // work out its size
                                var data = this.rfid.readPage(3);
                                if (data != null) {
                                    var page = 4; // skip the first four pages as they hold
                                                  // general info on the tag
                                    var pageCount = 0xFFFF; // Read until we hit an error
                                    // ...unless we know how big this tag is...
                                    if (data[2] == 0x12) {
                                        pageCount = 36; // NTAG213, 144-byte
                                    } else if (data[2] == 0x3E) {
                                        pageCount = 124; // NTAG215, 496-byte
                                    } else if (data[2] == 0x6D) {
                                        pageCount = 218; // NTAG216, 872-byte
                                    }
                                    // Check if there'll be enough space
                                    if (ndefMsgBuffer.length <= (pageCount-page)*4) {
                                        var idx = 0;
                                        var working = true;
                                        while ((idx < ndefMsgBuffer.length) 
                                               && (working)) {
                                            var block = new Buffer(4);
                                            block.fill(0);
                                            ndefMsgBuffer.copy(block, 0, idx, idx+4);
                                            var tries = 0;
                                            working = false; // so we drop into the while loop
                                            while ((tries++ < 5) && (!working)) {
                                                working = this.rfid.writePage(page, block);
                                            }
                                            page++;
                                            idx+=4;
                                        }
                                        if (working) {
                                            this.send(msg);
                                        } else {
                                            msg.payload = "Write error";
                                            this.error(msg.payload, msg);
                                        }
                                    } else {
                                        msg.payload = "Tag too small!"; 
                                        this.error(msg.payload, msg);
                                    }
                                } else {
                                    msg.payload = "Couldn't read capability container of RFID tag"; 
                                    this.error(msg.payload, msg);
                                }
                            } else if (tag.tagType == "Mifare 1K") {
                                // Try to read in the MAD from the tag
                                var mad = readMAD(this.rfid);

                                if (mad) {
                                    console.log(mad);
                                } else {
                                    console.log("Empty MAD");
                                    // See if we can format the MAD
                                    //FIXME mad = formatMAD();
                                }
                                if (mad && ndefRecords.length) {
                                    var sector = 1;
                                    var idx = 0;
                                    console.log("mad: ");
                                    console.log(mad);
                                    while ((idx < ndefMsgBuffer.length) && (sector < 16)) {
                                        // Find a sector we can write to
                                        console.log("sector*2: "+sector*2);
                                        console.log("mad[sector*2]: "+mad[sector*2]);
                                        console.log("mad[sector*2+1]: "+mad[sector*2+1]);

                                        if ((mad[sector*2] == 0x03) && (mad[sector*2+1] == 0xE1)) {
                                            // It's an existing NDEF block that we'll overwrite
                                            var NDEFkey = new Buffer(6);
                                            NDEFkey[0] = 0xD3;
                                            NDEFkey[1] = 0xF7;
                                            NDEFkey[2] = 0xD3;
                                            NDEFkey[3] = 0xF7;
                                            NDEFkey[4] = 0xD3;
                                            NDEFkey[5] = 0xF7;
                                            if (this.rfid.authenticate(sector, NDEFkey)) {
                                                var block = new Buffer(16);
                                                for (var b = 0; b < 3; b++) {
                                                    block.fill(0);
                                                    ndefMsgBuffer.copy(block, 0, idx, idx+16);
console.log(((sector<<2)        +b)+": "+block);
                                                    this.rfid.writeBlock((sector<<2)+b, block);
                                                    idx+=16;
                                                }
                                            }
                                        }
                                        if ((mad[sector*2] == 0x00) && (mad[sector*2+1] == 0x00)) {
                                            // It's an empty block, so use the default key to authenticate
                                            // We can write to this sector
                                            if (this.rfid.authenticate(sector)) {
                                                var block = new Buffer(16);
                                                for (var b = 0; b < 3; b++) {
                                                    block.fill(0);
                                                    ndefMsgBuffer.copy(block, 0, idx, idx+16);
                                                    this.rfid.writeBlock((sector<<2)+b, block);
                                                    idx+=16;
                                                }
                                                // Write the NDEF key into the final sector
                                                block.fill(0xff); // This will leave the 2nd key as the default
                                                NDEFkey.copy(block, 0);
                                                block[6] = 0x7F;
                                                block[7] = 0x07;
                                                block[8] = 0x88;
                                                block[9] = 0x40;
                                                this.rfid.writeBlock((sector<<2)+3, block);
                                            }
                                        }
                                        sector++;
                                    }
                                    this.send(msg);
                                } else {
                                    // Error, couldn't authenticate tag
                                    msg.payload = "Couldn't authenticate RFID tag"; 
                                    this.error(msg.payload, msg);
                                }
                            } else {
                                msg.payload = "Unrecognised tag type: "+tag.tagType; 
                                this.error(msg.payload, msg);
                            }
                        }
                    } else {
                        // Failed to find a tag
                        msg.payload = "No RFID tag found"; 
                        this.error(msg.payload, msg);
                    }
                } else {
                    msg.payload = "Missing either a msg.block or a msg.payload"; 
                    this.error(msg.payload, msg);
                }
            }
        });
    }

    function readMAD(rfid) {
        var MADkey = new Buffer(6);
        MADkey[0] = 0xA0;
        MADkey[1] = 0xA1;
        MADkey[2] = 0xA2;
        MADkey[3] = 0xA3;
        MADkey[4] = 0xA4;
        MADkey[5] = 0xA5;
        // Read the MAD (Mifare Application Directory) in to find out where the
        // NDEF blocks are
        if (rfid.authenticate(rfid.sectorForBlock(1), MADkey)) {
            var mad1 = rfid.readBlock(1);
            var mad2 = rfid.readBlock(2);
            var mad = Buffer.concat([mad1, mad2]);
            console.log(mad.toString('hex'));
            return mad;
        }
        return null;
    }

    RED.nodes.registerType("rpi-rfid in",RFID);
    RED.nodes.registerType("rpi-rfid write",RFIDWrite);
    RED.nodes.registerType("rpi-rfid read",RFIDRead);
    RED.nodes.registerType("rpi-rfid read-ndef",RFIDReadNDEF);
    RED.nodes.registerType("rpi-rfid write-ndef",RFIDWriteNDEF);
}
