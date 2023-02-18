  # XpressNet-Analyzer

(_Work in Progress_)

A high level logic analyzer for Saleae Logic 2.

![Picture of the analyzer](https://raw.githubusercontent.com/SE7-KN8/XpressNet-Analyzer/master/.github/img.png)

This extension provides support for XpressNet 3.0 a protocol by Lenz which is a protocol used in model railroads for communication.
To use this analyzer you first need an Async-Serial low lever decoder.

All packets are based on this documentation: [XpressNet-V3.0](https://wiki.rocrail.net/lib/exe/fetch.php?media=xpressnet:xpressnet-v2.pdf) and [XpressNet-V3.6](https://wiki.rocrail.net/lib/exe/fetch.php?media=xpressnet:xpressnet-lan-usb-23151-v1.pdf)

This analyzer is not complete, the table shows the current progress

### Corrected functions
The function status functions are corrected. They now show if a function is a momentary or toggle function
The new status requests and responses report the status as follows:

|Char|Function|Description|
|----|--------|-----------|
|M|Momentary function|When on a device the function button is pressed the function is ON, when the button is released the function is OFF again|
|T|Toggle function|When on a device the function button is pressed this function is ON, when the button is pressed again the function is OFF|


### From command station to device:
_* = Multiple packages of the same type_

|Name|Type|Implemented|
|----|----|:---------:|
|Normal inquiry|Inquiry|x|
|Request Acknowledgment|Request|x|
|Normal operation resumed|Broadcast|x|
|Track power off|Broadcast|x|
|Emergency stop|Broadcast|x|
|Service Mode entry|Broadcast|x|
|Feedback Broadcast|Broadcast||
|Programming info *|Response||
|Service Mode Response *|Response||
|Software Version|Response|X|
|Command station status indication|Response|X|
|Transfer Errors|Response||
|Command station busy response|Response||
|Instruction not supported|Response||
|Accessory Decoder information|Response|X|
|Locomotive information *|Response|X|
|Locomotive is being operated|Response|X|
|Function status|Response|X|
|Locomotive information (address retrieval)|Response|X|
|Double Header *|Multiple||
|MU+DH error||Response||



### From device to command station:
|Name|Type|Implemented|
|----|----|:---------:|
|Acknowledgment Response|Response|X|
|Resume operations|Request|X|
|Stop operations|Request|X|
|Stop all locomotives|Request||
|Emergency stop a locomotive|?||
|Register Mode read|Request||
|Direct Mode CV read|Request||
|Paged Mode read|Request||
|Service Mode results|Request|X|
|Register Mode Write|Request||
|Direct Mode CV Write|Request||
|Paged Mode write|Request||
|Command station software version|Request|X|
|Command station status|Request|X|
|Set command station power-up mode|?||
|Accessory Decoder information|Request|X|
|Accessory Decoder operation|Request|X|
|Locomotive information|Request|X|
|Function status|Request|X|
|Locomotive speed and direction|Instructions|X|
|Function operation|Instructions|X|
|Set function state|Instructions|X|
|Double header *|Multiple||
|Operations Mode programming byte mode write|Request||
|Operations Mode programming bit mode write|Request||
|Add a locomotive to a multi-unit|Request||
|Remove a locomotive from a multi-unit|Request||
|Address inquiry member of a multi-unit|Request||
|Address inquiry multi-unit|Request||
|Address inquiry locomotive at command station|Request||
|Delete locomotive from command station stack|Request||

### Following ROCONET extensions have been implemented:
 - Track power off: Short circuit


### TODOs:
 - Allow setting the accessory decoder address format (turnout, switching decoder, feedback module)
 - Handle other accessory decoders than switching decoders


