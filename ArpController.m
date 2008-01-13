#import <stdio.h>
#import <sys/types.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import "AppKit/NSProgressIndicator.h"
#import "AppKit/NSTableView.h"
#import "ArpSniffer.h"
#import "NetworkInfo.h"
#import "ArpController.h"

// Adds extended network devices
//#define EXTENDED_DEVIVES

@implementation ArpController

NSLock * arpLock = nil;
NSImage * upSortImage = nil;
NSImage * downSortImage = nil;
NSString * currentSortedColumn = @"";
bool upSort = true;
bool sniffing = false;
NSArray * deviceList = nil;

NSComparisonResult compareIPAddress(NSString * ipstring1, NSString * ipstring2)
{
	const char * ipch1 = [ipstring1 cString];
	const char * ipch2 = [ipstring2 cString];
	struct in_addr ip1, ip2;
	
	inet_aton(ipch1, &ip1);
	inet_aton(ipch2, &ip2);
	
	if (ip1.s_addr > ip2.s_addr)
		return NSOrderedDescending;
	else if (ip1.s_addr == ip2.s_addr)
		return NSOrderedSame;
	else
		return NSOrderedAscending;
}

int sortDictArray(id dict1, id dict2, void *context)
{
	NSString * columnName = (NSString *)context;
	NSDictionary * arpEntry1 = (NSDictionary *)dict1;
	NSDictionary * arpEntry2 = (NSDictionary *)dict2;
	
	if (!([columnName isEqualToString:@"IP Address"] ||
		  [columnName isEqualToString:@"MAC Address"]))
		return NSOrderedSame;
	
	NSString * string1 = [arpEntry1 objectForKey:columnName];
	NSString * string2 = [arpEntry2 objectForKey:columnName];
	
	if ([columnName isEqualToString:@"IP Address"])
	{
		if (upSort)
			return compareIPAddress(string1, string2);
		else
			return compareIPAddress(string2, string1);
	}
	else if ([columnName isEqualToString:@"MAC Address"])
	{
		if (upSort)
			return [string1 compare:string2];
		else
			return [string2 compare:string1];
	}
	else
		return NSOrderedSame;
}

// clear the arp cache and refresh the screen
- (IBAction) deviceSelected:(id)sender
{	
	DeviceInfo * deviceInfo;
	
	if (sniffing)
	{
		[arpSniffer stopCapture];
		[arpSniffer release];
		sniffing = false;
	}
	
	[scanLabel setHidden:true];
	[progress stopAnimation:progress];
	[progress setHidden:true];
	[buttonScan setEnabled:false];

	// clear all existing items in display
	[arpLock lock];
	[arplist removeAllObjects];
	[arpLock unlock];
	[table reloadData];
	
	// get the current selected device
	deviceInfo = [deviceList objectAtIndex:[devices indexOfSelectedItem]];
	
	@try
	{
		arpSniffer = [[ArpSniffer alloc] initialize:deviceInfo->name];
	}
	@catch (NSException * ex)
	{
		NSAlert * alert;
		NSRange permissionRange = [[ex reason] rangeOfString:@"Permission"];
		if (permissionRange.length > 0)
		{
			alert = [NSAlert alertWithMessageText:[ex reason]
									defaultButton:@"OK"
								  alternateButton:@"Try Again"
									  otherButton:nil
						informativeTextWithFormat:@"In order to use this application you must "
									"issue the following command at a terminal prompt:\n\n"
									"sudo chmod 777 /dev/bpf*"];
		}
		else
		{
			alert = [NSAlert alertWithMessageText:@"Error opening network device"
										  defaultButton:@"OK"
										alternateButton:@"Try Again"
											otherButton:nil
							  informativeTextWithFormat:[ex reason]];
		}
		
		// should we try again?
		if ([alert runModal] != NSOKButton)
			[self deviceSelected:self];
		return;
	}
	sniffing = true;
	
	// start the sniffer thread
	[NSThread detachNewThreadSelector: @selector(startCapture:)
							 toTarget: arpSniffer withObject: self];
	
	[scanLabel setHidden:false];
	[progress startAnimation:progress];
	[progress setHidden:false];
	[buttonScan setEnabled:true];
	
	return;
}

- (void) initDeviceList
{
	int i;
	
	// clear the list of devices,
	[devices removeAllItems];
	@try
	{
		deviceList = [netInfo networkDevices];
	}
	@catch (NSException * ex)
	{
		NSAlert * alert = [NSAlert alertWithMessageText:@"Error locating network devices"
										  defaultButton:@"OK"
										alternateButton:nil
											otherButton:nil
							  informativeTextWithFormat:[ex reason]];
		[alert runModal];
		return;
	}
	
	int bestItemIndex = 0;
	// iterate through each device, pick first interface with an IP
	for (i = 0; i < [deviceList count]; i++)
	{
		DeviceInfo * deviceInfo = [deviceList objectAtIndex:i];
		NSString * label = [[NSString alloc] initWithFormat:@"%s (%s)",
			[deviceInfo->name cString],
			inet_ntoa(deviceInfo->ip)
			];
		[devices addItemWithTitle:label];
		
		// if the device has a valid IP then 
		if (deviceInfo->ip.s_addr != 0)
			bestItemIndex = i;
	}
	[devices selectItemAtIndex:bestItemIndex];
}

// message called at startup time
- (void) awakeFromNib
{	
	if ([[NSTableView class] respondsToSelector: @selector(_defaultTableHeaderSortImage)]) 
		upSortImage = [[NSTableView class] _defaultTableHeaderSortImage];
	else
		upSortImage = nil;
	if ([[NSTableView class] respondsToSelector: @selector(_defaultTableHeaderReverseSortImage)]) 
		downSortImage = [[NSTableView class] _defaultTableHeaderReverseSortImage];
	else
		downSortImage = nil;

	[scanLabel setHidden:true];
	[progress stopAnimation:progress];
	[progress setHidden:true];
	[buttonScan setEnabled:false];
	
	[self initDeviceList];
	
	// initialize the lock object, used for access to arplist array
	arpLock = [[NSConditionLock alloc] init];

	// init array with starting space of 30, should be decent i imagine
	arplist = [[NSMutableArray alloc] initWithCapacity:30];	

	// enable sniffing on the selected device
	[self deviceSelected:devices];
}

// message called at quit time
- (void) applicationWillTerminate:(NSNotification *)notification
{
	// release objects
	[arpLock release];
	[arpSniffer stopCapture];
	[arpSniffer release];
	[arplist release];
}

- (IBAction) menuExport: (id)sender
{
	NSSavePanel * saveDialog = [NSSavePanel savePanel];
	[saveDialog setRequiredFileType:@""];
	[saveDialog setTitle:@"Export to Text File"];

	if ([saveDialog runModal] != NSOKButton)
		return;

	const char * fullPath = [[saveDialog filename] cString];
	FILE * handle = fopen ( fullPath, "w" );
	if (handle == NULL)
		return;
	
	// iterate through the existing arp cache
	int i;
	for (i = 0; i < [arplist count]; i++)
	{
		NSDictionary * item = [arplist objectAtIndex:i];
		NSString * ip = [item objectForKey:@"IP Address"];
		NSString * mac = [item objectForKey:@"MAC Address"];

		fprintf(handle, "%s\t%s\n", [ip cString], [mac cString]);
	}
	fclose(handle);
}

// clear the arp cache and refresh the screen
- (IBAction) pressButtonClear:(id)sender
{
	[arpLock lock];
	[arplist removeAllObjects];
	[arpLock unlock];
	
	[table reloadData];
	
	return;
}

// perform an active scan by sending ARP packets all over the network
- (IBAction) pressButtonScan:(id)sender
{
	DeviceInfo * deviceInfo = [deviceList objectAtIndex:[devices indexOfSelectedItem]];
	@try
	{
		[netInfo sendArpScan:deviceInfo];
	}
	@catch (NSException * ex)
	{
		NSAlert * alert;
		NSRange permissionRange = [[ex reason] rangeOfString:@"Permission"];
		if (permissionRange.length > 0)
		{
			alert = [NSAlert alertWithMessageText:[ex reason]
									defaultButton:@"OK"
								  alternateButton:@"Try Again"
									  otherButton:nil
						informativeTextWithFormat:@"In order to use this application you must "
									"issue the following command at a terminal prompt:\n\n"
									"sudo chmod 777 /dev/bpf*"];
		}
		else
		{
			alert = [NSAlert alertWithMessageText:@"Error opening network device"
										  defaultButton:@"OK"
										alternateButton:@"Try Again"
											otherButton:nil
							  informativeTextWithFormat:[ex reason]];
		}
		// should we try again?
		if ([alert runModal] != NSOKButton) {
			[self pressButtonScan:self];
			return;
	    }
	}
	[table reloadData];
	
	return;
}


// incoming arp request received
- (void)arpReceived:(char *)ipAddress macAddress:(char *)macAddress;
{
	NSString * keys[2];
	NSString * values[2];
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	
	keys[0] = @"IP Address";
	values[0] = [NSString stringWithFormat:@"%s", ipAddress];
		
	keys[1] = @"MAC Address";
	values[1] = [NSString stringWithFormat:@"%s", macAddress];
	
	NSDictionary * entry = [NSDictionary dictionaryWithObjects:(id *)values
													   forKeys:(id *)keys count:2];

	// iterate through the existing arp cache, look for duplicate entries
	int i;
	for (i = 0; i < [arplist count]; i++)
	{
		NSDictionary * item = [arplist objectAtIndex:i];
		NSString * ip = [item objectForKey:@"IP Address"];
		NSString * mac = [item objectForKey:@"MAC Address"];
		
		if ([ip isEqualToString:values[0]] && [mac isEqualToString:values[1]])
		{
			// duplicate entry found, bail out
			return;
		}
		else if ([ip isEqualToString:values[0]] || [mac isEqualToString:values[1]])
		{
			// we have a change in matchup between IP and MAC
			// TODO - notify? color?
			// ignore for now.
		}
	}
	
	[arpLock lock];
	[arplist addObject: entry];
	[arplist sortUsingFunction:(int (*)(id, id, void *))(sortDictArray)
					   context:currentSortedColumn];
	[arpLock unlock];
	
	[table reloadData];
	[pool release];
	
	return;
}

// TABLE DATA SOURCE
- (int) numberOfRowsInTableView: (NSTableView *)table
{
	[arpLock lock];
	int count = [arplist count];
	[arpLock unlock];

	// returns number of items in array
	return count;
}

- (void)            tableView: (NSTableView *) aTableView
              willDisplayCell: (id) aCell
			   forTableColumn: (NSTableColumn *) aTableColumn
			              row: (int) rowIndex
{


}


// this message is called for each row of the table
- (id)				tableView: (NSTableView *) tableView
	objectValueForTableColumn: (NSTableColumn*) tableColumn
						  row: (int) rowIndex
{
	NSDictionary * rowData;

	[arpLock lock];
	rowData = [arplist objectAtIndex:rowIndex];
	[arpLock unlock];
	
	return [rowData objectForKey:[tableColumn identifier]];
}

- (void) tableView:(NSTableView*)tableView didClickTableColumn:(NSTableColumn *)tableColumn;
{	
	NSString * columnName = [tableColumn identifier];
	
	// check to see if this column was already the selected one and if so invert the sort function.Ê Ê
	if ([currentSortedColumn isEqualToString:columnName])
	{
		if (upSort)
			upSort = false;
		else
			upSort = true;
	}
	else
	{
		// if there already was a sorted column, remove the indicator image from it.
		[tableView setIndicatorImage:nil
					   inTableColumn:[tableView tableColumnWithIdentifier:currentSortedColumn]];
		upSort = true;
	}

	// set the highlight+indicator image in the newly selected column
	[tableView setHighlightedTableColumn:tableColumn];      
	if (upSort)
		[tableView setIndicatorImage:upSortImage inTableColumn:tableColumn];
	else
		[tableView setIndicatorImage:downSortImage inTableColumn:tableColumn];
	
	currentSortedColumn = columnName; 

	[arpLock lock];
	[arplist sortUsingFunction:(int (*)(id, id, void *))(sortDictArray)
					   context:currentSortedColumn];
	[arpLock unlock];
	
	[tableView reloadData];
}

@end