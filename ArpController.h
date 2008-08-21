/* ArpController */

#import <Cocoa/Cocoa.h>
#import "MacVendor.h"

@interface ArpController : NSObject
{
    IBOutlet NSButton *buttonClear;
	IBOutlet NSButton *buttonScan;
    IBOutlet NSTableView *table;
	IBOutlet NSPopUpButton *devices;
	IBOutlet NSProgressIndicator *progress;
	NSMutableArray *arplist;
	ArpSniffer *arpSniffer;
	IBOutlet NetworkInfo *netInfo;
	IBOutlet NSTextField *scanLabel;
	MacVendor *macvendor;
}

- (void)			arpReceived: (char *)ipAddress
					 macAddress: (char *)macAddress;
- (IBAction)   pressButtonClear: (id)sender;
- (IBAction)	pressButtonScan: (id)sender;
- (IBAction)	 deviceSelected: (id)sender;
- (IBAction)		 menuExport: (id)sender;
- (int) numberOfRowsInTableView: (NSTableView *) table;
- (id)				  tableView: (NSTableView *) tableView
	  objectValueForTableColumn: (NSTableColumn*) tableColumn
							row: (int) rowIndex;
- (void)			  tableView: (NSTableView *) tableView
			didClickTableColumn: (NSTableColumn *) tableColumn;

@end