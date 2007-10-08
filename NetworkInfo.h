/* NetworkInfo */

#import <stdlib.h>
#import <sys/types.h>
#import <netinet/in.h>
#import <netinet/in_systm.h>
#import <netinet/ip.h>
#import <net/if.h>
#import <net/bpf.h>
#import <net/ethernet.h>
#import <net/route.h>
#import <net/if_dl.h>
#import <net/if_types.h>
#import <Cocoa/Cocoa.h>

@interface DeviceInfo : NSObject
{
	@public
	NSString * name;
	bool valid;
	struct ether_addr mac;
	struct in_addr ip;
	struct in_addr net;
	struct in_addr mask;
}
@end

@interface NetworkInfo : NSObject
{
	IBOutlet NSButton *buttonCancel;
	IBOutlet NSTextField *network;
	IBOutlet NSTextField *netmask;
	IBOutlet NSTextField *currentIP;
	IBOutlet NSWindow *scanPanel;
	IBOutlet NSProgressIndicator *progressBar;
}
- (IBAction)	pressCancel:(id)sender;
- (NSArray *) networkDevices;
- (void)		sendArpScan:(DeviceInfo *)deviceInfo;
- (void) lookupNetworkDevice:(char *)device
				   ipAddress:(bpf_u_int32 *)ip
			  networkAddress:(bpf_u_int32 *)net
					 netmask:(bpf_u_int32 *)mask;
@end