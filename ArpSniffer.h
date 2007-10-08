/* ArpSniffer */

#import <net/ethernet.h>
#import <Cocoa/Cocoa.h>


#if defined(DEBUG)
# define IFDEBUG(code)          code
#else
# define IFDEBUG(code)          /* no-op */
#endif

#define SNAPLEN 65535           /* maximum number of bytes captured */
#define READ_TIMEOUT 1 /* 500 */

#define ETHER_NTOA(a) (ether_ntoa((struct ether_addr *)&(a)))
#define INET_NTOA(a) (inet_ntoa(*(struct in_addr *)(&a)))

@interface ArpSniffer : NSObject
{
	bool active;
}

- (id)initialize:(NSString *)device;
- (void)startCapture:(id)controller;
- (void)stopCapture;

@end

#define IP_ADDR_LEN 4
struct arp_payload {
	u_char ar_sha[ETHER_ADDR_LEN];
	u_char ar_spa[IP_ADDR_LEN];
	u_char ar_tha[ETHER_ADDR_LEN];
	u_char ar_tpa[IP_ADDR_LEN];
};
