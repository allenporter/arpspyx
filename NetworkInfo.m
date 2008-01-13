#import <stdio.h>
#import <stdlib.h>
#import <sys/fcntl.h>
#import <sys/ioctl.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/uio.h>
#import <unistd.h>
#import <string.h>
#import <errno.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <net/if.h>
#import <net/bpf.h>
#import <net/ethernet.h>
#import <net/if_arp.h>
#import <arpa/inet.h>
#import <pcap.h>
#import <AppKit/NSApplication.h>
#import "NetworkInfo.h"
#import "ArpSniffer.h"

@implementation DeviceInfo
@end

@implementation NetworkInfo

u_char broadcast_ha[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
u_char empty_ha[ETHER_ADDR_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x0 };
bool scanning = false;

- (void) awakeFromNib
{	
// word!
	printf("Awake!\n");
}


// open bpf for writing
int bpf_open()
{
	int i, fd;
	char device[sizeof "/dev/bpf000"];
	
	for (i = 0;;i++)
	{
		sprintf(device, "/dev/bpf%d", i);
		
		fd = open(device, O_RDWR);
		if (fd == -1 && errno == EBUSY)
			continue;
		else
			break;
	}
	
	if (fd == -1)
	{
		NSString * errorString = [[NSString alloc] initWithFormat:@"%s(): open(): (%s): %s\n",
									__func__, device, strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}

	return fd;
}

void
bpf_init(int fd, DeviceInfo* deviceInfo)
{
	char * device = (char *)[deviceInfo->name cString];
	struct ifreq ifr;
	
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);
	
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
	if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) == -1)
	{
		NSString * errorString = [[NSString alloc] initWithFormat:@"%s(): BIOCSETIF: (%s): %s\n",
			__func__, device, strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
	
	if (ioctl(fd, BIOCGDLT, (caddr_t)&ifr) == -1)
	{
		NSString * errorString = [[NSString alloc] initWithFormat:@"%s(): BIOCGDLT: (%s): %s\n",
			__func__, device, strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
}

// send arp requests to the entire network connected to the device
- (void) sendArpScan:(DeviceInfo *)deviceInfo
{
	int fd, c;
	int i, j, k, l;
	struct ether_header * eth;
	struct arphdr * arp_header;
	struct arp_payload * payload;
	u_char * mask = (u_char *)&deviceInfo->mask.s_addr;
	u_char * net = (u_char *)&deviceInfo->net.s_addr;
	u_char * packet;
	int packet_len;
	u_char tpa[IP_ADDR_LEN] = { 0, 0, 0, 0 };				// storage for target address

	// set defaults
	[progressBar startAnimation:progressBar];
	[network setTitleWithMnemonic:[[NSString alloc] initWithCString:inet_ntoa(deviceInfo->net)]];
	[netmask setTitleWithMnemonic:[[NSString alloc] initWithCString:inet_ntoa(deviceInfo->mask)]];
	[currentIP setTitleWithMnemonic:@""];
	[progressBar setHidden:false];
	scanning = true;
	
	NSModalSession session = [NSApp beginModalSessionForWindow:scanPanel];	
	
	// allocate storage space for a sngle packet
	packet_len = sizeof(struct arp_payload) + sizeof(struct arphdr) +
		sizeof(struct ether_header);
	packet = malloc(packet_len);
	
	// set pointeres to appropriate places in header
	eth = (struct ether_header *)packet;
	arp_header = (struct arphdr *)(eth + 1);
	payload = (struct arp_payload *)(arp_header + 1);
	
	// set arp header values
	arp_header->ar_hrd = ntohs(ARPHRD_ETHER);
	arp_header->ar_pro = ntohs(ETHERTYPE_IP);
	arp_header->ar_hln = ETHER_ADDR_LEN;
	arp_header->ar_pln = IP_ADDR_LEN;
	arp_header->ar_op = ntohs(ARPOP_REQUEST);
	
	// set ethernet payload
	memcpy(eth->ether_dhost, broadcast_ha, ETHER_ADDR_LEN);	
	memcpy(eth->ether_shost, &deviceInfo->mac, ETHER_ADDR_LEN);
	eth->ether_type = ntohs(ETHERTYPE_ARP);
	
	// set arp payload except for target IP address
	memcpy(payload->ar_sha, &deviceInfo->mac, ETHER_ADDR_LEN);
	memcpy(payload->ar_spa, &deviceInfo->ip, IP_ADDR_LEN);
	memcpy(payload->ar_tha, empty_ha, ETHER_ADDR_LEN);
	
	// initlize bpf sdevice
	@try
	{
		fd = bpf_open();
		bpf_init(fd, deviceInfo);
	
		for (i = 0; i <= 255-mask[0]; i++)
		{
			tpa[0] = net[0] + i;
			for (j = 0; j <= 255-mask[1]; j++)
			{
				tpa[1] = net[1] + j;
				for (k = 0; k <= 255-mask[2]; k++)
				{
					tpa[2] = net[2] + k;
					for (l = 0; l <= 255-mask[3]; l++)
					{
						if (!scanning)
							goto SCAN_DONE;
					
						// set the protocol address
						tpa[3] = net[3] + l;
						memcpy(payload->ar_tpa, tpa, 4);

						// update dialog box
						[currentIP setTitleWithMnemonic:[[NSString alloc]
										initWithCString:inet_ntoa(*(struct in_addr *)tpa)]];

						// write the packet!
						c = write(fd, packet, packet_len);
						if (c != packet_len)
						{
							fprintf(stderr, "%s(): %d bytes written (%s)\n",
									__func__, c, strerror(errno));
						}
					
						// let dialog events run
						[NSApp runModalSession:session];
						usleep(100000);
					}
				}
			}
		}
SCAN_DONE:
		;
	}
	@finally
	{
		close(fd);
		scanning = false;
	
		[NSApp endModalSession:session];
		[scanPanel close];
	}
}

- (void) lookupNetworkDevice:(char *)device
			     ipAddress:(bpf_u_int32 *)ip
			networkAddress:(bpf_u_int32 *)net
				   netmask:(bpf_u_int32 *)mask
{
	int fd;
	struct sockaddr_in *sin;
	struct ifreq ifr;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
	{
		NSString * errorString = [[NSString alloc] initWithCString:strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
	memset(&ifr, 0, sizeof(ifr));
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	(void)strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	
	if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) < 0)
	{
		(void)close(fd);
		NSString * errorString = [[NSString alloc] initWithCString:strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
	*ip = sin->sin_addr.s_addr;
	*net = sin->sin_addr.s_addr;
	if (ioctl(fd, SIOCGIFNETMASK, (char *)&ifr) < 0)
	{
		(void)close(fd);
		NSString * errorString = [[NSString alloc] initWithCString:strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
	(void)close(fd);	
	*mask = sin->sin_addr.s_addr;
	if (*mask == 0)
	{
		if (IN_CLASSA(*net))
			*mask = IN_CLASSA_NET;
		else if (IN_CLASSB(*net))
			*mask = IN_CLASSB_NET;	 
		else if (IN_CLASSC(*net))
			*mask = IN_CLASSC_NET;
		else
		{
			NSException *exception = [NSException exceptionWithName:@"DeviceException"
															 reason:@"Class unknown"
														   userInfo:nil];
			@throw exception;
		}
				
	}
	*net &= *mask;
	return;
}

// use sysctl to obtain a list of ethernet devices
- (NSArray *) networkDevices
{
	NSMutableArray * devices = [[NSMutableArray alloc] init];
	int mib[6];
	size_t len;
	int8_t *buf, *next, *end;
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;
	/* for pcap_lookupnet */
	
	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_LINK;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;
	
	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1)
	{
		NSString * errorString = [[NSString alloc] initWithCString:strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
	
	buf = (char *)malloc(len);
	if (buf == NULL)
	{
		NSString * errorString = [[NSString alloc] initWithCString:strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"MallocException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
	
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1)
	{
		NSString * errorString = [[NSString alloc] initWithCString:strerror(errno)];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
	end = buf + len;
	
	// iterate through each returned structure from the sysctl
	for (next = buf; next < end; next += ifm->ifm_msglen)
	{
		char device_buf[64];

		ifm = (struct if_msghdr *)next;
		if (ifm->ifm_type != RTM_IFINFO)
			continue;

		// make sure this is a valid ethernet device of appropriate length
		sdl = (struct sockaddr_dl *)(ifm + 1);
		if (sdl->sdl_nlen > 64 || sdl->sdl_type != IFT_ETHER)
			continue;
		
		// copy device name to a temporary string
		strncpy(device_buf, sdl->sdl_data, sdl->sdl_nlen);
		device_buf[sdl->sdl_nlen] = NULL;

		// add device to the device list
		DeviceInfo * deviceInfo = [[DeviceInfo alloc] init];
		deviceInfo->name = [[NSString alloc] initWithCString:device_buf];
		memcpy(deviceInfo->mac.octet, LLADDR(sdl), ETHER_ADDR_LEN);
		
		// TODO - this information is probably located in the ifm structure, but
		// that will require more reading
		
		// attempt to get netmask and network from device. if unable to do so,
		// mark device as invalid
		@try
		{
			[self lookupNetworkDevice:(char *)device_buf
							ipAddress:(bpf_u_int32 *)&deviceInfo->ip
					   networkAddress:(bpf_u_int32 *)&deviceInfo->net
							  netmask:(bpf_u_int32 *)&deviceInfo->mask];
			deviceInfo->valid = true;
		}
		@catch (NSException * ex)
		{
			deviceInfo->valid = false;
		}
		[devices addObject:deviceInfo];
	}
	
	return devices;
}

// clear the arp cache and refresh the screen
- (IBAction) pressCancel:(id)sender
{
	scanning = false;
	return;
}

@end
