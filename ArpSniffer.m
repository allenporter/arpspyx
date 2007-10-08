//
// ArpSpyX
// Author: Allen Porter allen@thebends.org
//
// ArpSniffer.m
//

#import <sys/types.h>
#import <unistd.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <net/ethernet.h>
#import <net/bpf.h>
#import <sys/socket.h>
#import <net/if_arp.h>
#import <pcap.h>
#import <Security/Authorization.h>
#import <Security/AuthorizationDB.h>
#import <Security/AuthorizationTags.h>

//#define DEBUG
#import "ArpSniffer.h"

@implementation ArpSniffer

// instance level handler for libpcap session
static pcap_t * handle = NULL;

//
// packetNtoh (private) - converts from network to host byte order for essential
// fields.
//
void
packetNtoh(struct ether_header *ethr_hdr, struct arphdr *arp_hdr)
{
	ethr_hdr->ether_type = ntohs(ethr_hdr->ether_type);
	arp_hdr->ar_hrd = ntohs(arp_hdr->ar_hrd);
	arp_hdr->ar_pro = ntohs(arp_hdr->ar_pro);
	arp_hdr->ar_op = ntohs(arp_hdr->ar_op);
	return;
}

//
// hasValidHeaders (private) - is this a valid packet that we know how to handle?
//
bool
hasValidHeaders(const struct ether_header * ethr_hdr,
					  const struct arphdr * arp_hdr)
{
	if (ethr_hdr->ether_type != ETHERTYPE_ARP)
	{
		IFDEBUG(fprintf(stderr, "Not an ARP packet! [Ether Type = 0x%x]\n",
						ethr_hdr->ether_type));
		return false;
	}
	if (arp_hdr->ar_hrd != ARPHRD_ETHER)
	{
		IFDEBUG(fprintf(stderr, "Not an Ethernet Packet! [Hardware = 0x%x]\n",
				arp_hdr->ar_hrd));
		return false;
	}
	if (arp_hdr->ar_pro != ETHERTYPE_IP)
	{
		IFDEBUG(fprintf(stderr, "Datagram type not IP [0x%x]\n",
				arp_hdr->ar_pro));
		return false;
	}
	if (arp_hdr->ar_hln != sizeof(struct ether_addr))
	{
		IFDEBUG(fprintf(stderr, "Unsupported Hardware Addr Len [0x%x]\n", 
				arp_hdr->ar_hln));
		return false;
	}
	if (arp_hdr->ar_pln != sizeof(struct in_addr))
	{
		IFDEBUG(fprintf(stderr, "Unsupported Protocol Addr Len [0x%x]\n",
				arp_hdr->ar_pln));
		return false;
	}
	if (arp_hdr->ar_op != ARPOP_REQUEST &&
		arp_hdr->ar_op != ARPOP_REPLY)
	{
		IFDEBUG(fprintf(stderr, "Unsupported operation [0x%x]\n",
				arp_hdr->ar_op));
		return false;
	}
	
	/* packet looks good! */
	return true;
}

//
// packetReceived (private) - called when a packet is received. headers are checked then
//			passed off to the ArpController.
//
void packetReceived(u_char * args, struct pcap_pkthdr * header, const u_char * packet)
{
	id controller = (id)args;
	struct ether_header * ethr_hdr;
	struct arphdr * arp_hdr;
	struct arp_payload * payload;
	
	/* split the packet into ethernet header, arp header, and
	 * arp payload that contains MAC and IP addresses of ARP 
	 * request
	 */
	ethr_hdr = (struct ether_header *)packet;
	arp_hdr = (struct arphdr *)(ethr_hdr + 1);
	payload = (struct arp_payload *)(arp_hdr + 1);
	
	/* convert packet to host byte order and validate that we can
	 * handle the packet
	 */
	packetNtoh(ethr_hdr, arp_hdr);
	if (!hasValidHeaders(ethr_hdr, arp_hdr)) {
		return;
	}
	
	IFDEBUG(printf("Ethernet Dest: %s ", ETHER_NTOA(ethr_hdr->ether_dhost)));
	IFDEBUG(printf("Source: %s\n", ETHER_NTOA(ethr_hdr->ether_shost)));
	
	if (arp_hdr->ar_op == ARPOP_REQUEST)
	{
		IFDEBUG(
				printf("Request from %s ", INET_NTOA(payload->ar_spa));
				printf("[%s] ", ETHER_NTOA(payload->ar_sha));
				printf("for %s ", INET_NTOA(payload->ar_tpa));
				printf("[%s]\n", ETHER_NTOA(payload->ar_tha));
				);

		// hand off the request to the ArpController
		[controller arpReceived:INET_NTOA(payload->ar_spa) macAddress:ETHER_NTOA(payload->ar_sha)];
	}
	else if (arp_hdr->ar_op == ARPOP_REPLY)
	{
		IFDEBUG(
				printf("Reply from %s ", INET_NTOA(payload->ar_spa));
				printf("[%s] ", ETHER_NTOA(payload->ar_sha));
				printf("to %s ", INET_NTOA(payload->ar_tpa));
				printf("[%s]\n", ETHER_NTOA(payload->ar_tha));
				);
		
		// hand off source and target in reply packet to ArpController
		[controller arpReceived:INET_NTOA(payload->ar_spa) macAddress:ETHER_NTOA(payload->ar_sha)];
		[controller arpReceived:INET_NTOA(payload->ar_tpa) macAddress:ETHER_NTOA(payload->ar_tha)];
	}

	return;
}

//
// applyFilter (private) - given a pcap handle and a device name, apply a filter so
// only arp packets are received.
//
void
applyFilter(pcap_t * handle, char * device)
{
	char filter[] = "arp";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program bpf;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct in_addr addr;
	
	// get the network and netmask
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
	{
		NSString * errorString = [[NSString alloc] initWithCString:errbuf];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}
	
	// make sure the network is valid
	addr.s_addr = net;
	if (inet_ntoa(addr) == NULL)
	{
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:@"Invalid Network"
													   userInfo:nil];
		@throw exception;	
	}
	
	// make sure the netmask is valid
	addr.s_addr = mask;
	if (inet_ntoa(addr) == NULL)
	{
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:@"Invalid Netmask"
													   userInfo:nil];
		@throw exception;	
	}
	
	// apply the arp filter
	pcap_compile(handle, &bpf, filter, 0, net);
	pcap_setfilter(handle, &bpf);
	
	return;
}

//
// stopCapture - disable sniffing in the capture thread and release the pcap handle
//
- (void)stopCapture
{
	IFDEBUG(printf("stopCapture(): Stopping...\n"));
			
	// stop the main sniffer loop
	active = false;

	// give enough time for the main thread to close, 5 times the normal packet timeout amount
	usleep(5000);
	
	// clean up and close the pcap handle
	pcap_close(handle);
}

//
// startCapture - start listening for arp packets on an already opened pcap session. this function
//		should will block and should be started in its own thread. a call to stopCapture will close
//		force the thread to quit by making this function return.
//
- (void)startCapture:(id)controller
{
	// make sure we have a valid existing session
	if (handle == NULL)
	{
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:@"pcap not initialized"
													   userInfo:nil];
		@throw exception;
	}

	// loop until stopCapture is called
	active = true;	
	while (active)
	{
		// check for a packet
		int ret = pcap_dispatch(handle, 1, (pcap_handler)packetReceived, (u_char *)controller);
		if (ret < 0)
		{
			// device error occurred so throw an exception
			// TODO - is this ever handled? since its in its own thread, i dont think so
			NSException *exception = [NSException exceptionWithName:@"DeviceException"
															 reason:@"Read error occurred"
														   userInfo:nil];
			@throw exception;
		}
		else if (ret == 0)
		{
			// timeout occurred, so sleep and try again
			usleep(1000);
		}
	}

	// run when stopCapture is called
	IFDEBUG(printf("startCapture(): Exiting Loop!!\n"));
}

//
// initialize - start a pcap session.
//
- (id)initialize:(NSString *)device
{
	// convert NSString to C string for use with pcap
	char * dev = strdup((const char *)[device cString]);
	
	char errbuf[PCAP_ERRBUF_SIZE];

	IFDEBUG(printf("initialize(): Opening PCAP\n"));

	// open pcap!
	handle = pcap_open_live(dev, SNAPLEN, 1, READ_TIMEOUT, errbuf);
	if (handle == NULL)
	{
		NSString * errorString = [[NSString alloc] initWithCString:errbuf];
		NSException *exception = [NSException exceptionWithName:@"DeviceException"
														 reason:errorString
													   userInfo:nil];
		@throw exception;
	}

	// restrict this device to just ARP traffic
	applyFilter(handle, dev);
	
	// return a refernce to this object
	return self;
}

@end