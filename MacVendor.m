//
//  MacVendor.m
//  ArpSpyX

#import "MacVendor.h"
@implementation MacVendor

static NSDictionary *_vendors = nil;	//Dictionary
- (NSString *)vendorForMAC:(NSString*)MAC{
    NSString *aVendor;
	
    if (_vendors==Nil) { //the dictionary is cached for speed, but it needs to be loaded the first time
        _vendors = [[NSDictionary dictionaryWithContentsOfFile:[[[NSBundle bundleForClass:[MacVendor class]] resourcePath] stringByAppendingString:@"/macvendors.plist"]] retain];
		if (!_vendors) {
			NSLog(@"No vendors Database found!");
			return @"error";
		}
    }
	
    //do we have a valid MAC?
    if ((MAC==nil)||([MAC length]<5)) return @"";
    //see if we can find a most matching dictionary entry
	MAC = [MAC uppercaseString];
	aVendor = [_vendors objectForKey:MAC];
    if (aVendor == nil) {
        aVendor = [_vendors objectForKey:[MAC substringToIndex:8]];		
        if (aVendor == nil) {
            aVendor = [_vendors objectForKey:[MAC substringToIndex:7]];
            if (aVendor == nil) {
                aVendor = [_vendors objectForKey:[MAC substringToIndex:6]];
				if (aVendor == nil) {
					aVendor = [_vendors objectForKey:[MAC substringToIndex:5]];
					if (aVendor == nil) return @"unknown";
				}
            }
        }
    }
    return aVendor;
}
@end
