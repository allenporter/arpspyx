//
//  MacVendor.h
//  ArpSpyX
/*
        File:			MacVendor.h
		Author:			Adi Luhung Suryadi aka hungmac <adiluhung@gmail.com>
		Description:	This Class returned a string value of the MAC Address Vendor
		Date:			8/17/08.
		
		Source of this program taken from KisMAC and have been modified to match the needs.
		KisMac Author(s):	Michael Rossberg, Michael Thole
		Souce Link:			http://code.google.com/p/kismac-ng
                

    This is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this file; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#import <Cocoa/Cocoa.h>


@interface MacVendor : NSObject {
}
- (NSString*) vendorForMAC:(NSString*)MAC;
@end
