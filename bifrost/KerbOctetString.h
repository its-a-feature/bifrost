//
//  KerbOctetString.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//
#import <Foundation/Foundation.h>
#import "asn1.h"
@interface KerbOctetString : NSObject
    //type: 0x04
@property NSData* KerbOctetvalue;
-(id)initWithValue:(NSData*)baseValue;
-(id)initWithObject:(ASN1_Obj*)baseObject;
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
-(NSString*)getHexValue;
@end

