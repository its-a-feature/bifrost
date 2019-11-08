//
//  KerbGeneralizedTime.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//
#import "asn1.h"
@interface KerbGeneralizedTime: NSObject
//type: 0x18
@property NSString* value;
-(id)initWithValue:(NSString*)baseValue;
-(id)initWithTimeNow;
-(id)initWithTimeOffset:(int)daysOffset;
-(id)initWithObject:(ASN1_Obj*)baseObject;
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
-(NSString*)printTimeUTC;
@end

