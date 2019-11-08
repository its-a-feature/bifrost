//
//  KerbInteger.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//


#import "asn1.h"
@interface KerbInteger : NSObject
    //type: 0x02
    @property int KerbIntValue;
    -(id)initWithValue:(int)baseValue;
    -(id)initWithObject:(ASN1_Obj*)baseObject;
    -(NSData*)collapseToNSData;
    -(ASN1_Obj*)collapseToAsnObject;
@end


