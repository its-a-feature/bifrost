//
//  KerbGenericString.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//
#import <Foundation/Foundation.h>
#import "asn1.h"
@interface KerbGenericString : NSObject
//type: 0x1B
@property NSString* KerbGenStringvalue;
-(id)initWithValue:(NSString*)baseValue;
-(id)initWithObject:(ASN1_Obj*)baseObject;
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
@end

