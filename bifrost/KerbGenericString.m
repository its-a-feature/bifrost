//
//  KerbGenericString.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#include "KerbGenericString.h"

@implementation KerbGenericString
//type: 0x1B
NSString* KerbGenStringvalue;
-(id)initWithValue:(NSString*)baseValue{
    if(self = [super init]){
        self.KerbGenStringvalue = baseValue;
    }
    return self;
}
-(id)initWithObject:(ASN1_Obj*)baseObject{
    if(self = [super init]){
        self.KerbGenStringvalue = [[NSString alloc] initWithBytes:(Byte*)baseObject.data.bytes length:baseObject.data.length encoding:NSUTF8StringEncoding];
    }
    return self;
}
-(NSData*)collapseToNSData{
    return createCollapsedAsnBasicType(0x1B, [[NSData alloc] initWithBytes:self.KerbGenStringvalue.UTF8String length:self.KerbGenStringvalue.length]).data;
}
-(ASN1_Obj*)collapseToAsnObject{
    return createCollapsedAsnBasicType(0x1B, [[NSData alloc] initWithBytes:self.KerbGenStringvalue.UTF8String length:self.KerbGenStringvalue.length]);
}
@end
