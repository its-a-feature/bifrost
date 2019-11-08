//
//  KerbOctetString.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#include "KerbOctetString.h"

@implementation KerbOctetString
    //type: 0x04
    NSData* KerbOctetvalue;
-(id)initWithValue:(NSData*)baseValue{
    if(self = [super init]){
        self.KerbOctetvalue = baseValue;
    }
    return self;
}
-(id)initWithObject:(ASN1_Obj*)baseObject{
    //given {"type": 0x02, "length": total_legnth, "data": NSData obj for actual bytes}
    if(self = [super init]){
        self.KerbOctetvalue = [[NSData alloc] initWithData:baseObject.data];
    }
    return self;
}
-(NSData*)collapseToNSData{
    return createCollapsedAsnBasicType(0x04, self.KerbOctetvalue).data;
}
-(ASN1_Obj*)collapseToAsnObject{
    return createCollapsedAsnBasicType(0x04, self.KerbOctetvalue);
}
-(NSString*)getHexValue{
    NSMutableString* val = [[NSMutableString alloc] initWithString:@""];
    for(int i = 0; i < self.KerbOctetvalue.length; i++){
        [val appendFormat:@"%02X", ((Byte*)self.KerbOctetvalue.bytes)[i]];
    }
    return [[NSString alloc] initWithString:val];
}
@end
