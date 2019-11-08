//
//  KerbBitString.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KerbBitString.h"


@implementation KerbBitString
//type: 0x03
int KerbBitValue;
-(id)initWithValue:(int)baseValue{
    if(self = [super init]){
        self.KerbBitValue = baseValue;
    }
    return self;
}
-(id)initWithObject:(ASN1_Obj*)baseObject{
    if(self = [super init]){
        Byte* val = (Byte*)baseObject.data.bytes + 1; // move past the leading zero
        int network = *((int*)val);
        self.KerbBitValue = ntohl(network);
    }
    return self;
}
-(NSData*)collapseToNSData{
    return createCollapsedAsnBasicType(0x03, createAsnBitString(self.KerbBitValue)).data;
}
-(ASN1_Obj*)collapseToAsnObject{
    return createCollapsedAsnBasicType(0x03, createAsnBitString(self.KerbBitValue));
}
@end
