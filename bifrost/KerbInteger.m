//
//  KerbInteger.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KerbInteger.h"
@implementation KerbInteger
    //type: 0x02
    int KerbIntValue;
-(id)initWithValue:(int)baseValue{
    if(self = [super init]){
        self.KerbIntValue = baseValue;
    }
    return self;
}
-(id)initWithObject:(ASN1_Obj*)baseObject{
    //given {"type": 0x02, "length": total_legnth, "data": NSData obj for actual bytes}
    if(self = [super init]){
        self.KerbIntValue = 0;
        //Blob will have data of : 0x02 [NumOfBytes] [value]
        for(int i = 0; i < baseObject.data.length; i++){
            self.KerbIntValue <<= 8;
            self.KerbIntValue |= ((Byte*)baseObject.data.bytes)[i];
        }
    }
    return self;
}
-(NSData*)collapseToNSData{
    return createCollapsedAsnBasicType(0x02, minimizeAsnInteger(self.KerbIntValue)).data;
}
-(ASN1_Obj*)collapseToAsnObject{
    return createCollapsedAsnBasicType(0x02, minimizeAsnInteger(self.KerbIntValue));
}
@end
