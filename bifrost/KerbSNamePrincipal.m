//
//  KerbSNamePrincipal.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#include "KerbSNamePrincipal.h"

@implementation KerbSNamePrincipal
/* Format
 SEQUENCE (2 elem)                  0x30 [length bytes]
     [0] (1 elem)                   0xA0 [length bytes]
       INTEGER 2 krb5-nt-srv-inst   0x02 [length bytes] [value]
     [1] (1 elem)                   0xA1 [length bytes]
       SEQUENCE (2 elem)            0x30 [length bytes]
         GeneralString (krbtgt)     0x1B [length bytes] [value]
         GeneralString (domain)     0x1B [length bytes] [value]
 */
KerbInteger* krb5_nt_srv_inst; //ex: 2
KerbGenericString* account; //ex: krbtgt
KerbGenericString* domain; //ex: domain.com
-(id)initWithValueAccount:(NSString*)account Domain:(NSString*)domain{
    if(self = [super init]){
        self.krb5_nt_srv_inst = [[KerbInteger alloc] initWithValue:2];
        self.account = [[KerbGenericString alloc] initWithValue:account];
        self.domain = [[KerbGenericString alloc] initWithValue:domain];
    }
    return self;
}
-(id)initWithObject:(ASN1_Obj*)baseObject{
    if(self = [super init]){
        //given an ASN1 blob of the above structure, parse out the necessary information
        //assuming that baseObject points to sequence
        ASN1_Obj* curBlob = getNextAsnBlob(baseObject); // gets 0xA0
        curBlob = getNextAsnBlob(baseObject); // gets 0x02
        self.krb5_nt_srv_inst = [[KerbInteger alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA1
        curBlob = getNextAsnBlob(baseObject); // gets sequence
        curBlob = getNextAsnBlob(baseObject); // gets the general string
        self.account = [[KerbGenericString alloc] initWithValue:getAsnGenericStringBlob(curBlob)];
        if(baseObject.data.length != 0){
            curBlob = getNextAsnBlob(baseObject); // gets the general string
            self.domain = [[KerbGenericString alloc] initWithValue:getAsnGenericStringBlob(curBlob)];
        }else{
            self.domain = NULL;
        }
        
    }
    return self;
}
-(NSData*)collapseToNSData{
    return [self collapseToAsnObject].data;
}
-(ASN1_Obj*)collapseToAsnObject{
    NSData* collapsedPrin1Prin2;
    if(self.domain != NULL){
        collapsedPrin1Prin2 = appendAsnObj([self.account collapseToAsnObject], [self.domain collapseToAsnObject]);
    }else{
        collapsedPrin1Prin2 = [self.account collapseToNSData];
    }
    
    ASN1_Obj* collapsedPrin1Prin2Sequence = collapseAsnBasicType([[ASN1_Obj alloc] initWithType:0x30 Length:0x00 Data:collapsedPrin1Prin2]);
    KerbSequence* sequence = [[KerbSequence alloc] initWithEmpty];
    [sequence addAsn:[self.krb5_nt_srv_inst collapseToAsnObject] inSpot:0];
    [sequence addAsn:collapsedPrin1Prin2Sequence inSpot:1];
    return [sequence collapseToAsnObject];
}
-(NSString*)getNSString{
    NSMutableString* output = [[NSMutableString alloc] initWithString:self.account.KerbGenStringvalue];
    if(self.domain != NULL){
        [output appendFormat:@"/%s", self.domain.KerbGenStringvalue.UTF8String];
    }
    return output;
}
@end
