//
//  KerbCNamePrincipal.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KerbCNamePrincipal.h"
#import "KerbSequence.h"

@implementation KerbCNamePrincipal
/* Format
 SEQUENCE (2 elem)          0x30 [length bytes]
     [0] (1 elem)           0xA0 [length bytes]
       INTEGER 1            0x02 [length bytes] [value] - KRB5-NT-PRINCIPAL
     [1] (1 elem)           0xA1 [length bytes]
       SEQUENCE (1 elem)    0x30 [length bytes]
         GeneralString      0x1B [length bytes] [value]
 */
KerbInteger* krb5_int_principal;
KerbGenericString* username;
-(id)initWithValueUsername:(NSString*)username{
    if(self = [super init]){
        self.krb5_int_principal = [[KerbInteger alloc] initWithValue:1];
        if(username == NULL){
            self.username = NULL;
        }else{
            self.username = [[KerbGenericString alloc] initWithValue:username];
        }
    }
    return self;
}
-(id)initWithObject:(ASN1_Obj*)baseObject{
    if(self = [super init]){
        //given an ASN1 blob of the above structure, parse out the necessary information
        //assuming that baseObject points to sequence
        ASN1_Obj* curBlob = getNextAsnBlob(baseObject); // gets 0xA0
        curBlob = getNextAsnBlob(baseObject); // gets 0x02
        self.krb5_int_principal = [[KerbInteger alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA1
        curBlob = getNextAsnBlob(baseObject); // gets sequence
        curBlob = getNextAsnBlob(baseObject); // gets the general string
        self.username = [[KerbGenericString alloc] initWithValue:getAsnGenericStringBlob(curBlob)];
    }
    return self;
}
-(NSData*)collapseToNSData{
    return [self collapseToAsnObject].data;
}
-(ASN1_Obj*)collapseToAsnObject{
    KerbSequence* sequence = [[KerbSequence alloc] initWithEmpty]; //empty sequence
    [sequence addAsn:[self.krb5_int_principal collapseToAsnObject] inSpot:0]; //insert krb5_int_val at spot 0
    if(self.username != NULL){
        ASN1_Obj* collapsedUsernameSequence = collapseAsnBasicType([[ASN1_Obj alloc] initWithType:0x30 Length:0x00 Data:[self.username collapseToNSData]]);
        [sequence addAsn:collapsedUsernameSequence inSpot:1];
    }else{
        
        ASN1_Obj* emptySeq = collapseAsnBasicType([[ASN1_Obj alloc] initWithType:0x30 Length:0x00 Data:NULL]);
        [sequence addAsn:emptySeq inSpot:1];
    }
    
    return [sequence collapseToAsnObject];
}
@end
