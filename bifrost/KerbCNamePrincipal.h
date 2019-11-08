//
//  KerbCNamePrincipal.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//
#import "KerbInteger.h"
#import "KerbGenericString.h"
#import "KerbSequence.h"
#import "asn1.h"

@interface KerbCNamePrincipal : NSObject
/* Format
 SEQUENCE (2 elem)          0x30 [length bytes]
     [0] (1 elem)           0xA0 [length bytes]
       INTEGER 1            0x02 [length bytes] [value] KRB5-NT-PRINCIPAL
     [1] (1 elem)           0xA1 [length bytes]
       SEQUENCE (1 elem)    0x30 [length bytes]
         GeneralString      0x1B [length bytes] [value]
 */
@property KerbInteger* krb5_int_principal;
@property KerbGenericString* username;
-(id)initWithValueUsername:(NSString*)username;
-(id)initWithObject:(ASN1_Obj*)baseObject;
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
@end

