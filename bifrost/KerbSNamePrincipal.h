//
//  KerbSNamePrincipal.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//
#import "KerbInteger.h"
#import "KerbGenericString.h"
#import "KerbSequence.h"
#import "asn1.h"

@interface KerbSNamePrincipal : NSObject
/* Format
 SEQUENCE (2 elem)                  0x30 [length bytes]
     [0] (1 elem)                   0xA0 [length bytes]
       INTEGER 2 krb5-nt-srv-inst   0x02 [length bytes] [value]
     [1] (1 elem)                   0xA1 [length bytes]
       SEQUENCE (2 elem)            0x30 [length bytes]
         GeneralString (krbtgt)     0x1B [length bytes] [value]
         GeneralString (domain)     0x1B [length bytes] [value]
 */
@property KerbInteger* krb5_nt_srv_inst; //ex: 2
@property KerbGenericString* account; //ex: krbtgt
@property KerbGenericString* domain; //ex: domain.com
-(id)initWithValueAccount:(NSString*)account Domain:(NSString*)domain;
-(id)initWithObject:(ASN1_Obj*)baseObject;
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
-(NSString*)getNSString;
@end
