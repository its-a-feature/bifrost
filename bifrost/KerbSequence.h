//
//  KerbSequence.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import "asn1.h"

@interface KerbSequence : NSObject
//type: 0x30
@property NSMutableArray<ASN1_Obj*> *sequence;
-(id)initWithEmpty;
-(void)addNSData:(NSData*)data inSpot:(int)index;
-(void)addAsn:(ASN1_Obj*)obj inSpot:(int)index;
-(void)addEmptyinSpot:(int)index;
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
@end

