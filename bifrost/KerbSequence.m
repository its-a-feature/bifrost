//
//  KerbSequence.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KerbSequence.h"

@implementation KerbSequence
//type: 0x30
NSMutableArray<ASN1_Obj*> *sequence;
-(id)initWithEmpty{
    if(self = [super init]){
        self.sequence = [[NSMutableArray<ASN1_Obj*> alloc] init];
    }
    return self;
}
-(void)addNSData:(NSData*)data inSpot:(int)index{
    [self.sequence insertObject:[[ASN1_Obj alloc] initWithType:((Byte*)data.bytes)[0] Length:data.length Data:data] atIndex:index];
}
-(void)addAsn:(ASN1_Obj*)obj inSpot:(int)index{
    [self.sequence insertObject:obj atIndex:index];
}
-(void)addEmptyinSpot:(int)index{
    [self.sequence insertObject:[ASN1_Obj alloc] atIndex:index];
}
-(NSData*)collapseToNSData{
    return collapseAsnSequence(self.sequence).data;
}
-(ASN1_Obj*)collapseToAsnObject{
    return collapseAsnSequence(self.sequence);
}
@end
