//
//  KerbGeneralizedTime.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#include "KerbGeneralizedTime.h"

@implementation KerbGeneralizedTime
//type: 0x18
NSString* value;
-(id)initWithValue:(NSString*)baseValue{
    if(self = [super init]){
        self.value = baseValue;
    }
    return self;
}
-(id)initWithTimeNow{
    if(self = [super init]){
        NSDateFormatter *format = [[NSDateFormatter alloc] init];
        format.dateFormat = @"YYYYMMddHHmmss";
        format.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        NSMutableString* time = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate date]]];
        [time appendString:@"Z"];
        self.value = time;
    }
    return self;
}
-(id)initWithTimeOffset:(int)daysOffset{
    if(self = [super init]){
        NSDateComponents* deltaComps = [[NSDateComponents alloc] init];
        [deltaComps setDay:daysOffset];
        NSDate* tomorrow = [[NSCalendar currentCalendar] dateByAddingComponents:deltaComps toDate:[NSDate date] options:0];
        NSDateFormatter *format = [[NSDateFormatter alloc] init];
        format.dateFormat = @"YYYYMMddHHmmss";
        format.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        NSMutableString* time = [[NSMutableString alloc] initWithString:[format stringFromDate:tomorrow]];
        [time appendString:@"Z"];
        self.value = time;
    }
    return self;
}
-(id)initWithObject:(ASN1_Obj*)baseObject{
    if(self = [super init]){
        self.value = getAsnGenericStringBlob(baseObject);
    }
    return self;
}
-(NSData*)collapseToNSData{
    return createCollapsedAsnBasicType(0x18, [[NSData alloc] initWithBytes:self.value.UTF8String length:self.value.length]).data;
}
-(ASN1_Obj*)collapseToAsnObject{
    return createCollapsedAsnBasicType(0x18, [[NSData alloc] initWithBytes:self.value.UTF8String length:self.value.length]);
}
-(NSString*)printTimeUTC{
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"YYYYMMddHHmmssZ"];
    formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    NSDate* ticketTime = [formatter dateFromString:self.value];
    NSDateFormatter *newFormatter = [[NSDateFormatter alloc] init];
    newFormatter.dateFormat = @"YYYY-MM-dd HH:mm:ss z";
    newFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    return [newFormatter stringFromDate:ticketTime];
}
@end
