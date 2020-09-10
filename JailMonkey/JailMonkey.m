//
//  JailMonkey.m
//  Trackops
//
//  Created by Gant Laborde on 7/19/16.
//  Copyright © 2016 Facebook. All rights reserved.
//

#import "JailMonkey.h"
#include <TargetConditionals.h>
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dlfcn.h>
#include "TargetConditionals.h"
@import UIKit;
@import Darwin.sys.sysctl;

static NSString * const JMJailbreakTextFile = @"/private/jailbreak.txt";
static NSString * const JMisJailBronkenKey = @"isJailBroken";
static NSString * const JMisDebuggedKey = @"isDebuggedMode";
static NSString * const JMCanMockLocationKey = @"canMockLocation";

@implementation JailMonkey

RCT_EXPORT_MODULE();

#define A(c)            (c) - 0x19
#define HIDE_STR(str)   do { char *p = str;  while (*p) *p++ -= 0x19; } while (0)
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif

BOOL DEBUGGING = YES;

void LOG(NSString* loc)
{
    NSLog(@"Found: %@", loc);
}

// Preventing libobjc hooked, strstr implementation
const char* tuyul(const char* X, const char* Y)
{
    if (*Y == '\0')
        return X;

    for (int i = 0; i < strlen(X); i++)
    {
        if (*(X + i) == *Y)
        {
            char* ptr = tuyul(X + i + 1, Y + 1);
            return (ptr) ? ptr - 1 : NULL;
        }
    }

    return NULL;
}

char* UNHIDE_STR(char* str){
    do { char *p = str;  while (*p) *p++ += 0x19; } while (0);
    return str;
}

char* decryptString(char* str){
    str = UNHIDE_STR(str);
    str[strlen(str)]='\0';
    return str;
}

- (BOOL)isInjectedWithDynamicLibrary
{
    int i=0;
    while(true){
        const char *name = _dyld_get_image_name(i++);
        if(name==NULL){
            break;
        }
        if (name != NULL) {
            char cyinjectHide[] = {
                A('c'),
                A('y'),
                A('i'),
                A('n'),
                A('j'),
                A('e'),
                A('c'),
                A('t'),
                0
            };
            char libcycriptHide[] = {
                A('l'),
                A('i'),
                A('b'),
                A('c'),
                A('y'),
                A('c'),
                A('r'),
                A('i'),
                A('p'),
                A('t'),
                0
            };
            
            char libfridaHide[] = {
                A('F'),
                A('r'),
                A('i'),
                A('d'),
                A('a'),
                A('G'),
                A('a'),
                A('d'),
                A('g'),
                A('e'),
                A('t'),
                0
            };
            char zzzzLibertyDylibHide[] = {
                A('z'),
                A('z'),
                A('z'),
                A('z'),
                A('L'),
                A('i'),
                A('b'),
                A('e'),
                A('r'),
                A('t'),
                A('y'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            char sslkillswitch2dylib[] = {
                A('S'),
                A('S'),
                A('L'),
                A('K'),
                A('i'),
                A('l'),
                A('l'),
                A('S'),
                A('w'),
                A('i'),
                A('t'),
                A('c'),
                A('h'),
                A('2'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char zeroshadowdylib[] = {
                A('0'),
                A('S'),
                A('h'),
                A('a'),
                A('d'),
                A('o'),
                A('w'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char mobilesubstratedylib[] = {
                A('M'),
                A('o'),
                A('b'),
                A('i'),
                A('l'),
                A('e'),
                A('S'),
                A('u'),
                A('b'),
                A('s'),
                A('t'),
                A('r'),
                A('a'),
                A('t'),
                A('e'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char libsparkapplistdylib[] = {
                A('l'),
                A('i'),
                A('b'),
                A('s'),
                A('p'),
                A('a'),
                A('r'),
                A('k'),
                A('a'),
                A('p'),
                A('p'),
                A('l'),
                A('i'),
                A('s'),
                A('t'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char SubstrateInserterdylib[] = {
                A('S'),
                A('u'),
                A('b'),
                A('s'),
                A('t'),
                A('r'),
                A('a'),
                A('t'),
                A('e'),
                A('I'),
                A('n'),
                A('s'),
                A('e'),
                A('r'),
                A('t'),
                A('e'),
                A('r'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
            };
            
            char zzzzzzUnSubdylib[] = {
                A('z'),
                A('z'),
                A('z'),
                A('z'),
                A('z'),
                A('z'),
                A('U'),
                A('n'),
                A('S'),
                A('u'),
                A('b'),
                A('.'),
                A('d'),
                A('y'),
                A('l'),
                A('i'),
                A('b'),
                0
                
            };
            
            char kor[] = {
                A('.'),
                A('.'),
                A('.'),
                A('!'),
                A('@'),
                A('#'),
                0
            };
            char cephei[] = {
                A('/'),A('u'),A('s'),A('r'),A('/'),A('l'),A('i'),A('b'),A('/'),A('C'),A('e'),A('p'),A('h'),A('e'),A('i'),A('.'),A('f'),A('r'),A('a'),A('m'),A('e'),A('w'),A('o'),A('r'),A('k'),A('/'),A('C'),A('e'),A('p'),A('h'),A('e'),A('i'),
                0
            };
            if (tuyul(name, decryptString(cephei)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(kor)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(mobilesubstratedylib)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if(tuyul(name, decryptString(libsparkapplistdylib)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(cyinjectHide)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(libcycriptHide)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(libfridaHide)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(zzzzLibertyDylibHide)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(sslkillswitch2dylib)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(zeroshadowdylib)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(SubstrateInserterdylib)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
            if (tuyul(name, decryptString(zzzzzzUnSubdylib)) != NULL){
                if(DEBUGGING){LOG([[NSString alloc] initWithFormat:@"%s", name]);}
                return YES;
            }
        }
    }
    return NO;
}

+ (BOOL)requiresMainQueueSetup
{
    return YES;
}

- (NSArray *)pathsToCheck
{
    return @[
             @"/Applications/Cydia.app",
             @"/Library/MobileSubstrate/MobileSubstrate.dylib",
             @"/bin/bash",
             @"/usr/sbin/sshd",
             @"/etc/apt",
             @"/private/var/lib/apt",
             @"/usr/sbin/frida-server",
             @"/usr/bin/cycript",
             @"/usr/local/bin/cycript",
             @"/usr/lib/libcycript.dylib",
             @"/Applications/FakeCarrier.app",
             @"/Applications/Icy.app",
             @"/Applications/IntelliScreen.app",
             @"/Applications/MxTube.app",
             @"/Applications/RockApp.app",
             @"/Applications/SBSettings.app",
             @"/Applications/WinterBoard.app",
             @"/Applications/blackra1n.app",
             @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
             @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
             @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
             @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
             @"/bin/sh",
             @"/etc/ssh/sshd_config",
             @"/private/var/lib/cydia",
             @"/private/var/mobile/Library/SBSettings/Themes",
             @"/private/var/stash",
             @"/private/var/tmp/cydia.log",
             @"/usr/bin/sshd",
             @"/usr/libexec/sftp-server",
             @"/usr/libexec/ssh-keysign",
             @"/var/cache/apt",
             @"/var/lib/apt",
             @"/var/lib/cydia",
             @"/Library/LaunchDaemons/com.openssh.sshd.plist",
             @"/usr/bin/ssh",
             @"/private/etc/dpkg/origins/debian",
             @"/bin.sh",
             @"/private/etc/apt",
             @"/private/etc/ssh/sshd_config",
             @"/Applications/SBSetttings.app",
             @"/private/var/mobileLibrary/SBSettingsThemes/",
             @"/usr/libexec/cydia/",
             @"/Applications/Snoop-itConfig.app",
             @"/var/checkra1n.dmg",
             @"/var/binpack",
             ];
}

- (NSArray *)schemesToCheck
{
    return @[
             @"cydia://package/com.example.package",
             ];
}

- (BOOL)checkPaths
{
    BOOL existsPath = NO;

    for (NSString *path in [self pathsToCheck]) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]){
            existsPath = YES;
            break;
        }
    }

    return existsPath;
}

- (BOOL)checkSchemes
{
    BOOL canOpenScheme = NO;

    for (NSString *scheme in [self schemesToCheck]) {
        if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:scheme]]){
            canOpenScheme = YES;
            break;
        }
    }

    return canOpenScheme;
}

- (BOOL)canViolateSandbox{
	NSError *error;
    BOOL grantsToWrite = NO;
	NSString *stringToBeWritten = @"This is an anti-spoofing test.";
	[stringToBeWritten writeToFile:JMJailbreakTextFile atomically:YES
						  encoding:NSUTF8StringEncoding error:&error];
	if(!error){
		//Device is jailbroken
		grantsToWrite = YES;
	}

    [[NSFileManager defaultManager] removeItemAtPath:JMJailbreakTextFile error:nil];

    return grantsToWrite;
}

- (BOOL)isDebugged{
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    int name[4];

    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();

    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        NSLog(@"sysctl() failed: %s", strerror(errno));
        return false;
    }

    if ((info.kp_proc.p_flag & P_TRACED) != 0) {
        return true;
	}

    return false;
}

- (BOOL)isJailBroken{
    #if TARGET_OS_SIMULATOR
      return NO;
    #endif
    return [self checkPaths] || [self checkSchemes] || [self canViolateSandbox] || [self isInjectedWithDynamicLibrary];
}

- (NSDictionary *)constantsToExport
{
	return @{
			 JMisJailBronkenKey: @(self.isJailBroken),
			 JMisDebuggedKey: @(self.isDebugged),
			 JMCanMockLocationKey: @(self.isJailBroken)
			 };
}

@end
