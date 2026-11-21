#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdio.h>
#import <unistd.h>
#include <stdlib.h>

static FILE *gLog=NULL;
static void openLog(void){
    const char *paths[]={"/tmp/skdgate.log","/private/var/tmp/skdgate.log","/var/jb/tmp/skdgate.log",
        "/var/jb/Library/Logs/skdgate.log","/var/jb/var/mobile/Library/Logs/skdgate.log",NULL};
    for(int i=0;paths[i];i++){ gLog=fopen(paths[i],"a"); if(gLog) return; }
}
static void GLog(NSString *fmt,...){
    if(!gLog) openLog();
    va_list ap;va_start(ap,fmt);NSString*s=[[NSString alloc]initWithFormat:fmt arguments:ap];va_end(ap);
    NSLog(@"[SKDGATE] %@",s);
    if(gLog){fprintf(gLog,"%s\n",[s UTF8String]);fflush(gLog);}
}
static BOOL gISB=NO,gSK=NO;
static BOOL (*o1)(id,SEL,NSString*,BOOL)=NULL;
static BOOL r1(id self,SEL _c,NSString*p,BOOL b){GLog(@"isSignedByApple:%@ -> YES",p);return YES;}
static BOOL (*o2)(id,SEL)=NULL;
static BOOL r2(id self,SEL _c){GLog(@"sk_isAppStoreSigned -> YES");return YES;}
static void swz(void){
    if(gISB&&gSK) return;
    int n=objc_getClassList(NULL,0);
    if(n<=0) return;
    Class *cs=(Class*)malloc(sizeof(Class)*n);
    if(!cs) return;
    objc_getClassList(cs,n);
    SEL s1=sel_registerName("isSignedByAppleFileAtPath:basicCheck:");
    SEL s2=sel_registerName("sk_isAppStoreSigned");
    for(int i=0;i<n;i++){
        Class c=cs[i];
        if(!gISB){ Method m=class_getInstanceMethod(c,s1); if(m){o1=(void*)method_getImplementation(m);method_setImplementation(m,(IMP)r1);gISB=YES;GLog(@"hooked isSignedByApple on class %s",class_getName(c));}}
        if(!gSK){ Method m=class_getInstanceMethod(c,s2); if(m){o2=(void*)method_getImplementation(m);method_setImplementation(m,(IMP)r2);gSK=YES;GLog(@"hooked sk_isAppStoreSigned on class %s",class_getName(c));}}
        if(gISB&&gSK) break;
    }
    free(cs);
}
static void onimg(const struct mach_header*m,intptr_t v){swz();}
__attribute__((constructor)) static void init(void){
    @autoreleasepool{
        GLog(@"===== loaded pid %d =====",getpid());
        swz();
        GLog(@"after swz: gISB=%d gSK=%d",(int)gISB,(int)gSK);
        if(!(gISB&&gSK)) _dyld_register_func_for_add_image(onimg);
    }
}
