#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdio.h>
#import <unistd.h>
#import <sys/stat.h>

static FILE *gLog=NULL;
static void openLog(void){
    const char *paths[]={"/tmp/skdgate.log","/var/jb/tmp/skdgate.log","/private/var/tmp/skdgate.log",NULL};
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
static BOOL r1(id self,SEL _c,NSString*p,BOOL b){GLog(@"isSignedByAppleFileAtPath:%@ -> YES",p);return YES;}
static BOOL (*o2)(id,SEL)=NULL;
static BOOL r2(id self,SEL _c){GLog(@"sk_isAppStoreSigned -> YES");return YES;}
static void swz(void){
    Class c=objc_getClass("NSFileManager_LibAppStoreDaemon_");
    if(c&&!gISB){Method m=class_getInstanceMethod(c,sel_registerName("isSignedByAppleFileAtPath:basicCheck:"));GLog(@"NSFileManager class=%p method=%p",c,m);if(m){o1=(void*)method_getImplementation(m);method_setImplementation(m,(IMP)r1);gISB=YES;GLog(@"hooked isSignedByApple OK");}}
    Class l=objc_getClass("LSBundleRecord_LibAppStoreDaemon_");
    if(l&&!gSK){Method m=class_getInstanceMethod(l,sel_registerName("sk_isAppStoreSigned"));GLog(@"LSBundleRecord class=%p method=%p",l,m);if(m){o2=(void*)method_getImplementation(m);method_setImplementation(m,(IMP)r2);gSK=YES;GLog(@"hooked sk_isAppStoreSigned OK");}}
}
static void onimg(const struct mach_header*m,intptr_t v){swz();}
__attribute__((constructor)) static void init(void){
    @autoreleasepool{
        GLog(@"===== loaded pid %d =====",getpid());
        Class c1=objc_getClass("NSFileManager_LibAppStoreDaemon_");
        Class c2=objc_getClass("LSBundleRecord_LibAppStoreDaemon_");
        GLog(@"pre-scan classes: NSFileManager=%p LSBundleRecord=%p",c1,c2);
        swz();
        GLog(@"after swz: gISB=%d gSK=%d",(int)gISB,(int)gSK);
        if(!(gISB&&gSK)) _dyld_register_func_for_add_image(onimg);
    }
}
