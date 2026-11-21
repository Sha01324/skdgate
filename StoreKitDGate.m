#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdio.h>
#import <unistd.h>

static FILE *gLog=NULL;
static void openLog(void){
    const char *paths[]={"/tmp/skdgate.log","/private/var/tmp/skdgate.log","/var/jb/tmp/skdgate.log",NULL};
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
    Class fm=objc_getClass("NSFileManager");
    if(fm&&!gISB){Method m=class_getInstanceMethod(fm,sel_registerName("isSignedByAppleFileAtPath:basicCheck:"));GLog(@"NSFileManager=%p method=%p",fm,m);if(m){o1=(void*)method_getImplementation(m);method_setImplementation(m,(IMP)r1);gISB=YES;GLog(@"hooked isSignedByApple OK");}}
    Class lbr=objc_getClass("LSBundleRecord");
    if(lbr&&!gSK){Method m=class_getInstanceMethod(lbr,sel_registerName("sk_isAppStoreSigned"));GLog(@"LSBundleRecord=%p method=%p",lbr,m);if(m){o2=(void*)method_getImplementation(m);method_setImplementation(m,(IMP)r2);gSK=YES;GLog(@"hooked sk_isAppStoreSigned OK");}}
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
