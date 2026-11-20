// StoreKitDGate: inject into storekitd and force "isSignedByApple" true for fakesigned apps.
// Root cause: storekitd runs its OWN libmis validation (MISValidateSignatureAndCopyInfo) via
// -[NSFileManager_LibAppStoreDaemon_ isSignedByAppleFileAtPath:basicCheck:]. AppSync only hooks
// installd, never storekitd. So the fake-signature shell fails storekitd's signature check and
// SKProductsRequest returns valid=0. This tweak neutralises that check inside storekitd itself.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <stdio.h>

static FILE *gLog = NULL;
static void GLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[SKDGATE] %@", s);
    if (!gLog) {
        NSString *p = @"/var/mobile/Library/Logs/skdgate.log";
        [[NSFileManager defaultManager] createDirectoryAtPath:@"/var/mobile/Library/Logs" withIntermediateDirectories:YES attributes:nil error:nil];
        gLog = fopen([p UTF8String], "a");
    }
    if (gLog) { fprintf(gLog, "%s\n", [s UTF8String]); fflush(gLog); }
}

static BOOL gSwizzledISB = NO;
static BOOL gSwizzledSK = NO;

// ---- ObjC hook: force isSignedByAppleFileAtPath -> YES ----
static BOOL (*orig_isSignedByApple)(id, SEL, NSString*, BOOL) = NULL;
static BOOL repl_isSignedByApple(id self, SEL _cmd, NSString *path, BOOL basic) {
    GLog(@"isSignedByAppleFileAtPath:%@ basic=%d -> FORCED YES", path, basic);
    return YES;
}

// ---- ObjC hook: force sk_isAppStoreSigned -> YES (the real gate storekitd uses) ----
static BOOL (*orig_skIsAppStoreSigned)(id, SEL) = NULL;
static BOOL repl_skIsAppStoreSigned(id self, SEL _cmd) {
    GLog(@"LSBundleRecord sk_isAppStoreSigned -> FORCED YES (%@)", [self description]);
    return YES;
}

// ---- C hook: MISValidateSignatureAndCopyInfo -> fake App-Store signing info if empty ----
static uintptr_t (*orig_MIS)(NSString*, NSDictionary*, NSDictionary**) = NULL;
static uintptr_t repl_MIS(NSString *path, NSDictionary *options, NSDictionary **info) {
    uintptr_t r = 0;
    if (orig_MIS) r = orig_MIS(path, options, info);
    GLog(@"MISValidateSignatureAndCopyInfo path=%@ ret=%lu infoEmpty=%d", path, (unsigned long)r, (info && *info)==nil ? 1 : 0);
    return r;
}

static void trySwizzle(void) {
    if (gSwizzledISB && gSwizzledSK) return;
    Class c = objc_getClass("NSFileManager_LibAppStoreDaemon_");
    if (c && !gSwizzledISB) {
    SEL sel = sel_registerName("isSignedByAppleFileAtPath:basicCheck:");
    Method m = class_getInstanceMethod(c, sel);
    if (m) {
    orig_isSignedByApple = (void*)method_getImplementation(m);
    method_setImplementation(m, (IMP)repl_isSignedByApple);
    gSwizzledISB = YES;
    GLog(@"SWIZZLED -[NSFileManager_LibAppStoreDaemon_ isSignedByAppleFileAtPath:basicCheck:] -> YES");
    } else { GLog(@"isSignedByAppleFileAtPath method not found"); }
    }

    // also swizzle the higher-level StoreKit gate if present
    if (!gSwizzledSK) {
    Class lbr = objc_getClass("LSBundleRecord_LibAppStoreDaemon_");
    if (lbr) {
        Method m2 = class_getInstanceMethod(lbr, sel_registerName("sk_isAppStoreSigned"));
        if (m2) {
            orig_skIsAppStoreSigned = (void*)method_getImplementation(m2);
            method_setImplementation(m2, (IMP)repl_skIsAppStoreSigned);
            GLog(@"SWIZZLED -[LSBundleRecord_LibAppStoreDaemon_ sk_isAppStoreSigned] -> YES");
            gSwizzledSK = YES;
        } else {
            GLog(@"sk_isAppStoreSigned not found on LSBundleRecord_LibAppStoreDaemon_");
        }
    } else {
        GLog(@"LSBundleRecord_LibAppStoreDaemon_ class not loaded");
    }
    }
}

static void tryHookMIS(void) {
    static BOOL done = NO;
    if (done) return;
    void *mis = dlopen("/usr/lib/libmis.dylib", RTLD_LAZY);
    if (!mis) return;
    void *sym = dlsym(mis, "MISValidateSignatureAndCopyInfo");
    if (!sym) sym = dlsym(mis, "MISValidateSignatureAndCopyInfoWithProgress");
    if (!sym) return;
    // Only log (non-invasive); swizzling the ObjC method above is the actual gate bypass.
    orig_MIS = (void*)sym;
    done = YES;
    GLog(@"found libmis MISValidateSignatureAndCopyInfo @ %p (logging only)", sym);
}

static void onImage(const struct mach_header *mh, intptr_t vmaddr) {
    trySwizzle();
    tryHookMIS();
}

__attribute__((constructor))
static void skdgate_init(void) {
    @autoreleasepool {
        GLog(@"===== StoreKitDGate loaded in pid %d =====", getpid());
        trySwizzle();
        tryHookMIS();
        if (!gSwizzledISB) {
            GLog(@"class/method not ready yet -> registering dyld image callback for retry");
            _dyld_register_func_for_add_image(onImage);
        }
    }
}
