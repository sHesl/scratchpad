package touchid

/*
#cgo CFLAGS: -x objective-c -fmodules -fblocks
#cgo LDFLAGS: -framework CoreFoundation -framework LocalAuthentication -framework Foundation
#include <stdlib.h>
#include <stdio.h>
#import <LocalAuthentication/LocalAuthentication.h>
bool Authenticate(char const* msg) {
 LAContext *laContext = [[LAContext alloc] init];
 laContext.localizedFallbackTitle = @"";
 LAPolicy laPolicy = LAPolicyDeviceOwnerAuthentication;

 NSError *err = nil;
 dispatch_semaphore_t sema = dispatch_semaphore_create(0);
 NSString *nsMsg = [NSString stringWithUTF8String:msg];
 __block bool result = false;

 if ([laContext canEvaluatePolicy:laPolicy error:&err]) {
   [laContext evaluatePolicy:laPolicy
	 localizedReason:nsMsg
	 reply:^(BOOL success, NSError *error) {
	   result = success;
	   dispatch_semaphore_signal(sema);
	 }];
 }
 dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
 dispatch_release(sema);
 return result;
}
*/
import (
	"C"
)
import (
	"errors"
	"unsafe"
)

// TouchID prompts user authentication via TouchID biometrics, displaying the
// given message to the user in the format:
//
//    $process_name is trying to $msg
//
//    Touch ID to allow this.
//
func TouchID(msg string) error {
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))

	if ok := C.Authenticate(cMsg); ok {
		return nil
	}

	return errors.New("Touch ID authentication failed")
}
