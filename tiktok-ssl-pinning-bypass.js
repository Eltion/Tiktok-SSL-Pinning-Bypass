function waitForModule(moduleName) {
    return new Promise(resolve => {
        const interval = setInterval(() => {
            const module = Process.findModuleByName(moduleName);
            if (module != null) {
                clearInterval(interval);
                resolve(module);
            }
        }, 0);
    });
}

//Only needed when apk is patched with frida-gadget
//spoofSignature() 

function spoofSignature() {
    const originalSignature = "<ORIGINAL_APK_SIGNATURE>" //This will be set by patch_apk.py
    Java.perform(() => {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        const Signature = Java.use("android.content.pm.Signature");
        const ActivityThread = Java.use('android.app.ActivityThread');
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (a, b) {
            const packageInfo = this.getPackageInfo(a, b);
            const context = ActivityThread.currentApplication().getApplicationContext();
            const name = context.getPackageName();
            if (a == name && b == 64) {
                const signature = Signature.$new(originalSignature);
                packageInfo.signatures.value = Java.array('android.content.pm.Signature', [signature]);
            }
            return packageInfo;
        }
    });
}

function hook_callback(callback) {
    const f = new NativeFunction(callback, "int", ["pointer", "pointer"]);
    Interceptor.attach(f, {
        onLeave: function (retval) {
            retval.replace(0)
        }
    })
}

function hook_SSL_CTX_set_custom_verify(library) {
    const functionName = "SSL_CTX_set_custom_verify"


    try {
        const f = Module.getExportByName(library.name, functionName);
        const SSL_CTX_set_custom_verify = new NativeFunction(f, 'void', ['pointer', 'int', 'pointer'])

        Interceptor.replace(SSL_CTX_set_custom_verify, new NativeCallback(function (ssl, mode, callback) {
            hook_callback(callback);
            SSL_CTX_set_custom_verify(ssl, mode, callback)
        }, 'void', ['pointer', 'int', 'pointer']));

        logger(`[*][+] Hooked function: ${functionName}`);
    } catch (err) {
        logger(`[*][-] Failed to hook function: ${functionName}`);
        logger(err.toString())
    }
}

function logger(message) {
    console.log(message);
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.v("TIKTOK_SSL_PINNING_BYPASS", message);
    });
}


logger("[*][*] Waiting for libsscronet...");
waitForModule("libsscronet.so").then((lib) => {
    logger(`[*][+] Found libsscronet at: ${lib.base}`)
    hook_SSL_CTX_set_custom_verify(lib);
});

//Universal Android SSL Pinning Bypass #2
Java.perform(function () {
    try {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        if (ApiClient.checkTrustedRecursive) {
            logger("[*][+] Hooked checkTrustedRecursive")
            ApiClient.checkTrustedRecursive.implementation = function (a1, a2, a3, a4, a5, a6) {
                var k = array_list.$new();
                return k;
            }
        } else {
            logger("[*][-] checkTrustedRecursive not Found")
        }
    } catch (e) {
        logger("[*][-] Failed to hook checkTrustedRecursive")
    }
});


Java.perform(function () {
    try {
        const x509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const sSLContext = Java.use("javax.net.ssl.SSLContext");
        const TrustManager = Java.registerClass({
            implements: [x509TrustManager],
            methods: {
                checkClientTrusted(chain, authType) {
                },
                checkServerTrusted(chain, authType) {
                },
                getAcceptedIssuers() {
                    return [];
                },
            },
            name: "com.leftenter.tiktok",
        });
        const TrustManagers = [TrustManager.$new()];
        const SSLContextInit = sSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
        SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
            SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
        };
        logger("[*][+] Hooked SSLContextInit")
    } catch (e) {
        logger("[*][-] Failed to hook SSLContextInit")
    }
})