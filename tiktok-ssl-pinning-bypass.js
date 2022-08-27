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

function hook_callback(callback) {
    const f = new NativeFunction(callback, "int", ["pointer","pointer"]);
    Interceptor.attach(f, {
        onLeave: function(retval)
        {
            retval.replace(0)
        }
    })
}

function hook_SSL_CTX_set_custom_verify(library) {
    const functionName = "SSL_CTX_set_custom_verify"
    

    try {
        const f = Module.getExportByName(library.name, functionName);
        const  SSL_CTX_set_custom_verify = new NativeFunction(f, 'void', ['pointer', 'int','pointer'])

        Interceptor.replace(SSL_CTX_set_custom_verify,  new NativeCallback(function(ssl, mode, callback) {
            hook_callback(callback);
            SSL_CTX_set_custom_verify(ssl, mode, callback)
        }, 'void', ['pointer', 'int','pointer']));

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
    } catch(e) {
        logger("[*][-] Failed to hook checkTrustedRecursive")
    }
});

