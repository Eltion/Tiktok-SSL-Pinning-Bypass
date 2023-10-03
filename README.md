# Tiktok SSL Pinning Bypass

Bypass TikTok SSL pinning on Android devices.  
Supported ABIs: `armeabi-v7a`, `arm64-v8a`  
The Latest version: `v30.1.2`

If you like this project:  
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/eltimusa4q)  

**Bitcoin**: bc1q6kvvun3cfm5kadesxflntszp8z9lqesra35law  
**Ethereum**: 0x47633Ef59b0F765b7f8047b0A56230cfeBB34027  
**USDC**: 0x47633Ef59b0F765b7f8047b0A56230cfeBB34027  
**USDT**: 0x47633Ef59b0F765b7f8047b0A56230cfeBB34027  

## Patched APK (No Root)

Download the latest patched APK: 
+ [tiktok-v30.1.2.apk](https://github.com/Eltion/Tiktok-SSL-Pinning-Bypass/releases/download/v30.1.2/tiktok-v30.1.2.apk)  
[See all versions](https://github.com/Eltion/Tiktok-SSL-Pinning-Bypass/releases/)

## Run using Frida (Requires Root)

Requires frida-tools and radare2
```
python gen_script.py -i <your apk>
frida -U -l .\ssl_bypass.js -f com.zhiliaoapp.musically
```

## Patch APK (with frida-gadget)

You can create your own patched APK. 

### Requirements Linux (Ubuntu):
1. Install java JRE: `sudo apt install default-jre`
2. Install apksigner: `sudo apt install apksigner`
3. Install zipalign: `sudo apt install zipalign`  
4. Install radare2: `sudo apt install radare2`  

Note: apksigner and zipalign can also be found in android sdk [build-tools](https://dl.google.com/android/repository/build-tools_r30.0.1-linux.zip)

### Requirements Windows:
1. Install java JRE
2. Download [build-tools](https://dl.google.com/android/repository/build-tools_r30.0.1-windows.zip) and unzip
3. Add unzip folder to path variable
4. Install [radare2](https://github.com/radareorg/radare2/releases/) and add to path


### Instructions

1. Download tiktok apk file.
2. Install requirements > `pip install -r requirements.txt`
3. Run script > `python patch_apk.py -i <input apk> -o <output apk>`

After that an patched apk file should be generated.

## Patch library (without frida, requires root)

1. Install tiktok from Play Store or from the apk
2. Pull `libsscronet.so` from the phone

```bash
adb shell

#inside adb shell 

su
apk=$(pm path com.zhiliaoapp.musically | cut -d':' -f2)
app_dir=$(dirname $apk)
libsscronet=$app_dir/lib/arm64/libsscronet.so #for arm replace arm64 with arm 
echo $libsscronet
#/data/app/~~MaV1k6AHxSX2VmtJHZXXZg==/com.zhiliaoapp.musically-qb3IhNrRlxGAHW93wN_haw==/lib/arm64/libsscronet.so 
cp "$libsscronet" /sdcard/libsscronet.so

exit
exit

#outsite adb shell 

adb pull /sdcard/libsscronet.so
```

4. Run `python -i libsscronet.so -a [arm64-v8a|armeabi-v7a]`
5. After `libsscronet_patched.so` is created we can push it in to the phone

```bash
adb push libsscronet_patched.so /sdcard/libsscronet_patched.so
adb shell

#inside adb shell 

su

apk=$(pm path com.zhiliaoapp.musically | cut -d':' -f2)
app_dir=$(dirname $apk)
libsscronet=$app_dir/lib/arm64/libsscronet.so #for arm replace arm64 with arm 
rm "$libsscronet"
cp /sdcard/libsscronet_patched.so "$libsscronet" 
exit
exit
```

## Intercept network traffic

You can use a tool like mitmproxy or Burp Suite to intercept the network.

1. Install patched APK in the device
2. Install [mitmproxy](https://mitmproxy.org/) or [Burp Suite](https://portswigger.net/burp)
3. Set up proxy for wifi settings or run: `adb shell settings put global http_proxy <proxy>`

Now you should be able to see the network traffic.

## View script logs
To view the logcat run:
```
adb logcat -s "TIKTOK_SSL_PINNING_BYPASS:V"
```

[#leftenter](#leftenter)
