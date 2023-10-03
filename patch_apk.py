import json
import lzma
import zipfile
import lief
from zipfile import ZipFile
import shutil
import os
import requests
import sys
import argparse
from shutil import which
import subprocess
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import Encoding
import binascii
import find_offset


TEMP_FOLDER = os.getcwd() + "/temp"
DEFAULT_OUTPUT_NAME = "app_patched.apk"
SUPPORTED_ARCHS = ["armeabi-v7a", "arm64-v8a"]


def inject_frida_gadget(libpath):
    print("Patching:", libpath)
    libnative = lief.parse(libpath)
    libnative.add_library("libgadget.so")
    libnative.write(libpath)


def create_temp_folder():
    delete_temp_folder()
    os.mkdir(TEMP_FOLDER)


def is_tool_installed(name):
    return which(name) is not None


def check_tools():
    if not is_tool_installed("keytool"):
        print("keytool not installed or not in PATH")
        return False
    if not is_tool_installed("apksigner"):
        print("apksigner not installed or not in PATH")
        return False
    if not is_tool_installed("zipalign"):
        print("zipalign not installed or not in PATH")
        return False
    if not is_tool_installed("r2"):
        print("r2 not installed or not in PATH")
        return False
    return True


def create_keystore(keyalias, storepass):
    print("Generating keystore...")
    keystore_file = "{0}/release.keystore".format(TEMP_FOLDER)
    subprocess.call(
        'keytool -genkey -v -keystore {0} -alias {1} -keyalg RSA -keysize 2048 -validity 8000 -dname '
        '"CN=com.leftenter.android, OU=ID, O=APK, L=Unknown, S=Unknown, C=XK" -storepass {2}'.format(
            keystore_file, keyalias, storepass),
        shell=True)
    shutil.copy(keystore_file, "release.keystore")
    return keystore_file


def sign_apk(apk, keystore, key_alias, store_pass):
    print("Signing apk...")
    subprocess.call(
        "apksigner sign -ks {0} --ks-key-alias {1} --ks-pass pass:{2} {3}".format(
            keystore, key_alias, store_pass, apk),
        shell=True
    )


def zip_align_apk(apk):
    print("Running zipalign...")
    tmp_apk = apk.replace(".apk", "_tmp.apk")
    shutil.move(apk, tmp_apk)
    subprocess.call(
        'zipalign -p -f 4 {0} {1}'.format(tmp_apk, apk), stderr=subprocess.STDOUT, shell=True)
    os.remove(tmp_apk)


def delete_temp_folder():
    if (os.path.exists(TEMP_FOLDER)):
        shutil.rmtree(TEMP_FOLDER)


def get_app_arch(apk):
    res = []
    with ZipFile(apk, "r") as zip_file:
        for filename in zip_file.namelist():
            if filename.startswith("lib/x86/") and "x86" not in res:
                res.append("x86")
            elif filename.startswith("lib/x86_64/") and "x86_64" not in res:
                res.append("x86_64")
            elif filename.startswith("lib/armeabi-v7a/") and "armeabi-v7a" not in res:
                res.append("armeabi-v7a")
            elif filename.startswith("lib/arm64-v8a/") and "arm64-v8a" not in res:
                res.append("arm64-v8a")
    return res


def extract_libs_for_apk(apk, arch):
    libs = ["libsysoptimizer.so"]
    with ZipFile(apk) as zip_file:
        namelist = zip_file.namelist()
        for lib in libs:
            libname = "lib/{0}/{1}".format(arch, lib)
            if libname in namelist:
                print("Extracting:", libname)
                return zip_file.extract(libname, TEMP_FOLDER)


def get_arch(apk):
    app_archs = get_app_arch(apk)
    print("App ABIs: ", app_archs)
    archs = list(set(app_archs) & set(SUPPORTED_ARCHS))
    print("Supported ABIs: ", archs)
    return archs


def copy_apk_to_temp_folder(apk_path):
    filepath = os.path.join(TEMP_FOLDER, "app.apk")
    shutil.copy(apk_path, filepath)
    return filepath


def download_file(url, filename):
    filepath = os.path.join(TEMP_FOLDER, filename)
    with open(filepath, "wb") as f:
        print("Downloading %s" % filename)
        response = requests.get(url, stream=True)
        total_length = response.headers.get('content-length')
        if total_length is None:
            f.write(response.content)
        else:
            dl = 0
            total_length = int(total_length)
            for data in response.iter_content(chunk_size=4096):
                dl += len(data)
                f.write(data)
                done = int(50 * dl / total_length)
                sys.stdout.write("\r[%s%s]" % ('=' * done, ' ' * (50-done)))
                sys.stdout.flush()
    print("\n")
    return filepath


def extract_frida_gadget(archive_path, arch):
    filepath = os.path.join(TEMP_FOLDER, "lib", arch, "libgadget.so")
    with lzma.open(archive_path, mode='rb') as archive:
        with open(filepath, "wb") as f:
            f.write(archive.read())

    os.remove(archive_path)
    return filepath


def download_frida_gadget(arch):
    arch_config = {
        "x86": "x86",
        "x86_64": "x86_64",
        "armeabi-v7a": "arm",
        "arm64-v8a": "arm64"
    }
    response = requests.get(
        "https://api.github.com/repos/frida/frida/releases").text
    releases = json.loads(response)
    for release in releases:
        tag_name = release["tag_name"]
        for asset in release["assets"]:
            if asset["name"] == "frida-gadget-{0}-android-{1}.so.xz".format(tag_name, arch_config[arch]):
                frida_gadget_url = asset["browser_download_url"]
                archive_path = download_file(
                    frida_gadget_url, "firda-gadget-{0}-{1}.so.xz".format(tag_name, arch))
                return extract_frida_gadget(archive_path, arch)


def patch_apk(apk):
    print("Rebuilding apk file...")
    apk_in = ZipFile(apk, "r")
    apk_out = ZipFile(os.path.join(TEMP_FOLDER, "new_apk.apk"), "w")
    files = apk_in.infolist()
    for file in files:
        if not os.path.exists(os.path.join(TEMP_FOLDER, file.filename)) and not file.filename.startswith("META-INF\\"):
            apk_out.writestr(file.filename, apk_in.read(
                file.filename), compress_type=file.compress_type, compresslevel=9)
    apk_in.close()
    libfolder = os.path.join(TEMP_FOLDER, "lib")
    for (root, _, files) in os.walk(libfolder, topdown=True):
        for filename in files:
            filepath = os.path.join(root, filename)
            archname = os.path.relpath(filepath, TEMP_FOLDER)
            apk_out.write(filepath, archname,
                          compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    apk_out.close()
    return apk_out.filename


def get_signature_file(apk):
    with ZipFile(apk, "r") as apk_in:
        files = apk_in.infolist()
        for file in files:
            if file.filename.startswith("META-INF") and file.filename.endswith("RSA"):
                return apk_in.read(file.filename)


def extract_original_signature(apk):
    singature_file_content = get_signature_file(apk)
    certificate = pkcs7.load_der_pkcs7_certificates(singature_file_content)[0]
    certificate_bytes = certificate.public_bytes(Encoding.DER)
    return binascii.hexlify(certificate_bytes).decode()


def copy_script_temp(apk):
    signature = extract_original_signature(apk)
    src = os.path.join(os.getcwd(), "tiktok-ssl-pinning-bypass.js")
    dest = os.path.join(TEMP_FOLDER, "libsslbypass.js.so")
    f_src = open(src, "r")
    script_content = f_src.read()
    f_src.close()
    script_content = script_content.replace(
        "<ORIGINAL_APK_SIGNATURE>", signature)
    script_content = script_content.replace(
        "//spoofSignature()", "spoofSignature()")
    f_dest = open(dest, "w")
    f_dest.write(script_content)
    f_dest.close()
    return dest


def set_function_offset(script, arch, offset):
    print("fun_offset: " + offset)
    src = os.path.join(TEMP_FOLDER, "libsslbypass.js.so")
    dest = os.path.join(TEMP_FOLDER, "lib", arch, "libsslbypass.js.so")
    f_src = open(src, "r")
    script_content = f_src.read()
    f_src.close()
    if arch == "armeabi-v7a":
        script_content = script_content.replace("<ARM_OFFSET>", offset)
    elif arch == "arm64-v8a":
        script_content = script_content.replace("<ARM64_OFFSET>", offset)
    f_dest = open(dest, "w")
    f_dest.write(script_content)
    f_dest.close()
    return dest


def create_config_file():
    filepath = os.path.join(TEMP_FOLDER, "libgadget.config.so")
    config = {
        "interaction": {
            "type": "script",
            "path": "./libsslbypass.js.so"
        }
    }
    with open(filepath, 'w') as f:
        json.dump(config, f)
        return filepath


def main():
    parser = argparse.ArgumentParser(
        description='Remove ssl pining from tiktok app')
    parser.add_argument("-i", "--input", type=str,
                        help="Input apk file.", required=True)
    parser.add_argument("-o", "--output", type=str,
                        help="Output apk file.", default=DEFAULT_OUTPUT_NAME)
    parser.add_argument("--keystore", type=str,
                        help="Use your own keystore for signing.")
    parser.add_argument("--keyalias", type=str,
                        help="Key alias", default="PATCH")
    parser.add_argument("--storepass", type=str,
                        help="Password for keystore", default="password")

    args = parser.parse_args()
    inputfile = args.input
    outputfile = args.output
    keyalias = args.keyalias
    storepass = args.storepass
    keystore = None

    if not check_tools():
        exit(1)

    create_temp_folder()
    temp_apk = copy_apk_to_temp_folder(inputfile)

    archs = get_arch(temp_apk)
    if len(archs) == 0:
        print("Current ABI is not supported!")
        exit(1)

    if (args.keystore):
        keystore = args.keystore
    else:
        keystore = create_keystore(keyalias, storepass)

    config_file = create_config_file()
    print("Created config_file at: ", config_file)
    script = copy_script_temp(temp_apk)
    print("Created script_file at: ", script)
    for arch in archs:
        print("\nPatching for", arch)
        nativelib = extract_libs_for_apk(temp_apk, arch)
        arch_folder = os.path.join(TEMP_FOLDER, "lib", arch)
        download_frida_gadget(arch)
        inject_frida_gadget(nativelib)
        fcn_offset = find_offset.find_function_from_apk(temp_apk, arch)
        set_function_offset(script, arch, fcn_offset)
        shutil.copy(config_file, arch_folder)
    output = patch_apk(temp_apk)
    zip_align_apk(output)
    sign_apk(output, keystore, keyalias, storepass)
    outputpath = shutil.move(output, outputfile)
    delete_temp_folder()
    print("Sucessful. Patched file at:", outputpath)


main()
