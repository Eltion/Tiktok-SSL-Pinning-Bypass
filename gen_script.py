import find_offset
import argparse
import os


def gen_script(arm_offset, arm64_offset):
    src = os.path.join(os.getcwd(), "tiktok-ssl-pinning-bypass.js")
    dest = os.path.join(os.getcwd(), "ssl_bypass.js")
    f_src = open(src, "r")
    script_content = f_src.read()
    f_src.close()
    script_content = script_content.replace("<ARM_OFFSET>", arm_offset)
    script_content = script_content.replace("<ARM64_OFFSET>", arm64_offset)
    f_dest = open(dest, "w")
    f_dest.write(script_content)
    f_dest.close()
    return dest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generates frida script for current apk version')
    parser.add_argument("-i", "--input", type=str,
                        help="Input apk file.", required=True)

    args = parser.parse_args()
    apk = args.input

    arm_offset = find_offset.find_function_from_apk(apk, "armeabi-v7a")
    arm64_offset = find_offset.find_function_from_apk(apk, "arm64-v8a")

    print("arm offset:", arm_offset)
    print("arm64 offset:", arm64_offset)

    new_script = gen_script(arm_offset, arm64_offset)
    print("Frida script generated at: " + new_script)
