import r2pipe
from zipfile import ZipFile
import tempfile
import argparse
import shutil


def patch_function_arm64(lib):
    print("Finding function offset in " + lib)
    r2 = r2pipe.open(lib, ["-w", "-2"])
    r2.cmd('aae')
    results = r2.cmdj('/j HandleVerifyResult')
    offset = results[0]['offset']
    results = r2.cmdj('axtj ' + str(offset))
    usage_offset = results[0]['from']
    r2.cmd("s " + str(usage_offset))
    r2.cmd("e search.from="+str(usage_offset-1000))
    r2.cmd("e search.to="+str(usage_offset))

    results = r2.cmdj("/badj sub sp, sp")
    offset = hex(results[-1]["offset"])
    r2.cmd("s " + str(offset))
    r2.cmd("wao ret0")
    r2.quit()


def patch_function_arm(lib):
    print("Finding function offset in " + lib)
    r2 = r2pipe.open(lib, ["-w", "-2"])
    r2.cmd('aae')
    results = r2.cmdj('/j HandleVerifyResult')
    offset = results[0]['offset']
    results = r2.cmdj('axtj ' + str(offset))
    usage_offset = results[0]['from']
    r2.cmd("s " + str(usage_offset))
    r2.cmd("e search.from="+str(usage_offset-1000))
    r2.cmd("e search.to="+str(usage_offset))

    results = r2.cmdj("/badj sub sp")
    offset = hex(results[-1]["offset"]-4)
    r2.cmd("s " + str(offset))
    r2.cmd("wao ret0")
    r2.quit()


def patch_function(lib, arch):
    if arch == "arm64-v8a":
        return patch_function_arm64(lib)
    elif arch == "armeabi-v7a":
        return patch_function_arm(lib)
    else:
        raise Exception("Architecture not supported")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Static patch for libsscronet.so')
    parser.add_argument("-i", "--input", type=str,
                        help="libsscronet.so file.", required=True)
    
    parser.add_argument("-a", "--arch", type=str,
                        help="App arch [arm64-v8a|armeabi-v7a]", required=True)

    args = parser.parse_args()
    lib = args.input
    arch = args.arch

    shutil.copy(lib, "libsscronet_patched.so")

    patch_function(lib, arch)
    print("Done!")

