import r2pipe
from zipfile import ZipFile
import tempfile
import argparse


def find_function_arm64(lib):
    print("Finding function offset in " + lib)
    
    r2 = r2pipe.open(lib, ["-2"])
    
    r2.cmd('aae')
    results = r2.cmdj('/xj 56 65 72 69 66 79 43 65 72 74 00')
    offset = results[0]['offset']
    results = r2.cmdj('axtj ' + str(offset))
    results = [x for x in results if x['type'] == "STRN"]
    usage_offset = results[1]['from']
    r2.cmd("s " + str(usage_offset))

    r2.cmd("e search.from="+str(usage_offset-1000))
    r2.cmd("e search.to="+str(usage_offset))
    results = r2.cmdj("/badj sub sp, sp")
    r2.quit()
    offset = hex(results[-1]["offset"])
    return offset



def find_function_arm(lib):
    print("Finding function offset in " + lib)
    r2 = r2pipe.open(lib, ["-2"])
    r2.cmd('aae')
    results = r2.cmdj('/xj 56 65 72 69 66 79 43 65 72 74 00')
    offset = results[0]['offset']
    results = r2.cmdj('axtj ' + str(offset))
    usage_offset = results[0]['from']

    r2.cmd("s " + str(usage_offset))

    r2.cmd("e search.from="+str(usage_offset-1000))
    r2.cmd("e search.to="+str(usage_offset))

    results = r2.cmdj("/badj sub sp")
    r2.quit()
    offset = hex(results[-1]["offset"]-4)
    return offset


def find_function_offset(lib, arch):
    if arch == "arm64-v8a":
        return find_function_arm64(lib)
    elif arch == "armeabi-v7a":
        return find_function_arm(lib)
    else:
        raise Exception("Architecture not supported")


def find_function_from_apk(apk, arch):
    libname = "libsscronet.so"
    lib = extract_lib_for_apk(apk, arch, libname)
    return find_function_offset(lib, arch)


def extract_lib_for_apk(apk, arch, lib):
    with ZipFile(apk) as zip_file:
        namelist = zip_file.namelist()
        libname = "lib/{0}/{1}".format(arch, lib)
        if libname in namelist:
            print("Extracting:", libname)
            return zip_file.extract(libname, tempfile.gettempdir())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Finds offset of the function which verifies certificate chain.')
    parser.add_argument("-i", "--input", type=str,
                        help="Input apk file.", required=True)

    args = parser.parse_args()
    apk = args.input

    arm_offset = find_function_from_apk(apk, "armeabi-v7a")
    arm64_offset = find_function_from_apk(apk, "arm64-v8a")

    print("arm offset:", arm_offset)
    print("arm64 offset:", arm64_offset)
