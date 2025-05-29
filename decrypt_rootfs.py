import sys
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from argparse import ArgumentParser
from hashlib import sha256
from Crypto.Cipher import ChaCha20, AES
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc3279
from tqdm import tqdm
import ctypes
import logging
import subprocess
import binascii
import pyfiglet


class crypto_ctx_ctr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("nonce", ctypes.c_uint64),
        ("counter", ctypes.c_uint64),
    ]


class crypto_ctx_ctr_u(ctypes.Union):
    _pack_ = 1
    _fields_ = [("ctr", crypto_ctx_ctr), ("counter", ctypes.c_uint8 * 16)]


class crypto_ctx(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("padding", ctypes.c_uint8 * 174),
        ("null", ctypes.c_uint8),
        ("rootfs_hash", ctypes.c_uint8 * 32),
        ("u", crypto_ctx_ctr_u),
        ("aes_key", ctypes.c_uint8 * 32),
    ]


def print_logo():
    ascii_art = pyfiglet.figlet_format("RANDORISEC")
    max_width = max(len(line) for line in ascii_art.split("\n"))
    print(ascii_art)
    print("https://randorisec.fr\n\n\n".center(max_width))


def resolve_register(expr):
    if expr.is_id():
        return expr.name

    if expr.is_slice() and expr.arg.is_id():
        base = expr.arg.name.upper()
        start = expr.start
        stop = expr.stop
        size = stop - start

        reg_aliases = {
            # format: (base, start, size): alias
            ("RAX", 0, 8): "AL",
            ("RAX", 0, 16): "AX",
            ("RAX", 0, 32): "EAX",
            ("RAX", 0, 64): "RAX",

            ("RBX", 0, 8): "BL",
            ("RBX", 0, 16): "BX",
            ("RBX", 0, 32): "EBX",
            ("RBX", 0, 64): "RBX",

            ("RDX", 0, 8): "DL",
            ("RDX", 0, 16): "DX",
            ("RDX", 0, 32): "EDX",
            ("RDX", 0, 64): "RDX",

            ("RCX", 0, 8): "CL",
            ("RCX", 0, 16): "CX",
            ("RCX", 0, 32): "ECX",
            ("RCX", 0, 64): "RCX",

            # Extend as needed
        }

        return reg_aliases.get((base, start, size), f"{base}[{start}:{stop}]")

    return None


def locate_fgt_verify_initrd(file_flatkc):
    output = subprocess.check_output(
        f"""
        objdump -d --section=.init.text {file_flatkc} |
        egrep "rsa_parse_pub_key|push.*rbp" |
        egrep "rsa_parse_pub_key" -B1 |
        head -1 |
        cut -d':' -f1
        """,
        shell=True,
    ).decode()

    seed_addr = int(output, 16)
    logging.debug(f"SEED address found: {hex(seed_addr)}")
    return seed_addr


def search_MOVs(reg):
    machine = Machine(container.arch)
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    asmcfg = mdis.dis_multiblock(fgt_verify_initrd_addr)
    all_srcs = list()
    for block in asmcfg.blocks:
        for instr in block.lines:
            if instr.name == "MOV":
                dst, src = instr.get_args_expr()
                if (dst.is_id() and dst.name == reg) and src.is_int():
                    all_srcs.append(src.arg)
    return all_srcs


def get_seed():
    return min(search_MOVs("RSI"))


def get_rsapubkey_addr():
    return search_MOVs("RDX")[0]


def derivate_chacha20_params(seed):
    sha = sha256()
    sha.update(seed[5:])
    sha.update(seed[:5])
    key = sha.digest()
    sha = sha256()
    sha.update(seed[2:])
    sha.update(seed[:2])
    iv = sha.digest()[:16]
    return key, iv


def extract_chacha20_params(reg1, reg2):
    machine = Machine(container.arch)
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    asmcfg = mdis.dis_multiblock(fgt_verify_initrd_addr)
    all_srcs = []
    for block in asmcfg.blocks:
        if "sha256_update" not in block.to_string():
            continue

        reg1_val, reg2_val = 0, 0
        for instr in block.lines:
            if instr.name == "MOV":
                dst, src = instr.get_args_expr()

                if (resolve_register(dst) == reg1) and src.is_int():
                    reg1_val = src.arg

                if (resolve_register(dst) == reg2) and src.is_int():
                    reg2_val = src.arg

        all_srcs.append((reg1_val, reg2_val))
        if (len(all_srcs)) == 4:
            break

    if (len(all_srcs)) != 4:
        # Failed to find all components
        return None, None

    sha = sha256()
    sha.update(container.executable.get_virt().get(all_srcs[0][0], all_srcs[0][0] + all_srcs[0][1]))
    sha.update(container.executable.get_virt().get(all_srcs[1][0], all_srcs[1][0] + all_srcs[1][1]))
    key = sha.digest()

    sha = sha256()
    sha.update(container.executable.get_virt().get(all_srcs[2][0], all_srcs[2][0] + all_srcs[2][1]))
    sha.update(container.executable.get_virt().get(all_srcs[3][0], all_srcs[3][0] + all_srcs[3][1]))
    iv = sha.digest()[:16]

    return key, iv


def decrypt_rsapubkey(rsapubkey_data, key, iv):
    chacha = ChaCha20.new(key=key, nonce=iv[4:])
    counter = int.from_bytes(iv[:4], "little")
    chacha.seek(counter * 64)
    rsapubkey = chacha.decrypt(rsapubkey_data)
    return rsapubkey


def decrypt_rootfs_sig(rootfs_sig, decoded_key):
    res = pow(
        int.from_bytes(rootfs_sig, "big"),
        int(decoded_key["publicExponent"]),
        int(decoded_key["modulus"]),
    )

    num_bytes = (res.bit_length() + 7) // 8
    assert num_bytes == 255, "signature broken"

    logging.debug(f"sig: {binascii.hexlify(res.to_bytes(num_bytes, "big")).upper()}")

    sig_struct = crypto_ctx()
    ctypes.memmove(ctypes.byref(sig_struct), res.to_bytes(num_bytes, "big"), num_bytes)
    return sig_struct


def decrypt_rootfs(file_rootfs_dec, rootfs_enc):
    ctr_increment = 0
    for i in range(ctypes.sizeof(sig_struct.u.counter)):
        ctr_increment = (
            ctr_increment
            ^ (sig_struct.u.counter[i] & 0xF)
            ^ (sig_struct.u.counter[i] >> 4)
        )

    logging.debug(f"AES-CTR increment: {ctr_increment}")

    cipher = AES.new(bytes(sig_struct.aes_key), AES.MODE_ECB)
    blk_off = 0
    rootfs_dec = bytes()
    fd_out = open(file_rootfs_dec, "wb")
    with tqdm(total=len(rootfs_enc)) as pbar:
        while blk_off < len(rootfs_enc):
            keystream = cipher.encrypt(sig_struct.u.counter)
            fd_out.write(
                bytes(
                    [
                        b ^ k
                        for b, k in zip(
                            rootfs_enc[blk_off : blk_off + AES.block_size], keystream
                        )
                    ]
                )
            )
            sig_struct.u.ctr.counter += max(ctr_increment, 1)
            blk_off += AES.block_size
            pbar.update(AES.block_size)

        if len(rootfs_enc) % AES.block_size > 0:
            keystream = cipher.encrypt(sig_struct.u.counter)
            fd_out.write(
                bytes([b ^ k for b, k in zip(rootfs_enc[blk_off:], keystream)])
            )


if __name__ == "__main__":
    print_logo()
    parser = ArgumentParser(description="Decrypt FortiGate rootfs.gz")
    parser.add_argument("flatkc", help="`flatkc` kernel ELF binary")
    parser.add_argument("rootfs", help="encrypted `rootfs.gz` file")
    parser.add_argument("rootfs_dec", help="output for decrypted file")
    parser.add_argument("--debug", action="store_true", help="print debug info")
    options = parser.parse_args()

    log_lvl = logging.DEBUG if options.debug else logging.INFO
    logging.basicConfig(level=log_lvl, format="[%(levelname)s] %(message)s")

    with open(options.rootfs, "rb") as fd:
        data = fd.read()
        rootfs_enc, rootfs_sig = data[:-256], data[-256:]

    logging.info(f"Retrieving crypto material...")

    fgt_verify_initrd_addr = locate_fgt_verify_initrd(options.flatkc)
    loc_db = LocationDB()
    container = Container.from_stream(open(options.flatkc, "rb"), loc_db)
    # seed_addr = get_seed()
    # seed_data = container.executable.get_virt().get(seed_addr, seed_addr + 32)
    # logging.debug(f"SEED: {binascii.hexlify(seed_data).upper()}")

    rsapubkey_addr = get_rsapubkey_addr()
    rsapubkey_data = container.executable.get_virt().get(
        rsapubkey_addr, rsapubkey_addr + 270
    )
    logging.debug(f"RSAPUBKEY: {binascii.hexlify(rsapubkey_data).upper()}")

    # key, iv = derivate_chacha20_params(seed_data)
    key, iv = extract_chacha20_params("RSI", "EDX")
    if key == None or iv == None:
        logging.error("Failed to extract key or iv")
        sys.exit(1)

    logging.debug(f"key: {binascii.hexlify(key).upper()}")
    logging.debug(f"iv: {binascii.hexlify(iv).upper()}")

    decoded_key, _ = decoder.decode(
        decrypt_rsapubkey(rsapubkey_data, key, iv), asn1Spec=rfc3279.RSAPublicKey()
    )

    sig_struct = decrypt_rootfs_sig(rootfs_sig, decoded_key)

    logging.debug(f"AES key: {binascii.hexlify(bytes(sig_struct.aes_key)).upper()}")
    logging.debug(
        f"AES counter: {binascii.hexlify(bytes(sig_struct.u.counter)).upper()}"
    )

    sha = sha256()
    sha.update(rootfs_enc)
    assert sha.digest() == bytes(sig_struct.rootfs_hash), "rootfs corrupted?"

    logging.info(f"Decrypting {options.rootfs}...")
    decrypt_rootfs(options.rootfs_dec, rootfs_enc)
    logging.info("DONE.")
