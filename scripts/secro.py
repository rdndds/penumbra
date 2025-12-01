#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Shomy
# SPDX-License-Identifier: AGPL-3.0-or-later
#
import struct
from dataclasses import dataclass, is_dataclass
from enum import Enum, auto
from hashlib import sha1
from typing import Final, Type, TypeVar

T = TypeVar("T")


AC_SV5_MAGIC: Final[int] = 0x35353535
AC_MD2_MAGIC: Final[int] = 0x36363636
AC_SV5_MAGIC_MD_V5A: Final[int] = 0x37373737
AC_ANDRO_MAGIC: Final[int] = 0x41414141
AC_MD_INFO_MAGIC: Final[int] = 0x42424242
AC_H_MAGIC: Final[int] = 0x48484848
SW_SEC_BOOT_MAGIC: Final[int] = 0x57575757
MD2_SECRO_MAX_LEN: Final[int] = 4092
AP_SECRO_MAX_LEN: Final[int] = 2672
AND_SECROIMG_SIZE: Final[int] = 0x2C00
SV5_SECRO_MAX_LEN: Final[int] = 8188
MD_V5A_SECRO_MAX_LEN: Final[int] = 8188

FACTORY_EN_CODE = 0x45  # In AC_ANDRO, after SML key


AC_H_FORMAT: Final[str] = "<16s11I2B2s"
AC_ANDRO_FORMAT: Final[str] = "<I32sB11s"  # + SW_SEC_BOOT_FORMAT + 2672s
SW_SEC_BOOT_FORMAT: Final[str] = "<17I128sII52s"
SV5_FORMAT: Final[str] = "<I8188s"


class SwSecBootFeatureSupport(Enum):
    DISABLE = 0
    ENABLE = 1


class SwSecBootLock(Enum):
    UNKNOWN = 0
    LOCK = 1
    UNLOCK = 2


class SwSecBootCert(Enum):
    PER_PROJECT = 1
    PER_DEVICE = 2


class SwSecBootTry(Enum):
    NOT_TRY = auto()
    TRY_LOCK = auto()
    TRY_UNLOCK = auto()


class SwSecBootDone(Enum):
    NOT_DONE = auto()
    DONE_LOCKED = auto()
    DONE_UNLOCKED = auto()


class SwSecBootChk(Enum):
    CHECK_IMG = 1
    NOT_CHECK_IMG = 2


@dataclass
class AndSwSecBoot:
    magic_number: int
    flashtool_unlock_support: SwSecBootFeatureSupport
    lock_type: SwSecBootLock
    dl_format_check: SwSecBootLock
    dl_1st_loader_lock: SwSecBootLock
    dl_2nd_loader_lock: SwSecBootLock
    dl_image_lock: SwSecBootLock
    boot_chk_2nd_loader: SwSecBootChk
    boot_chk_logo: SwSecBootChk
    boot_chk_bootimg: SwSecBootChk
    boot_chk_recovery: SwSecBootChk
    boot_chk_system: SwSecBootChk
    boot_chk_others: SwSecBootChk
    fastboot_unlock_support: SwSecBootFeatureSupport
    fastboot_unlock_unsigned: int
    clean_keybox: int
    cert_type: SwSecBootCert
    cert_device_id: bytes  # 128
    boot_chk_cust1: SwSecBootChk
    boot_chk_cust2: SwSecBootChk
    reserve: bytes  # 52


@dataclass
class AndACHeader:
    m_identifier: bytes  # 16, AND_AC_REGION
    magic_number: int
    region_length: int
    region_offset: int
    hash_length: int
    hash_offset: int
    andro_length: int
    andro_offset: int
    sv5_length: int  # md1_len
    sv5_offset: int  # md1_offset
    md2_length: int
    md2_offset: int
    world_phone_support: bool
    world_phone_md_count: int  # uchar
    reserve: bytes  # 2


@dataclass
class AndACAndro:
    magic_number: int
    sml_aes_key: bytes  # 32
    factory_en: int  # 1
    reserve1: bytes  # 11
    sw_sec_boot: AndSwSecBoot
    reserve2: bytes  # 2672


@dataclass
class AndACMD:
    magic_number: int
    reserve: bytes  # 4092


@dataclass
class AndACSV5:
    magic_number: int
    reserve: bytes  # 8188 # Md stored here


@dataclass
class SecroImg:
    data: bytes
    old_format: bool
    header: AndACHeader
    andro: AndACAndro
    sv5: AndACSV5  # V3 (8192)
    hash: bytes  # 32 (sha1?)
    padding: bytes  # 0x400


def unpack_dataclass(fmt: str, data: bytes, cls: Type[T]) -> T:
    if not is_dataclass(cls):
        raise ValueError("cls must be a dataclass type")

    raw = struct.unpack(fmt, data[: struct.calcsize(fmt)])
    fields = []

    for value, field in zip(raw, cls.__dataclass_fields__.values()):
        ftype = field.type

        if isinstance(ftype, type) and issubclass(ftype, Enum):
            fields.append(ftype(value))
        else:
            fields.append(value)

    return cls(*fields)


def parse_secro(data: bytes) -> SecroImg:
    if len(data) < AND_SECROIMG_SIZE - 0x40C:  # - Padding
        raise ValueError("Secro image too small")

    offset = 0
    ac_header = unpack_dataclass(AC_H_FORMAT, data, AndACHeader)

    assert ac_header.m_identifier.startswith(b"AND_AC_REGION")
    assert ac_header.magic_number == AC_H_MAGIC

    print(ac_header)

    old_format = ac_header.md2_offset == 0 and ac_header.md2_length == 0

    offset = ac_header.andro_offset

    SW_SEC_BOOT_SIZE = struct.calcsize(SW_SEC_BOOT_FORMAT)
    AC_ANDRO_SIZE = (
        struct.calcsize(AC_ANDRO_FORMAT) + SW_SEC_BOOT_SIZE + AP_SECRO_MAX_LEN
    )

    andro_data = data[offset : offset + AC_ANDRO_SIZE]
    sw_sec_boot_data = andro_data[
        struct.calcsize(AC_ANDRO_FORMAT) : struct.calcsize(AC_ANDRO_FORMAT)
        + SW_SEC_BOOT_SIZE
    ]

    sw_sec_boot = unpack_dataclass(SW_SEC_BOOT_FORMAT, sw_sec_boot_data, AndSwSecBoot)
    andro_unpacked = struct.unpack(
        AC_ANDRO_FORMAT, andro_data[: struct.calcsize(AC_ANDRO_FORMAT)]
    )

    andro = AndACAndro(
        magic_number=andro_unpacked[0],
        sml_aes_key=andro_unpacked[1],
        factory_en=andro_unpacked[2],
        reserve1=andro_unpacked[3],
        sw_sec_boot=sw_sec_boot,
        reserve2=andro_data[
            struct.calcsize(AC_ANDRO_FORMAT) + struct.calcsize(SW_SEC_BOOT_FORMAT) :
        ],
    )

    assert andro.magic_number == AC_ANDRO_MAGIC
    assert sw_sec_boot.magic_number == SW_SEC_BOOT_MAGIC

    offset = ac_header.sv5_offset
    sv5_data = data[offset : offset + struct.calcsize(SV5_FORMAT)]
    sv5 = unpack_dataclass(SV5_FORMAT, sv5_data, AndACSV5)
    assert sv5.magic_number == AC_SV5_MAGIC
    assert len(sv5.reserve) == SV5_SECRO_MAX_LEN

    if old_format:
        assert (b == 0 for b in sv5.reserve[:MD2_SECRO_MAX_LEN])
    else:
        md1_offset = ac_header.sv5_offset
        md1_data = data[md1_offset : md1_offset + struct.calcsize("<I4096s")]
        md1 = unpack_dataclass("<I4096s", md1_data, AndACMD)
        md2_offset = ac_header.md2_offset
        md2_data = data[md2_offset : md2_offset + struct.calcsize("<I4096s")]
        md2 = unpack_dataclass("<I4096s", md2_data, AndACMD)
        assert md1.magic_number == AC_SV5_MAGIC
        assert md2.magic_number == AC_MD2_MAGIC

    hash_offset = ac_header.hash_offset
    hash_length = ac_header.hash_length

    data_to_hash = data[:hash_offset]
    sha1_hash = sha1(data_to_hash).digest()

    stored_hash = data[hash_offset : hash_offset + hash_length]

    assert len(stored_hash) == 20
    assert sha1_hash == stored_hash, "Hash mismatch!"

    secro = SecroImg(
        data=data,
        old_format=old_format,
        header=ac_header,
        andro=andro,
        sv5=sv5,
        hash=stored_hash,
        padding=data[hash_offset + hash_length :],
    )

    return secro


def unlock_secro(secro: SecroImg) -> SecroImg:
    secro.andro.factory_en = FACTORY_EN_CODE
    secro.andro.sw_sec_boot.lock_type = SwSecBootLock.UNLOCK
    secro.andro.sw_sec_boot.dl_1st_loader_lock = SwSecBootLock.UNLOCK
    secro.andro.sw_sec_boot.dl_2nd_loader_lock = SwSecBootLock.UNLOCK
    secro.andro.sw_sec_boot.dl_image_lock = SwSecBootLock.UNLOCK
    secro.andro.sw_sec_boot.dl_format_check = SwSecBootLock.UNLOCK
    secro.andro.sw_sec_boot.fastboot_unlock_support = SwSecBootFeatureSupport.ENABLE
    secro.andro.sw_sec_boot.flashtool_unlock_support = SwSecBootFeatureSupport.ENABLE
    secro.andro.sw_sec_boot.boot_chk_logo = SwSecBootChk.NOT_CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_bootimg = SwSecBootChk.NOT_CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_recovery = SwSecBootChk.NOT_CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_system = SwSecBootChk.NOT_CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_others = SwSecBootChk.NOT_CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_2nd_loader = SwSecBootChk.NOT_CHECK_IMG
    secro.andro.sw_sec_boot.fastboot_unlock_unsigned = 1

    if not secro.old_format:
        secro.andro.sw_sec_boot.boot_chk_cust1 = SwSecBootChk.NOT_CHECK_IMG
        secro.andro.sw_sec_boot.boot_chk_cust2 = SwSecBootChk.NOT_CHECK_IMG

    return secro


def lock_secro(secro: SecroImg) -> SecroImg:
    secro.andro.factory_en = FACTORY_EN_CODE
    secro.andro.sw_sec_boot.lock_type = SwSecBootLock.LOCK
    secro.andro.sw_sec_boot.dl_1st_loader_lock = SwSecBootLock.LOCK
    secro.andro.sw_sec_boot.dl_2nd_loader_lock = SwSecBootLock.LOCK
    secro.andro.sw_sec_boot.dl_image_lock = SwSecBootLock.LOCK
    secro.andro.sw_sec_boot.dl_format_check = SwSecBootLock.LOCK
    secro.andro.sw_sec_boot.fastboot_unlock_support = SwSecBootFeatureSupport.DISABLE
    secro.andro.sw_sec_boot.flashtool_unlock_support = SwSecBootFeatureSupport.DISABLE
    secro.andro.sw_sec_boot.boot_chk_logo = SwSecBootChk.CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_bootimg = SwSecBootChk.CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_recovery = SwSecBootChk.CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_system = SwSecBootChk.CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_others = SwSecBootChk.CHECK_IMG
    secro.andro.sw_sec_boot.boot_chk_2nd_loader = SwSecBootChk.CHECK_IMG
    secro.andro.sw_sec_boot.fastboot_unlock_unsigned = 1

    if not secro.old_format:
        secro.andro.sw_sec_boot.boot_chk_cust1 = SwSecBootChk.CHECK_IMG
        secro.andro.sw_sec_boot.boot_chk_cust2 = SwSecBootChk.CHECK_IMG

    return secro


def create_secro(secro: SecroImg) -> bytes:
    ac_header_packed = struct.pack(
        AC_H_FORMAT,
        secro.header.m_identifier,
        secro.header.magic_number,
        secro.header.region_length,
        secro.header.region_offset,
        secro.header.hash_length,
        secro.header.hash_offset,
        secro.header.andro_length,
        secro.header.andro_offset,
        secro.header.sv5_length,
        secro.header.sv5_offset,
        secro.header.md2_length,
        secro.header.md2_offset,
        int(secro.header.world_phone_support),
        secro.header.world_phone_md_count,
        secro.header.reserve,
    )

    andro_packed = struct.pack(
        AC_ANDRO_FORMAT,
        AC_ANDRO_MAGIC,
        secro.andro.sml_aes_key,
        secro.andro.factory_en,
        secro.andro.reserve1,
    )

    sw_sec_boot = secro.andro.sw_sec_boot
    sw_sec_boot_packed = struct.pack(
        SW_SEC_BOOT_FORMAT,
        sw_sec_boot.magic_number,
        sw_sec_boot.flashtool_unlock_support.value,
        sw_sec_boot.lock_type.value,
        sw_sec_boot.dl_format_check.value,
        sw_sec_boot.dl_1st_loader_lock.value,
        sw_sec_boot.dl_2nd_loader_lock.value,
        sw_sec_boot.dl_image_lock.value,
        sw_sec_boot.boot_chk_2nd_loader.value,
        sw_sec_boot.boot_chk_logo.value,
        sw_sec_boot.boot_chk_bootimg.value,
        sw_sec_boot.boot_chk_recovery.value,
        sw_sec_boot.boot_chk_system.value,
        sw_sec_boot.boot_chk_others.value,
        sw_sec_boot.fastboot_unlock_support.value,
        sw_sec_boot.fastboot_unlock_unsigned,
        sw_sec_boot.clean_keybox,
        sw_sec_boot.cert_type.value,
        sw_sec_boot.cert_device_id,
        sw_sec_boot.boot_chk_cust1.value,
        sw_sec_boot.boot_chk_cust2.value,
        sw_sec_boot.reserve,
    )

    secro_data = (
        ac_header_packed
        + andro_packed
        + sw_sec_boot_packed
        + secro.andro.reserve2
        + secro.sv5.magic_number.to_bytes(4, "little")
        + secro.sv5.reserve
    )

    # Recalculate hash
    hash_offset = secro.header.hash_offset
    data_to_hash = secro_data[:hash_offset]
    sha1_hash = sha1(data_to_hash).digest()
    secro_data += sha1_hash

    return secro_data


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <secro_img> [<lock|unlock> <output_img>]")
        print()
        print("Arguments:")
        print("  <secro_img>       Input secro image")
        print("  <lock|unlock>     (Optional) Must be provided together with <output_img>")
        print("  <output_img>      (Optional) Output image; must be provided together with <lock|unlock>")

        sys.exit(1)

    secro_img_path = sys.argv[1]
    action = ""
    output_img_path = ""
    if len(sys.argv) == 4:
        action = sys.argv[2].lower()
        output_img_path = sys.argv[3]

    with open(secro_img_path, "rb") as f:
        secro_data = f.read()

    secro_img = parse_secro(secro_data)

    print("Secro image parsed successfully.")

    print("=" * 40)
    print("Secro Image Details:")
    print(f"Old Format: {secro_img.old_format}")
    print(f"Hash: {secro_img.hash.hex()}")
    print("=" * 40)
    print("AC Header:")
    print(f"Region Start: {hex(secro_img.header.region_offset)}")
    print(f"Region Length: {secro_img.header.region_length}")
    print(f"MD1 Offset: {hex(secro_img.header.sv5_offset)}")
    print(f"MD1 Length: {secro_img.header.sv5_length}")
    if not secro_img.old_format:
        print(f"MD2 Offset: {hex(secro_img.header.md2_offset)}")
        print(f"MD2 Length: {secro_img.header.md2_length}")
        print(f"World Phone Support: {secro_img.header.world_phone_support}")
        print(f"World Phone MD Count: {secro_img.header.world_phone_md_count}")
    print("=" * 40)
    print("Andro Section:")
    print(f"SML AES Key: {secro_img.andro.sml_aes_key.hex()}")
    print(f"Factory Enable: {secro_img.andro.factory_en == FACTORY_EN_CODE}")
    print("SW Sec Boot Configuration:")
    print(f"  Flashtool Unlock Support: {secro_img.andro.sw_sec_boot.flashtool_unlock_support.name}")
    print(f"  Lock Type: {secro_img.andro.sw_sec_boot.lock_type.name}")
    print(f"  DL Format Check: {secro_img.andro.sw_sec_boot.dl_format_check.name}")
    print(f"  DL 1st Loader Lock: {secro_img.andro.sw_sec_boot.dl_1st_loader_lock.name}")
    print(f"  DL 2nd Loader Lock: {secro_img.andro.sw_sec_boot.dl_2nd_loader_lock.name}")
    print(f"  DL Image Lock: {secro_img.andro.sw_sec_boot.dl_image_lock.name}")
    print(f"  Boot Check 2nd Loader: {secro_img.andro.sw_sec_boot.boot_chk_2nd_loader.name}")
    print(f"  Boot Check Logo: {secro_img.andro.sw_sec_boot.boot_chk_logo.name}")
    print(f"  Boot Check Bootimg: {secro_img.andro.sw_sec_boot.boot_chk_bootimg.name}")
    print(f"  Boot Check Recovery: {secro_img.andro.sw_sec_boot.boot_chk_recovery.name}")
    print(f"  Boot Check System: {secro_img.andro.sw_sec_boot.boot_chk_system.name}")
    print(f"  Boot Check Others: {secro_img.andro.sw_sec_boot.boot_chk_others.name}")
    print(f"  Fastboot Unlock Support: {secro_img.andro.sw_sec_boot.fastboot_unlock_support.name}")
    print(
        f"  Fastboot Unlock Unsigned: {secro_img.andro.sw_sec_boot.fastboot_unlock_unsigned}"
    )
    print(f"  Clean Keybox: {secro_img.andro.sw_sec_boot.clean_keybox}")
    print(f"  Cert Type: {secro_img.andro.sw_sec_boot.cert_type.name}")
    # print(f"  Cert Device ID: {str(secro_img.andro.sw_sec_boot.cert_device_id)}")
    if not secro_img.old_format:
        print(f"  Boot Check Cust1: {secro_img.andro.sw_sec_boot.boot_chk_cust1.name}")
        print(f"  Boot Check Cust2: {secro_img.andro.sw_sec_boot.boot_chk_cust2.name}")

    print("=" * 40)

    if action == "lock":
        print("Locking secro image...")
        locked_secro = secro_img
        with open(output_img_path, "wb") as f:
            f.write(create_secro(locked_secro))
            print(f"Locked secro image written to {output_img_path}")
    elif action == "unlock":
        print("Unlocking secro image...")
        unlocked_secro = unlock_secro(secro_img)
        with open(output_img_path, "wb") as f:
            f.write(create_secro(unlocked_secro))
            print(f"Unlocked secro image written to {output_img_path}")
