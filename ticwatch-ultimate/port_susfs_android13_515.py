#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
source = sys.argv[2] if len(sys.argv) > 2 else "unknown"


def read(rel):
    return (root / rel).read_text()


def write(rel, text):
    (root / rel).write_text(text)


def insert_before(rel, marker, block, guard):
    s = read(rel)
    if guard in s:
        return
    if marker not in s:
        raise SystemExit(f"cannot port {rel}: anchor not found: {marker!r}")
    s = s.replace(marker, block + marker, 1)
    write(rel, s)

# The current Android13-5.15 SuSFS patch has a header-context hunk that does
# not match either the TicWatch downstream source or the September AOSP tree.
# All functional task_mmu hunks apply; restore only the rejected include.
insert_before(
    "fs/proc/task_mmu.c",
    "#include <asm/elf.h>",
    "#if defined(CONFIG_KSU_SUSFS_SUS_KSTAT) || defined(CONFIG_KSU_SUSFS_SUS_MAP)\n"
    "#include <linux/susfs_def.h>\n"
    "#endif\n\n",
    "#include <linux/susfs_def.h>",
)

# September AOSP changed namespace.c's include context.  If its first SuSFS
# hunk was rejected, the later functional hunks are already present but need
# these declarations/IDs.  The TicWatch downstream source normally gets this
# hunk cleanly, so this is conditional and idempotent.
ns = read("fs/namespace.c")
if "susfs_mnt_id_ida" not in ns:
    anchor = '#include "pnode.h"'
    if anchor not in ns:
        raise SystemExit("cannot port fs/namespace.c: pnode.h anchor missing")
    block = (
        "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
        "#include <linux/susfs_def.h>\n"
        "#endif\n\n"
        "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
        "extern bool susfs_is_current_ksu_domain(void);\n"
        "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;\n\n"
        "#define CL_COPY_MNT_NS BIT(25) /* used by copy_mnt_ns() */\n\n"
        "static DEFINE_IDA(susfs_mnt_id_ida);\n"
        "static DEFINE_IDA(susfs_mnt_group_ida);\n"
        "#endif\n\n"
    )
    ns = ns.replace(anchor, block + anchor, 1)
    write("fs/namespace.c", ns)

# Winkmoon's exact TicWatch lineage already contains the legacy full-manual
# reboot hook.  SuSFS v2 inline mode needs the direct reboot supercall flow
# without CONFIG_KSU_MANUAL_HOOK, otherwise ReSukiSU's inline hook validator
# correctly rejects the mixed hook implementation.
rp = "kernel/reboot.c"
s = read(rp)
legacy = (
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
    "#endif\n"
)
inline = (
    "#ifdef CONFIG_KSU_SUSFS\n"
    "\tret = ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
    "\tif (ret)\n"
    "\t\tgoto orig_flow;\n"
    "\treturn ret;\n"
    "orig_flow:\n"
    "#endif\n"
)
if legacy in s:
    s = s.replace(legacy, inline, 1)
    write(rp, s)

# The extern must also be selected by the active inline mode.  Depending on
# which half of the upstream hunk applied, normalize it here.
s = read(rp)
s = s.replace(
    "#ifdef CONFIG_KSU_MANUAL_HOOK\nextern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n#endif",
    "#ifdef CONFIG_KSU_SUSFS\nextern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n#endif",
    1,
)
write(rp, s)

# Never hide a new/unexpected patch failure. Only these context rejects are
# accepted and repaired above. Anything else aborts the build.
allowed = {
    "fs/proc/task_mmu.c.rej",
    "fs/namespace.c.rej",
    "kernel/reboot.c.rej",
}
rejects = sorted(str(p.relative_to(root)) for p in root.rglob("*.rej"))
unexpected = [p for p in rejects if p not in allowed]
if unexpected:
    raise SystemExit("unexpected SuSFS rejects: " + ", ".join(unexpected))
for rel in rejects:
    (root / rel).unlink()

# Hard validation of the pieces required by the ReSukiSU inline checker and
# the SuSFS features enabled in the release config.
checks = {
    "fs/proc/task_mmu.c": ["susfs_def.h", "CONFIG_KSU_SUSFS_SUS_MAP"],
    "fs/namespace.c": ["susfs_mnt_id_ida", "susfs_is_sdcard_android_data_not_decrypted"],
    "kernel/reboot.c": ["#ifdef CONFIG_KSU_SUSFS", "ksu_handle_sys_reboot", "orig_flow:"],
}
for rel, needles in checks.items():
    data = read(rel)
    missing = [x for x in needles if x not in data]
    if missing:
        raise SystemExit(f"incomplete SuSFS port in {rel}: {missing}")

print(f"SuSFS deterministic Android13/5.15 port fixups OK ({source})")
