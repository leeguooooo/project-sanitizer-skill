#!/usr/bin/env python3
"""
LLDB helpers for inspecting and safely mutating a libc++ std::string field
reached through a register (e.g. an object base in x22, field at +off).

Companion to references/analysis-methodology.md, section
"Mutating a C++ container field at runtime (without crashing the target)".

Why this exists
---------------
Blind-writing bytes into a std::string field crashes the target: if the
field currently holds a *long* (heap) string and you overwrite it with
short/inline bytes, you clobber the heap data pointer, and the next
allocator op aborts with "BUG IN CLIENT OF LIBMALLOC: memory corruption".
These helpers do the reads first, and offer two non-crashing write paths.

Load in an LLDB session:
    (lldb) command script import scripts/lldb_std_string_field.py

Then, at a breakpoint where the object base is in a register:
    (lldb) sstr_dump   x22 0x2b0        # read-only: decode + type the object
    (lldb) sstr_set    x22 0x2b0 hello  # safe rebuild (reads old flag, frees old buf)

ABI note: the long/short flag position is libc++-build-specific. This module
defaults to the layout where the flag is the MSB of the object's last byte
(base+0x17 for a 24-byte std::string) and long-form is {ptr@+0, size@+8,
cap@+0x10}. Confirm against the target's own SSO-check disassembly
(the `ldrsb Wt,[Xn,#f]` + `tbz/tbnz Wt,#31` pair) before trusting it.
"""

import lldb
import shlex

OBJ_SIZE = 0x18      # sizeof(std::string) on 64-bit libc++
FLAG_OFF = 0x17      # byte holding the long/short flag (last byte)


def _u64(data, off):
    return int.from_bytes(data[off:off + 8], "little")


def _read_obj(process, addr):
    err = lldb.SBError()
    data = process.ReadMemory(addr, OBJ_SIZE, err)
    if not err.Success():
        raise RuntimeError("read object @ 0x%x failed: %s" % (addr, err))
    return bytearray(data)


def decode_string(process, addr):
    """Return (is_long, text, heap_ptr_or_None). Read-only."""
    obj = _read_obj(process, addr)
    is_long = (obj[FLAG_OFF] & 0x80) != 0
    if is_long:
        ptr = _u64(obj, 0x00)
        size = _u64(obj, 0x08)
        err = lldb.SBError()
        raw = process.ReadMemory(ptr, min(size, 0x1000), err) if size else b""
        text = raw.decode("utf-8", "replace") if err.Success() else "<unreadable>"
        return True, text, ptr
    else:
        size = obj[FLAG_OFF] & 0x7f
        text = bytes(obj[0:size]).decode("utf-8", "replace")
        return False, text, None


def sstr_dump(debugger, command, result, internal_dict):
    """sstr_dump <base_reg> <hex_off> — read-only decode + object/vtable dump.

    Run across several breakpoint fires: if [base] (the vtable pointer) or
    the decoded value differs between fires at the SAME (bp, reg, off), the
    register is aliasing different objects across paths — the field is not a
    stable field. Confirm register provenance before trusting it.
    """
    args = shlex.split(command)
    if len(args) != 2:
        result.SetError("usage: sstr_dump <base_reg> <hex_off>")
        return
    reg, off = args[0], int(args[1], 16)
    frame = debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
    process = debugger.GetSelectedTarget().GetProcess()
    base = frame.FindRegister(reg).GetValueAsUnsigned()
    if base == 0:
        result.SetError("register %s is 0 on this path — wrong base?" % reg)
        return
    field = base + off
    vtable = lldb.SBError()
    vptr = process.ReadPointerFromMemory(base, vtable)
    is_long, text, heap = decode_string(process, field)
    result.AppendMessage("base(%s) = 0x%x   [base]=vtable 0x%x   (type it to confirm object identity)"
                         % (reg, base, vptr))
    result.AppendMessage("field @ 0x%x : %s  value=%r%s"
                         % (field, "LONG" if is_long else "short", text,
                            "  heap=0x%x" % heap if heap else ""))


def sstr_set(debugger, command, result, internal_dict):
    """sstr_set <base_reg> <hex_off> <new_string> — crash-safe field rebuild.

    Reads the OLD flag first: if the old form was long, frees the old heap
    buffer after installing the new value (else it leaks). Writes the whole
    24-byte object in one self-consistent form; never leaves the flag and
    contents disagreeing. Prefer swapping the upstream assignment source
    (see module docstring) when you can reach the assign call.
    """
    args = shlex.split(command)
    if len(args) < 3:
        result.SetError("usage: sstr_set <base_reg> <hex_off> <new_string>")
        return
    reg, off, new_s = args[0], int(args[1], 16), " ".join(args[2:])
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    frame = process.GetSelectedThread().GetSelectedFrame()
    base = frame.FindRegister(reg).GetValueAsUnsigned()
    field = base + off

    old_long, _, old_heap = decode_string(process, field)
    payload = new_s.encode("utf-8")
    err = lldb.SBError()

    if len(payload) <= OBJ_SIZE - 2:          # fits inline (short form)
        obj = bytearray(OBJ_SIZE)
        obj[0:len(payload)] = payload
        obj[FLAG_OFF] = len(payload)           # MSB clear = short, low bits = size
        process.WriteMemory(field, bytes(obj), err)
    else:                                       # long form: allocate in target
        buf = frame.EvaluateExpression("(void*)malloc(%d)" % (len(payload) + 1)).GetValueAsUnsigned()
        process.WriteMemory(buf, payload + b"\x00", err)
        obj = bytearray(OBJ_SIZE)
        obj[0x00:0x08] = buf.to_bytes(8, "little")
        obj[0x08:0x10] = len(payload).to_bytes(8, "little")
        cap = (len(payload) + 1) | (1 << 63)   # cap with long-flag MSB set
        obj[0x10:0x18] = cap.to_bytes(8, "little")
        process.WriteMemory(field, bytes(obj), err)

    if not err.Success():
        result.SetError("write failed: %s" % err)
        return

    if old_long and old_heap:                   # reclaim the old buffer, don't leak
        frame.EvaluateExpression("(void)free((void*)0x%x)" % old_heap)
        result.AppendMessage("freed old long buffer 0x%x" % old_heap)
    result.AppendMessage("set field @ 0x%x = %r (%s form)"
                         % (field, new_s, "short" if len(payload) <= OBJ_SIZE - 2 else "long"))


# --- swap-the-assignment-source pattern (safest hijack) -----------------------
# At a breakpoint on the assign call site (add Xd,base,#off; <load src>;
# bl basic_string::assign/operator=), rewrite the SOURCE argument registers
# before the call, letting libc++ allocate/manage storage. No manual heap
# writes => cannot corrupt the heap. Sketch:
#
#   def on_assign_bp(frame, bp_loc, internal_dict):
#       process = frame.GetThread().GetProcess()
#       payload = b"your-target\x00"
#       buf = frame.EvaluateExpression("(void*)malloc(%d)" % len(payload)).GetValueAsUnsigned()
#       err = lldb.SBError(); process.WriteMemory(buf, payload, err)
#       frame.FindRegister("x1").SetValueFromCString(str(buf))   # src ptr arg
#       frame.FindRegister("x2").SetValueFromCString(str(len(payload) - 1))  # len arg
#       return False   # continue; assign copies from your buffer


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f %s.sstr_dump sstr_dump" % __name__)
    debugger.HandleCommand("command script add -f %s.sstr_set sstr_set" % __name__)
    print("[lldb_std_string_field] loaded: sstr_dump, sstr_set")
