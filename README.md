# ida_py_ppc2c
PowerPC to C plugin for IDA converted to python.
- Modified version of Zak Stanborough's PPC2C plugin released as part of [Hex-Rays Plug-In Contest 2009](https://www.hex-rays.com/contests/2009/).

Changes
-------

- Ported to ida python 3.
- Fixed extrdi mask.
- Added clrrdi, clrlsldi, extldi, sldi, srdi, rotldi, rotrdi.
- Shifts print mask again.
- Removed BC opcodes, ida handle them fine nowdays.
- Added cr manipulation opcodes.
- New SIMPLIFY option to detect opcode pairs that can be used as advanced "and"/"and not" (enabled by default).
- More minor changes here and there.

 To scan single opcode push F10.
 To scan multiple opcodes, mark them with mouse, and push F10.
 To scan whole function, select any address inside function and press ALT + SHIFT + F10.

Examples
--------

    clrlsldi  r9, r31, 32,9   # r9 = (r31 << 9) & 0x1FFFFFFFE00
    clrlwi    r28, r28, 24    # r28 = r28 & 0xFF
    clrrwi    r6, r7, 2       # r6 = r7 & 0xFFFFFFFC
    extrdi    r3, r3, 5,38    # r3 = (r3 >> 21) & 0x1F
    insrdi    r0, r30, 4,60   # r0 = (r0 & ~0xF) | (r30 & 0xF)
    rldicl    r10, r7, 2,56   # r10 = ((r7 << 2) | (r7 >> 62)) & 0xFF
    rlwinm    r0, r0, 0,16,27 # r0 = r0 & 0xFFF0
    sldi      r7, r29, 3      # r7 = (r29 << 3) & 0xFFFFFFFFFFFFFFF8
    
	SIMPLIFY = 0 output:
    0x66EA4   rlwinm    r9, r0, 29,1,31   # r9 = ((r0 << 29) | (r0 >> 3)) & 0x7FFFFFFF
    0x66EB4   rotlwi    r9, r9, 3         # r9 = (r9 << 3) | (r9 >> 29)

	SIMPLIFY = 1 output:
    0x66EA4   rlwinm    r9, r0, 29,1,31   # Paired with rotlwi at 0x66EB4
    0x66EB4   rotlwi    r9, r9, 3         # r9 = r0 & ~0x4 (r0 from 0x66EA4)
	
	Warning! SIMPLIFY option edit comment for both locations.
	Regardless on which opcode of those 2 ida_py_ppc2c was used.
