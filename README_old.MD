PPC 2 C Plugin
==============
Modified version of Zak Stanborough's PPC2C plugin released as part of [Hex-Rays Plug-In Contest 2009](https://www.hex-rays.com/contests/2009/).

Overview
--------

This converts tricky PPC assembly instructions into C code by placing a comment
after the instruction. This makes it easy to understand what these instructions
are doing at a glance. At this stage only the instructions which are hard to
understand are converted into C code, but this plugin could be extended to
convert all instructions into C code.

Install
-------

Build and copy the PPC2C.plw and PPC2C.p64 files to your IDA\plugins directory.

You then need to either copy plugins.cfg into your IDA\plugins directory or add
the following line to your IDA\plugins\plugns.cfg file:

PPC_To_C:_Entire_Function		PPC2C		Ctrl-F10	1	; convert the current function to C

Usage
-----

Once installed the plugin can be used by opening an IDB file for the PPC
processor and then pressing F10 to convert the current line or currently
selected lines into C, or pressing Ctrl-F10 to convert all lines in the
current function into C code.

Example
-------

Examples of the C comments that are generated by this plugin are:

    bc  14, 4*cr7+eq, loc_800037A8 # if(cr7 is equal) goto loc_800037A8

    bc  7, eq, loc_80010B58   # if(cr0 is not equal) goto loc_80010B58

    clrlwi %r0, %r0, 31       # %r0 = %r0 & 1

    rldicr %r10, %r10, 24,39  # %r10 = ((%r10 << 24) | (%r10 >> 40)) & 0xFFFFFFFFFF000000

    rldicl %r4, %r4, 0,48     # %r4 = %r4 & 0xFFFF

    rldicl %r0, %r0, 0,59     # %r0 = %r0 & 0x1F

    rldicl %r9, %r9, 61,3     # %r9 = (%r9 >> 3) & 0x1FFFFFFFFFFFFFFF

    slwi %r9, %r9, 8          # %r9 = %r9 << 8