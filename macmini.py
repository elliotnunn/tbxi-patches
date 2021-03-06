#!/usr/bin/env python3

import patch_common
import cfmtool
from ppcasm import assemble

from os import path
import shutil
import os
import struct
import fnmatch
import tempfile
from ast import literal_eval as eval


src, cleanup = patch_common.get_src(desc='''
Boot the Mac mini. Works on Mac OS ROM v6.7 and later (Mac OS 9.1, late '01).
First, patches the boot script to (a) add PowerMac10,1/2 to the COMPATIBLE tag,
(b) pretend that the machine is a Cube and (c) add a prim-info property to the
PMU device. Second, patches the NanoKernel to prevent the CPU Plugin from
hanging when a THRM register access silently fails. Third, if necessary, patches
the Kauai ATA driver into old ROMs (pre-9.1).
Fourth, patches and inserts a native driver parcel for the ATI Radeon 9200
(ATY,RockHopper2), to enable acceleration with the c.2005 ATI Extensions.
''')


def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def patch_nk_proc_table(orig):
    try:
        code = bytearray(orig)

        # find the processor flags table, and make our glorious G4 known...
        # our reference point is the ConfigInfo-tyle 601 info, which comes right after
        tbl = code.index(b'\x00\x00\x10\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x20\x00\x20\x00\x01\x00\x40\x00\x40\x00\x20\x00\x20\x00\x20\x00\x08\x00\x08\x01\x00\x00\x02')
        num_entries = 0
        for i in reversed(range(0, tbl, 4)):
            if code[i] and code[i+1]:
                break
            num_entries += 1

        assert num_entries == 32
        tbl -= (1+1+4) * num_entries
        print('NK PowerCall table patch: location @', hex(tbl))

        pvr = 16 + 3 # 0x8003

        code[tbl + pvr] = 0x23 # upper nib means use NAP bit, lower nib I can't remember
        tbl += num_entries
        code[tbl + pvr] = 2 # HID0_NHR_and_sleep
        tbl += num_entries
        struct.pack_into('>L', code, tbl + 4*pvr, 0x1F) # hasL2CR hasPLRUL1 hasTAU hasVMX hasMSSregs

        return bytes(code)

    except:
        print('NK PowerCall table patch: patch failed')
        return orig


# On the 7447a (or something), accesses to the THRM registers fail silently,
# causing the CPU Plugin to hang when asked to get the temp. Patch the NK to
# test for a non-THRM CPU, and return an error in this case. (The NK is involved
# because it invokes the CPUP fragment in supervisor mode in response to an
# MPCpuPlugin call.)

def patch_nk_mpcpuplugin(orig):
    try:
        # For picking apart PPC stuff, turn it into a list of longs...
        while len(orig) % 4: orig.append(b'\0') # first ensure 4-aligned
        code = [x for (x,) in struct.iter_unpack('>L', orig)]

        # find syscall dispatch routine
        for i in range(3, len(code)):
            if code[i] == 0x92E80020: # stw r23, 0x20(r8)
                if code[i-1] == 0x92E90020: # stw r23, 0x20(r9)
                    i -= 1 # ignore this annoying instruction

                if code[i-3] >> 16 == 0x3EE0 and code[i-2] >> 16 == 0x62F7 and code[i-1] == 0x7EF7CA14:
                    # lis r23, HI; ori r23, r23, LO; add r23, r23, r25
                    mpdisp = ((code[i-3] & 0xFFFF) << 16) + (code[i-2] & 0xFFFF)
                    if code[mpdisp//4] == 0x7C3042A6: continue # FP hander has same offset in diff table
                    print('NK MPCpuPlugin patch: MPDispatch @', hex(mpdisp))
                    break
                elif code[i-1] >> 16 == 0x3AF9: # addi r23, r25, LO
                    mpdisp = code[i-1] & 0xFFFF
                    if code[mpdisp//4] == 0x7C3042A6: continue # FP hander has same offset in diff table
                    print('NK MPCpuPlugin patch: MPDispatch @', hex(mpdisp))
                    break

        # find routine's table
        for i in range(mpdisp//4, len(code)):
            if code[i] & 0xFC000003 == 0x48000000: # short unconditional non-link jump to end of table
                mpcnt = (code[i] & 0x3FFFFFF) // 4 - 1
                mptab = (i + 1) * 4
                print('NK MPCpuPlugin patch: MPDispatchTable @', hex(mptab))
                break

        # MP calls invoked via "li r0, NUMBER; sc", and this is that number:
        kMPCPUPlugin = 46

        if mpcnt > kMPCPUPlugin:
            mpcpuplugin = code[mptab//4 + kMPCPUPlugin] + 4*kMPCPUPlugin # weird table
            print('NK MPCpuPlugin patch: MPCpuPlugin @', hex(mpcpuplugin))

            for i in range(mpcpuplugin//4, len(code)):
                if code[i] & 0xFC000003 == 0x48000000: # short unconditional non-link jump to call return routine
                    returnproc = sign_extend(code[i] & 0x3FFFFFF, 26) + i*4
                    print('NK MPCpuPlugin patch: return proc @', hex(returnproc))
                    break

            # insert our new implementation into the table
            code[mptab//4 + kMPCPUPlugin] = 4*len(code) - 4*kMPCPUPlugin

            print('NK MPCpuPlugin patch: new MPCpuPlugin @', hex(len(code)*4))

            # place our new implementation at the end of the NK
            code.extend([
                0x2C03000C, # cmpwi   r3, kGetProcessorTemp
                0x40820020, # bne     passthru
                0x7D1F42A6, # mfpvr   r8
                0x5508001E, # rlwinm  r8, r8, 0, 0xFFFF0000
                0x3D208003, # lis     r9, 0x8003
                0x7C084800, # cmpw    r8, r9
                0x4082000C, # bne     passthru
                0x3860CD2B, # li      r3, kCantReportProcessorTemperatureErr
                # place a return path branch here
                # place a passthru branch here
            ])

            # add those two unconditional branches
            for targ in [returnproc, mpcpuplugin]:
                inst = targ - len(code)*4
                inst = inst & 0x3FFFFFF
                inst |= 0x48000000
                code.append(inst)

        return b''.join(struct.pack('>L', x) for x in code)

    except:
        print('NK MPCpuPlugin patch: patch failed')
        return orig


# iBook G4            000000ff 00000060 00003e80 00017fb5 0202d607 00000000 00011300 46000220
# Power Mac G4 MDD    000000ff 0000002c 00030d40 0001e705 00003400 00000000 0000260d 46000270

#                                                ^^^^^^^^ public PM features
#                                                         ^^^^^^^^ private PM features
#                                                                           ^^^^ batt count

# FROM THE DARWIN SOURCES:

# // PUBLIC power management features
# // NOTE: this is a direct port from classic, some of these bits
# //       are obsolete but are included for completeness
# enum {
#   kPMHasWakeupTimerMask        = (1<<0),  // 1=wake timer is supported
#   kPMHasSharedModemPortMask    = (1<<1),  // Not used
#   kPMHasProcessorCyclingMask   = (1<<2),  // 1=processor cycling supported
#   kPMMustProcessorCycleMask    = (1<<3),  // Not used
#   kPMHasReducedSpeedMask       = (1<<4),  // 1=supports reduced processor speed
#   kPMDynamicSpeedChangeMask    = (1<<5),  // 1=supports changing processor speed on the fly
#   kPMHasSCSIDiskModeMask       = (1<<6),  // 1=supports using machine as SCSI drive
#   kPMCanGetBatteryTimeMask     = (1<<7),  // 1=battery time can be calculated
#   kPMCanWakeupOnRingMask       = (1<<8),  // 1=machine can wake on modem ring
#   kPMHasDimmingSupportMask     = (1<<9),  // 1=has monitor dimming support
#   kPMHasStartupTimerMask       = (1<<10), // 1=can program startup timer
#   kPMHasChargeNotificationMask = (1<<11), // 1=client can determine charger status/get notifications
#   kPMHasDimSuspendSupportMask  = (1<<12), // 1=can dim diplay to DPMS ('off') state
#   kPMHasWakeOnNetActivityMask  = (1<<13), // 1=supports waking upon receipt of net packet
#   kPMHasWakeOnLidMask          = (1<<14), // 1=can wake upon lid/case opening
#   kPMCanPowerOffPCIBusMask     = (1<<15), // 1=can remove power from PCI bus on sleep
#   kPMHasDeepSleepMask          = (1<<16), // 1=supports deep (hibernation) sleep
#   kPMHasSleepMask              = (1<<17), // 1=machine support low power sleep (ala powerbooks)
#   kPMSupportsServerModeAPIMask = (1<<18), // 1=supports reboot on AC resume for unexpected power loss
#   kPMHasUPSIntegrationMask     = (1<<19)  // 1=supports incorporating UPS devices into power source calcs
# };

# // PRIVATE power management features
# // NOTE: this is a direct port from classic, some of these bits
# //       are obsolete but are included for completeness.
# enum {
#   kPMHasExtdBattInfoMask       = (1<<0),  // Not used
#   kPMHasBatteryIDMask          = (1<<1),  // Not used
#   kPMCanSwitchPowerMask        = (1<<2),  // Not used 
#   kPMHasCelsiusCyclingMask     = (1<<3),  // Not used
#   kPMHasBatteryPredictionMask  = (1<<4),  // Not used
#   kPMHasPowerLevelsMask        = (1<<5),  // Not used
#   kPMHasSleepCPUSpeedMask      = (1<<6),  // Not used
#   kPMHasBtnIntHandlersMask     = (1<<7),  // 1=supports individual button interrupt handlers
#   kPMHasSCSITermPowerMask      = (1<<8),  // 1=supports SCSI termination power switch
#   kPMHasADBButtonHandlersMask  = (1<<9),  // 1=supports button handlers via ADB
#   kPMHasICTControlMask         = (1<<10), // 1=supports ICT control
#   kPMHasLegacyDesktopSleepMask = (1<<11), // 1=supports 'doze' style sleep
#   kPMHasDeepIdleMask           = (1<<12), // 1=supports Idle2 in hardware
#   kPMOpenLidPreventsSleepMask  = (1<<13), // 1=open case prevent machine from sleeping
#   kPMClosedLidCausesSleepMask  = (1<<14), // 1=case closed (clamshell closed) causes sleep
#   kPMHasFanControlMask         = (1<<15), // 1=machine has software-programmable fan/thermostat controls
#   kPMHasThermalControlMask     = (1<<16), // 1=machine supports thermal monitoring
#   kPMHasVStepSpeedChangeMask   = (1<<17), // 1=machine supports processor voltage/clock change
#   kPMEnvironEventsPolledMask   = (1<<18)  // 1=machine doesn't generate pmu env ints, we must poll instead 
# };

# // DEFAULT public and private features for machines whose device tree
# // does NOT contain this information (pre-Core99).

# // For Cuda-based Desktops

# #define kStdDesktopPMFeatures   kPMHasWakeupTimerMask         |\
#                                 kPMHasProcessorCyclingMask    |\
#                                 kPMHasDimmingSupportMask      |\
#                                 kPMHasStartupTimerMask        |\
#                                 kPMSupportsServerModeAPIMask  |\
#                                 kPMHasUPSIntegrationMask

# #define kStdDesktopPrivPMFeatures  kPMHasExtdBattInfoMask     |\
#                                    kPMHasICTControlMask       |\
#                                    kPMHasLegacyDesktopSleepMask

# #define kStdDesktopNumBatteries 0

# // For Wallstreet (PowerBook G3 Series 1998)

# #define kWallstreetPMFeatures   kPMHasWakeupTimerMask         |\
#                                 kPMHasProcessorCyclingMask    |\
#                                 kPMHasReducedSpeedMask        |\
#                                 kPMDynamicSpeedChangeMask     |\
#                                 kPMHasSCSIDiskModeMask        |\
#                                 kPMCanGetBatteryTimeMask      |\
#                                 kPMHasDimmingSupportMask      |\
#                                 kPMHasChargeNotificationMask  |\
#                                 kPMHasDimSuspendSupportMask   |\
#                                 kPMHasSleepMask

# #define kWallstreetPrivPMFeatures  kPMHasExtdBattInfoMask      |\
#                                    kPMHasBatteryIDMask         |\
#                                    kPMCanSwitchPowerMask       |\
#                                    kPMHasADBButtonHandlersMask |\
#                                    kPMHasSCSITermPowerMask     |\
#                                    kPMHasICTControlMask        |\
#                                    kPMClosedLidCausesSleepMask |\
#                                    kPMEnvironEventsPolledMask

# #define kStdPowerBookPMFeatures      kWallstreetPMFeatures
# #define kStdPowerBookPrivPMFeatures  kWallstreetPrivPMFeatures

# #define kStdPowerBookNumBatteries 2

# // For 101 (PowerBook G3 Series 1999)

# #define k101PMFeatures          kPMHasWakeupTimerMask         |\
#                                 kPMHasProcessorCyclingMask    |\
#                                 kPMHasReducedSpeedMask        |\
#                                 kPMDynamicSpeedChangeMask     |\
#                                 kPMHasSCSIDiskModeMask        |\
#                                 kPMCanGetBatteryTimeMask      |\
#                                 kPMHasDimmingSupportMask      |\
#                                 kPMHasChargeNotificationMask  |\
#                                 kPMHasDimSuspendSupportMask   |\
#                                 kPMHasSleepMask               |\
#                                 kPMHasUPSIntegrationMask

# #define k101PrivPMFeatures      kPMHasExtdBattInfoMask        |\
#                                 kPMHasBatteryIDMask           |\
#                                 kPMCanSwitchPowerMask         |\
#                                 kPMHasADBButtonHandlersMask   |\
#                                 kPMHasSCSITermPowerMask       |\
#                                 kPMHasICTControlMask          |\
#                                 kPMClosedLidCausesSleepMask   |\
#                                 kPMEnvironEventsPolledMask

# #define IOPMNoErr       0   // normal return

#                         // returned by powerStateWillChange and powerStateDidChange:
# #define IOPMAckImplied      0   // acknowledgement of power state change is implied
# #define IOPMWillAckLater    1   // acknowledgement of power state change will come later

#                         // returned by requestDomainState
# #define IOPMBadSpecification    4   // unrecognized specification parameter
# #define IOPMNoSuchState     5   // no power state matches search specification

# #define IOPMCannotRaisePower    6   // a device cannot change its power for some reason

#                         // returned by changeStateTo
# #define IOPMParameterError  7   // requested state doesn't exist
# #define IOPMNotYetInitialized   8   // device not yet fully hooked into power management "graph"


FORTH = r'''
\ Hacks for Mac mini, should not affect other machines
" /" select-dev " model" active-package get-package-property 0= if
    decode-string 2swap 2drop 2dup " PowerMac10,1" $= -rot " PowerMac10,2" $= or if

        \ Pretend to be a Power Mac G4 Cube
        " /" select-dev
            " PowerMac5,1" encode-string 2dup
            " model" property
            " MacRISC" encode-string encode+
            " MacRISC2" encode-string encode+
            " Power Macintosh" encode-string encode+
            " compatible" property
        device-end

        \ Pretend to have a PowerPC 7445/55, actual PVR unaffected
        " /cpus/PowerPC,G4@0" select-dev
            80010201 encode-int " cpu-version" property
        device-end

        \ Set prim-info (for PwrMgr v2 in NativePowerMgrLib)
        " via-pmu/power-mgt" select-dev
            000000ff encode-int
            0000002c encode-int encode+
            00030d40 encode-int encode+
            0001e705 encode-int encode+     \ public features
            00001400 encode-int encode+     \ private features
            00000000 encode-int encode+
            0000260d encode-int encode+
            46000270 encode-int encode+
            " prim-info" property
        device-end

    then
then \ End of mini hacks
'''.strip()

def patch_booter(text):
    text = text.replace('<COMPATIBLE>\n', '<COMPATIBLE>\nPowerMac10,1 PowerMac10,2 ', 1)
    text = text.replace('<BOOT-SCRIPT>', '<BOOT-SCRIPT>\n'+FORTH, 1)
    return text


# The Mini's Radeon 9200 is an ATY,RockHopper2 with PCI device ID 5962, which is
# unknown to ATI's OS 9 driver package. First, we need an ndrv, which would
# usually be shipped in the card ROM and sometimes replaced by the "ATI ROM
# Xtender". Mac OS X shipped with 200+ of these, and darthnVader found that the
# RockHopper2 ndrv from 10.3.6 works great, while 10.3.8+ has a graypage problem.
# We use the "parcel" mechanism to insert this into the device tree. To enable
# acceleration, the on-disk ATI extensions require Status 128 (ATIGetInfo) calls
# to the ndrv to return a known device ID (offset 0x4e in the struct). ID 5961
# (also Radeon 9200) seems to keep everything happy. The code below patches reads
# from PCI config space to this end. (The extensions passed around in
# "9200os9.sit", supposedly for the DVI-I Radeon 9200, do not work. The accl 4
# "GraphicsAccelerationR6" resource of ATI Graphics Accelerator has apparently
# been bin-patched to replace 5961 with 5960.)

def patch_rockhopper_ndrv(src, dest=None):
    with tempfile.TemporaryDirectory() as tmp:
        cfmtool.dump(src, tmp)

        glue_file = eval(open(path.join(tmp, 'hdump', 'codelocs-xtocglue.txt')).read())
        glue_info = next(d for d in glue_file if d['function'] == 'ExpMgrConfigReadLong')

        code_path = path.join(tmp, glue_info['section'])
        code = bytearray(open(code_path, 'rb').read())
        while len(code) % 4: code.append(0) # align just in case

        # All calls to ExpMgrConfigReadLong go through this "cross-TOC glue" function...
        glue_offset = glue_info['offset']
        glue_toc, = struct.unpack_from('>h', code, glue_offset + 2)

        print('ATY,RockHopper2 patch: catching %s to change device 0x5962 to 0x5961' % glue_info['function'])

        # ...So replace it with a branch to the end of the code
        code[glue_offset:glue_offset+4] = assemble('b %d' % (len(code) - glue_offset))
        for i in range(glue_offset+4, glue_offset+24, 4): code[i:i+4] = assemble('nop')

        code.extend(assemble(f"""
                mflr    r0                  # Standard stack setup
                stw     r0, 8(r1)
                stw     r2, 0x14(r1)        # Essential, caller uses this
                stwu    r1, -0x40(r1)

                stw     r4, 0x38(r1)        # Make the call,
                stw     r5, 0x3c(r1)        # but save the args first
                bl      ExpMgrConfigReadLong

                cmpwi   cr0, r3, 0          # If call failed, punt
                bne     cr0, return

                lwz     r4, 0x38(r1)        # If wrong address, punt
                cmpwi   cr0, r4, 0
                bne     cr0, return

                lwz     r5, 0x3c(r1)        # If wrong returned value, punt
                lwz     r8, 0(r5)
                lis     r7, 0x5962
                ori     r7, r7, 0x1002
                cmpw    cr0, r7, r8
                bne     cr0, return

                lis     r8, 0x5961          # Save the new returned value
                ori     r8, r8, 0x1002
                stw     r8, 0(r5)

            return:                         # Stack teardown
                lwz     r1, 0(r1)
                lwz     r0, 8(r1)
                mtlr    r0
                blr

            # r3=opaqueNRptr, r4=config_addr, r5=result_ptr
            ExpMgrConfigReadLong:
                lwz     r12, {glue_toc}(r2)
                stw     r2, 0x14(r1)
                lwz     r0, 0(r12)
                lwz     r2, 4(r12)
                mtctr   r0
                bctr
        """))

        open(code_path, 'wb').write(code)
        return cfmtool.build(tmp, dest)


for (parent, folders, files) in os.walk(src):
    folders.sort(); files.sort() # make it kinda deterministic
    for filename in files:
        full = path.join(parent, filename)

        if filename.startswith('NanoKernel'):
            code = open(full, 'rb').read()
            code = patch_nk_proc_table(code)
            code = patch_nk_mpcpuplugin(code)
            open(full, 'wb').write(code)

        elif filename == 'Bootscript':
            text = open(full).read()
            text = patch_booter(text)
            open(full, 'w').write(text)

        elif filename == 'Parcelfile':
            if not any(fnmatch.fnmatch(fn, 'kauai-ata*.pef') for fn in os.listdir(parent)):
                print('ROM lacks Kauai ATA driver (< ROM 9.1), patching it in') # the only known version
                shutil.copy(path.join(path.dirname(__file__), 'kauai-ata.pef'), parent)

                with open(full, 'a') as f:
                    f.write('prop flags=0x0000c a=kauai-ata b=ata\n')
                    f.write('\tndrv flags=0x00006 name=driver,AAPL,MacOS,PowerPC src=kauai-ata.pef.lzss\n\n')

            if not any(fnmatch.fnmatch(fn, 'ATY,RockHopper2*.pef') for fn in os.listdir(parent)):
                print('Adding ATY,RockHopper2 ndrv parcel (v1.0.1f63, OS X 10.3.6). Credit to darthnVader:')
                print('http://macos9lives.com/smforum/index.php/topic,2408.msg29393.html#msg29393')

                ndrv1 = path.join(path.dirname(__file__), 'ATY,RockHopper2-1.0.1f63-20040916.133447.pef')
                ndrv2 = path.join(parent, path.basename(ndrv1))
                shutil.copy(ndrv1, ndrv2)

                patch_rockhopper_ndrv(ndrv2, ndrv2)

                # compatible w/ ATY,RockHopper2 and device_type=display, override existing
                # must come before the cofb parcel
                with open(full, 'r+') as f:
                    lines = f.readlines()
                    idx = next(i for (i, ln) in enumerate(lines) if ' b=display' in ln)
                    lines[idx:idx] = ['prop flags=0x0000c a=ATY,RockHopper2 b=display\n',
                        '\tndrv flags=0x00004 name=driver,AAPL,MacOS,PowerPC src=%s\n\n' % path.basename(ndrv2)]
                    f.seek(0)
                    f.writelines(lines)

            if path.exists(path.join(parent, 'MotherBoardHAL.pef')):
                print('ROM has MotherBoardHAL (< ROM 6.7), therefore unlikely to work')

        elif filename == 'cicn_-20020':
            print('Patching Happy Mac as tradition dictates. Credit to MacTron:')
            print('http://macos9lives.com/smforum/index.php/topic,4354.msg30328.html#msg30328')
            shutil.copyfile(path.join(path.dirname(__file__), 'mactron.cicn'), full)


cleanup()
