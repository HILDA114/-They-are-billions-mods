# -*- coding: utf-8 -*-
"""
TAB 游戏速度修改器（内存字段版）
================================

背景（为什么换方案）
--------------------
前一版做的是"挂钩系统计时 API，把经过的时间乘倍率"。实测证明对《亿万僵尸》
无效：引擎的游戏速度不是一个"问系统要时间"的结果，而是引擎对象里的一个
**数据字段**。所以再怎么改时钟都没用。

本工具走的正是各路修改器/CE 表的同一套路：
    在游戏进程里定位 DXVision.DXGame 实例，直接读写它的速度字段。

字段布局（来自 FearlessRevolution 社区表 TheyAreBillions.CT，作者 Tuuuup!，
脚本移植自游戏 1.1.3.18，与本机 1.1.4 同代）：

    _GameSpeed                          double  对象 +0x1D8
    _GameTime                           double  对象 +0x1E0
    _GameElapsedTime                    double  对象 +0x1E8
    _MaxGameSpeed                       float   对象 +0x224
    <GameTimeInt>k__BackingField        int32   对象 +0x228
    <GameElapsedTimeInt>k__BackingField int32   对象 +0x22C
    <ShowFrameRate>k__BackingField      byte    对象 +0x254

对象怎么找
----------
游戏自己代码里有一句：

    OnKeyDown+310:  48 B9 <8字节地址>      mov rcx, 0x00000183480B5C78
    OnKeyDown+31A:  48 8B 19               mov rbx,[rcx]
    OnKeyDown+31D:  48 8B 09               mov rcx,[rcx]
    OnKeyDown+320:  39 09                  cmp  [rcx],ecx
    OnKeyDown+322:  E8 ...                 call DXVision.DXGame::get_Paused

那个硬编码的 8 字节地址就是一个**存着 DXGame 实例的静态槽**。于是：

    1) 在游戏的可执行内存里搜特征 `48 B9 ??x8 48 8B 19 48 8B 09`
    2) 读出那 8 字节 = 静态槽地址 slot
    3) 读 slot 里的指针 = DXGame 实例
    4) 按上面的偏移读写字段

整个过程**只读定位、不挂钩、不改游戏代码**。唯一写入的是速度字段本身，
退出时按原值还原。

用法
----
    python tab_gspeed.py                # 定位 + 显示字段 + 交互命令（输数字设速度）
    python tab_gspeed.py --read         # 只读观测：确认找到的对象对不对（最安全，什么都不写）
    python tab_gspeed.py --set 5        # 定位后直接把 _GameSpeed 设成 5
    python tab_gspeed.py --fps on       # 打开游戏内屏幕帧率显示（写 ShowFrameRate=1）
    python tab_gspeed.py --pid 1234     # 直接指定进程 pid
    python tab_gspeed.py --selftest     # 自检：对合成的假目标验证"定位→取对象→读写→还原"全链路

交互命令：输正数设置速度值，0/r 回 1x，q 退出。定位耗时约 4 秒（扫 227 MB）。
"""

import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import subprocess
import sys
import threading
import time

# ----------------------------------------------------------------------------
# Win32
# ----------------------------------------------------------------------------
k32 = ctypes.WinDLL('kernel32', use_last_error=True)

HANDLE = wt.HANDLE
DWORD = wt.DWORD
BOOL = wt.BOOL
SIZE_T = ctypes.c_size_t

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
SYNCHRONIZE = 0x00100000
PROC_ACCESS = (PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
               PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE)

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
REGION_EXEC = (0x10, 0x20, 0x40, 0x80)      # E / ER / ERW / EWC

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', DWORD), ('cntUsage', DWORD), ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)), ('th32ModuleID', DWORD),
                ('cntThreads', DWORD), ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', ctypes.c_long), ('dwFlags', DWORD),
                ('szExeFile', ctypes.c_wchar * 260)]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', DWORD), ('RegionSize', SIZE_T), ('State', DWORD),
                ('Protect', DWORD), ('Type', DWORD)]


def _proto(dll, name, argtypes, restype):
    fn = getattr(dll, name)
    fn.argtypes = argtypes
    fn.restype = restype
    return fn


OpenProcess = _proto(k32, 'OpenProcess', [DWORD, BOOL, DWORD], HANDLE)
CloseHandle = _proto(k32, 'CloseHandle', [HANDLE], BOOL)
ReadProcessMemory = _proto(k32, 'ReadProcessMemory',
                           [HANDLE, ctypes.c_void_p, ctypes.c_void_p, SIZE_T, ctypes.POINTER(SIZE_T)], BOOL)
WriteProcessMemory = _proto(k32, 'WriteProcessMemory',
                            [HANDLE, ctypes.c_void_p, ctypes.c_void_p, SIZE_T, ctypes.POINTER(SIZE_T)], BOOL)
VirtualQueryEx = _proto(k32, 'VirtualQueryEx',
                        [HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), SIZE_T], SIZE_T)
VirtualAlloc = _proto(k32, 'VirtualAlloc', [ctypes.c_void_p, SIZE_T, DWORD, DWORD], ctypes.c_void_p)
CreateToolhelp32Snapshot = _proto(k32, 'CreateToolhelp32Snapshot', [DWORD, DWORD], HANDLE)
Process32FirstW = _proto(k32, 'Process32FirstW', [HANDLE, ctypes.POINTER(PROCESSENTRY32W)], BOOL)
Process32NextW = _proto(k32, 'Process32NextW', [HANDLE, ctypes.POINTER(PROCESSENTRY32W)], BOOL)
SetConsoleOutputCP = _proto(k32, 'SetConsoleOutputCP', [ctypes.c_uint], BOOL)
SetConsoleCtrlHandler = _proto(k32, 'SetConsoleCtrlHandler', [ctypes.c_void_p, BOOL], BOOL)
GetConsoleWindow = _proto(k32, 'GetConsoleWindow', [], HANDLE)
SetConsoleTitleW = _proto(k32, 'SetConsoleTitleW', [ctypes.c_wchar_p], BOOL)

# ----------------------------------------------------------------------------
# 字段偏移（社区 CE 表 + 本机 1.1.4 实机校验）
# ----------------------------------------------------------------------------
OFF_OBJ_BASE = 0x1D8          # _GameSpeed 相对 DXGame 实例的偏移
OFF_GAME_SPEED = 0x1D8        # 唯一要写的字段
OFF_GAME_TIME = 0x1E0
OFF_GAME_ELAPSED = 0x1E8
OFF_MAX_SPEED = 0x224         # 只读参考，绝不写
OFF_GAME_TIME_INT = 0x228     # <GameTimeInt>，定位用的镜像指纹
OFF_GAME_ELAPSED_INT = 0x22C
OFF_SHOW_FPS = 0x254

SPAN = OFF_SHOW_FPS + 8       # 一次读这么多字节就够

# 定位：x64 `REX.W movabs reg, imm64` 的机器码是 48-4F B8-BF + 8 字节立即数
MOVABS_RE = re.compile(rb'[\x48-\x4f][\xb8-\xbf]')
SANE_PTR_LO = 0x10000
SANE_PTR_HI = 0x00007FFFFFFFFFFF

CHUNK = 4 * 1024 * 1024
MAX_SCAN = 900 * 1024 * 1024

# 实测（1.1.4，暂停中的对局）：字段值 -> 实际模拟倍速（受 CPU/FPS 饱和）
#   2 -> 1.8x    3 -> 2.6x    5 -> 3.9x    8 -> 5.0x    10 -> 7.3x    12 -> 7.9x
SATURATION_NOTE = '提示：真实倍速受 CPU/FPS 限制会低于字段值（实测 3→约2.6x，5→约3.9x，10→约7.3x）'


# ----------------------------------------------------------------------------
# 基础读写
# ----------------------------------------------------------------------------
def find_pid(exe_name):
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return None
    try:
        e = PROCESSENTRY32W(); e.dwSize = ctypes.sizeof(e)
        ok = Process32FirstW(snap, ctypes.byref(e))
        while ok:
            if e.szExeFile.lower() == exe_name.lower():
                return e.th32ProcessID
            ok = Process32NextW(snap, ctypes.byref(e))
    finally:
        CloseHandle(snap)
    return None


def rpm(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = SIZE_T(0)
    if not ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def wpm(h, addr, data):
    got = SIZE_T(0)
    return bool(WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(got)))


def rd_u64(h, a):
    b = rpm(h, a, 8)
    return struct.unpack('<Q', b)[0] if b and len(b) == 8 else None


def rd_f64(h, a):
    b = rpm(h, a, 8)
    return struct.unpack('<d', b)[0] if b and len(b) == 8 else None


def rd_f32(h, a):
    b = rpm(h, a, 4)
    return struct.unpack('<f', b)[0] if b and len(b) == 4 else None


def rd_i32(h, a):
    b = rpm(h, a, 4)
    return struct.unpack('<i', b)[0] if b and len(b) == 4 else None


def rd_u8(h, a):
    b = rpm(h, a, 1)
    return b[0] if b else None


def wr_f64(h, a, v):
    return wpm(h, a, struct.pack('<d', v))


def wr_f32(h, a, v):
    return wpm(h, a, struct.pack('<f', v))


def wr_u8(h, a, v):
    return wpm(h, a, bytes([v & 0xFF]))


# ----------------------------------------------------------------------------
# 定位（版本无关）
# ----------------------------------------------------------------------------
def scan_static_slots(h, verbose=True, max_scan=MAX_SCAN):
    """枚举可执行内存里所有 `movabs reg, imm64`，返回候选静态槽地址集合。

    不依赖任何游戏版本特征码 —— 这是 1.1.3.18 那条 AOB 在 1.1.4 上失效后
    的替代方案。
    """
    slots = set()
    addr = 0x10000
    limit = 0x7FFFFFFF0000
    scanned = 0
    nreg = 0
    while addr < limit:
        mbi = MEMORY_BASIC_INFORMATION()
        if not VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if size <= 0:
            break
        prot = mbi.Protect
        if (mbi.State == MEM_COMMIT and not (prot & PAGE_GUARD)
                and (prot & 0xFF) in REGION_EXEC):
            nreg += 1
            off = 0
            carry = b''
            while off < size and scanned < max_scan:
                n = min(CHUNK, size - off)
                chunk = rpm(h, base + off, n)
                if chunk:
                    buf = carry + chunk
                    for mo in MOVABS_RE.finditer(buf):
                        i = mo.start()
                        if i + 10 <= len(buf):
                            imm = struct.unpack_from('<Q', buf, i + 2)[0]
                            if SANE_PTR_LO <= imm <= SANE_PTR_HI:
                                slots.add(imm)
                    carry = buf[-12:]
                    scanned += n
                else:
                    carry = b''
                off += n
        addr = base + size
    if verbose:
        print('  [定位] 可执行区 %d 块，读 %.1f MB，候选静态槽 %d 个'
              % (nreg, scanned / 2**20, len(slots)))
    return slots


def find_object(h, verbose=True):
    """返回 (obj_addr, info, slot_addr)；失败返回 (None, None, None)。

    步骤：候选静态槽 -> 解引用取对象指针 -> 字段指纹校验。
    严格指纹 = _GameTime > 0 且 (int)_GameTime == <GameTimeInt>。
    """
    slots = scan_static_slots(h, verbose=verbose)
    if not slots:
        return None, None, None

    cands = []
    near = []
    seen = set()
    for s in slots:
        p = rd_u64(h, s)
        if not p or not (SANE_PTR_LO <= p <= SANE_PTR_HI) or (p & 7):
            continue
        if p in seen:
            continue
        seen.add(p)
        info = probe_object(h, p)
        if info is None:
            continue
        info['slot'] = s
        if info['gt'] > 1.0 and abs(info['gti'] - int(info['gt'])) <= 1:
            cands.append(info)
        elif info['score'] >= 5:
            near.append(info)

    if verbose:
        print('  [定位] 解引用 %d 个指针，严格指纹命中 %d 个' % (len(seen), len(cands)))

    if not cands:
        if verbose and near:
            near.sort(key=lambda d: -d['score'])
            print('  [诊断] 无严格命中，最接近的几个：')
            for c in near[:5]:
                print('     obj=0x%X score=%d _GameSpeed=%g _GameTime=%.1f GTI=%d _MaxGameSpeed=%g'
                      % (c['obj'], c['score'], c['gs'], c['gt'], c['gti'], c['mx']))
        return None, None, None

    cands.sort(key=lambda d: (-d['score'], -d['gt'], d['obj']))
    best = cands[0]
    if verbose:
        for c in cands[:5]:
            print('     obj=0x%X slot=0x%X score=%d  _GameSpeed=%g  _GameTime=%.2f  _MaxGameSpeed=%g'
                  % (c['obj'], c['slot'], c['score'], c['gs'], c['gt'], c['mx']))
    return best['obj'], best, best['slot']


def probe_object(h, obj):
    """读一批字段并判断像不像 DXGame。返回 dict 或 None"""
    if not obj or obj < 0x10000:
        return None
    raw = rpm(h, obj + OFF_OBJ_BASE, SPAN)
    if not raw or len(raw) < SPAN:
        return None
    gs, gt, ge = struct.unpack_from('<ddd', raw, 0)
    mx, = struct.unpack_from('<f', raw, OFF_MAX_SPEED - OFF_OBJ_BASE)
    gti, gt_e_i = struct.unpack_from('<ii', raw, OFF_GAME_TIME_INT - OFF_OBJ_BASE)
    fps = raw[OFF_SHOW_FPS - OFF_OBJ_BASE]
    if not (0.0 <= gs < 1e7):
        return None
    if not (0.0 <= gt < 1e12 and 0.0 <= ge < 1e12):
        return None
    if not (0.0 <= mx < 1e7):
        return None
    if gs != gs or gt != gt:          # NaN
        return None
    score = 0
    if abs(gti - int(gt)) <= 1:
        score += 2
    if abs(gt_e_i - int(ge)) <= 1:
        score += 2
    if fps in (0, 1):
        score += 1
    if 0.05 < mx < 1000:
        score += 1
    return dict(obj=obj, gs=gs, gt=gt, ge=ge, mx=mx, gti=gti, gei=gt_e_i, fps=fps, score=score)


def confirm_monotonic(h, info, wait=1.2):
    """再采一次，确认 GameTime 在增长（证明这是活的游戏时钟对象）"""
    time.sleep(wait)
    raw = rpm(h, info['obj'] + OFF_GAME_TIME, 8)
    if not raw:
        return False, 0.0
    t2 = struct.unpack('<d', raw)[0]
    d = t2 - info['gt']
    return (d > 0), d / wait


# ----------------------------------------------------------------------------
# 修改器主体
# ----------------------------------------------------------------------------
class GameSpeed:
    def __init__(self, pid, verbose=True):
        self.pid = pid
        self.verbose = verbose
        self.h = None
        self.obj = None
        self.slot = None
        self.info = None
        self.base_gs = None
        self.base_mx = None
        self.ratio = 1.0
        self.forcing = False
        self.base_fps = None
        self.stop = threading.Event()
        self.thread = None

    def open(self):
        self.h = OpenProcess(PROC_ACCESS, False, self.pid)
        if not self.h:
            raise OSError('OpenProcess 失败 (err %d) —— 请用管理员身份运行' % ctypes.get_last_error())
        return self

    def close(self):
        if self.h:
            CloseHandle(self.h)
            self.h = None

    def locate(self, quiet=False):
        obj, info, slot = find_object(self.h, verbose=not quiet)
        if not obj:
            return False
        self.obj, self.info, self.slot = obj, info, slot
        self.base_gs = info['gs']
        self.base_mx = info['mx']
        self.base_fps = info['fps']
        return True

    def refresh_obj(self):
        """重新读静态槽（GC 移动过对象也没关系）"""
        p = rd_u64(self.h, self.slot) if self.slot else None
        if p and p != self.obj:
            if self.verbose:
                print('  [提示] 对象指针变化 0x%X -> 0x%X（GC 移动），已跟随'
                      % (self.obj or 0, p))
            self.obj = p
        return self.obj

    # ---- 读 ----
    def read(self):
        if not self.obj:
            return None
        raw = rpm(self.h, self.obj + OFF_OBJ_BASE, SPAN)
        if not raw or len(raw) < SPAN:
            # 对象可能被 GC 移动过：重新读一次静态槽再试
            self.refresh_obj()
            raw = rpm(self.h, self.obj + OFF_OBJ_BASE, SPAN)
            if not raw or len(raw) < SPAN:
                return None
        gs, gt, ge = struct.unpack_from('<ddd', raw, 0)
        mx, = struct.unpack_from('<f', raw, OFF_MAX_SPEED - OFF_OBJ_BASE)
        gti, gei = struct.unpack_from('<ii', raw, OFF_GAME_TIME_INT - OFF_OBJ_BASE)
        fps = raw[OFF_SHOW_FPS - OFF_OBJ_BASE]
        return dict(gs=gs, gt=gt, ge=ge, mx=mx, gti=gti, gei=gei, fps=fps)

    # ---- 写 ----
    def set_target(self, value, force=True):
        """把 _GameSpeed 直接设为 value（绝对值，不按定位时的值等比缩放）。

        这里必须是绝对值：定位时如果游戏处于暂停态，_GameSpeed 本来就是 0，
        旧版按 0×倍率 算，写进去还是 0 —— 表现就是"按了完全没反应"。
        """
        value = float(value)
        self.ratio = value
        if not self.obj:
            return False
        ok = wr_f64(self.h, self.obj + OFF_GAME_SPEED, value)
        # 目标就是 1.0（正常速度）时没必要看守
        self.forcing = bool(force) and value != 1.0
        return bool(ok)

    # 兼容旧调用名
    def set_ratio(self, r, force=True):
        return self.set_target(r, force)

    def set_fps(self, on):
        if not self.obj:
            return False
        return wr_u8(self.h, self.obj + OFF_SHOW_FPS, 1 if on else 0)

    def restore(self):
        """退出时把速度恢复成 1.0（原版正常速度），并还原帧率显示开关。

        例外：如果退出瞬间 _GameSpeed 已经是 0（= 你自己按空格暂停了），
        就原样留着不动 —— 不把玩家的暂停状态给解掉。
        也绝不碰 _MaxGameSpeed。
        """
        self.forcing = False
        if not self.obj:
            return
        cur = self.read()
        if cur is None or abs(cur['gs']) > 1e-9:
            wr_f64(self.h, self.obj + OFF_GAME_SPEED, 1.0)
        if self.base_fps is not None:
            wr_u8(self.h, self.obj + OFF_SHOW_FPS, self.base_fps)

    # ---- 看守线程：引擎把字段改回"正常值"时，重新写回目标值 ----
    def start_watchdog(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop.clear()

        def loop():
            last_note = 0.0
            while not self.stop.wait(0.1):
                if not self.forcing:
                    continue
                self.refresh_obj()
                cur = self.read()
                if not cur:
                    continue
                # 只在引擎把速度重置为"正常值 1.0"时写回。
                # 刻意不覆盖 0 —— 0 等于暂停，通常是你自己按了空格，必须尊重。
                if 0.5 <= cur['gs'] <= 1.5 and abs(cur['gs'] - self.ratio) > 0.05:
                    wr_f64(self.h, self.obj + OFF_GAME_SPEED, self.ratio)
                    now = time.time()
                    if self.verbose and now - last_note > 1.5:
                        last_note = now
                        print('  [看守] 引擎把 _GameSpeed 改成了 %g，已写回 %g'
                              % (cur['gs'], self.ratio))
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def stop_watchdog(self):
        self.stop.set()


# ----------------------------------------------------------------------------
# 自检：造一个假目标，验证 扫描→取对象→读写 全链路
# ----------------------------------------------------------------------------
def make_target():
    """子进程模式：造一块带特征的假 DXGame，然后一直活着。"""
    SetConsoleOutputCP(65001)
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_READWRITE = 0x04
    MEM_COMMIT_RESERVE = 0x3000
    code = VirtualAlloc(None, 0x1000, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    data = VirtualAlloc(None, 0x1000, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    if not code or not data:
        print('ALLOC FAIL'); return 1
    obj = data + 0x100                    # 假 DXGame 对象
    slot = data + 0x10                    # 静态槽：存对象指针
    ctypes.memmove(slot, struct.pack('<Q', obj), 8)
    # movabs rcx, slot  (48 B9 + 8字节地址) —— 与真实引擎里那句同形
    code_bytes = b'\x48\xB9' + struct.pack('<Q', slot) + b'\xC3'
    ctypes.memmove(code, code_bytes, len(code_bytes))
    print('PID %d' % os.getpid(), flush=True)
    print('CODE 0x%X SLOT 0x%X OBJ 0x%X' % (code, slot, obj), flush=True)
    t0 = time.time()
    # 初始化：速度字段只写一次，之后不再碰它 —— 这样"我们写进去的值是否生效"
    # 才测得出（否则假目标会不停覆盖，测的是假目标自己）
    init = bytearray(SPAN)
    struct.pack_into('<ddd', init, 0, 1.0, 1000.0, 500.0)
    struct.pack_into('<f', init, OFF_MAX_SPEED - OFF_OBJ_BASE, 5.0)
    init[OFF_SHOW_FPS - OFF_OBJ_BASE] = 0
    ctypes.memmove(obj + OFF_OBJ_BASE, bytes(init), SPAN)
    try:
        while True:
            t = time.time() - t0
            gt = 1000.0 + t * 8.0            # 假装游戏时间
            ge = 500.0 + t * 4.0
            live = bytearray(16)
            struct.pack_into('<dd', live, 0, gt, ge)
            ctypes.memmove(obj + OFF_GAME_TIME, bytes(live), 16)
            ctypes.memmove(obj + OFF_GAME_TIME_INT,
                           struct.pack('<ii', int(gt), int(ge)), 8)
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    return 0


def selftest():
    print('=' * 66)
    print(' 自检：生成假目标进程，验证全链路')
    print('=' * 66)
    p = subprocess.Popen([sys.executable, os.path.abspath(__file__), '--make-target'],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         encoding='utf-8', errors='replace')
    obj_expect = None
    try:
        for _ in range(40):
            line = p.stdout.readline()
            if not line:
                break
            line = line.strip()
            print('   目标:', line, flush=True)
            if 'OBJ' in line:
                obj_expect = int(line.split('OBJ')[-1].strip(), 16)
                break
        pid = p.pid
        h = OpenProcess(PROC_ACCESS, False, pid)
        if not h:
            print('   ✘ OpenProcess 失败')
            return 1

        print('\n1) 扫描特征并定位对象')
        obj, info, slot = find_object(h, verbose=True)
        ok_loc = (obj == obj_expect)
        print('   期望 0x%X，实得 %s -> %s' % (obj_expect, hex(obj) if obj else 'None',
                                              'OK' if ok_loc else '失败'))

        print('\n2) 读数')
        gs = GameSpeed(pid); gs.h = h; gs.obj, gs.info, gs.slot = obj, info, slot
        gs.base_gs = info['gs']; gs.base_mx = info['mx']; gs.base_fps = info['fps']
        cur = gs.read()
        print('   _GameSpeed=%g  _GameTime=%.2f  _MaxGameSpeed=%g  ShowFPS=%d'
              % (cur['gs'], cur['gt'], cur['mx'], cur['fps']))
        ok_read = abs(cur['gs'] - 1.0) < 1e-6

        print('\n3) 设为 3（绝对值写入）')
        gs.set_target(3.0)
        time.sleep(0.3)
        cur2 = gs.read()
        print('   _GameSpeed=%g  _MaxGameSpeed=%g' % (cur2['gs'], cur2['mx']))
        ok_set = abs(cur2['gs'] - 3.0) < 1e-6 and abs(cur2['mx'] - 5.0) < 1e-6

        print('\n4) 看守：模拟引擎改回 1.0，看是否被写回')
        wr_f64(h, obj + OFF_GAME_SPEED, 1.0)
        gs.forcing = True
        gs.stop.clear()
        gs.start_watchdog()
        time.sleep(0.8)
        cur3 = gs.read()
        gs.stop_watchdog()
        print('   _GameSpeed=%g（应为 3）' % cur3['gs'])
        ok_wd = abs(cur3['gs'] - 3.0) < 1e-3

        print('\n4b) 看守必须尊重暂停：写入 0 后不应被覆盖')
        gs.forcing = True
        gs.stop.clear()
        gs.start_watchdog()
        wr_f64(h, obj + OFF_GAME_SPEED, 0.0)
        time.sleep(0.6)
        cur3b = gs.read()
        gs.stop_watchdog()
        print('   _GameSpeed=%g（应为 0，暂停被尊重）' % cur3b['gs'])
        ok_pause = abs(cur3b['gs']) < 1e-9

        print('\n5) 暂停态退出：应保留暂停（不把 0 改成 1）')
        gs.restore()
        time.sleep(0.3)
        cur4 = gs.read()
        print('   _GameSpeed=%g（应为 0）' % cur4['gs'])
        ok_rs = abs(cur4['gs']) < 1e-6

        print('\n5b) 正常态退出：应回到 1.0')
        wr_f64(h, obj + OFF_GAME_SPEED, 3.0)
        gs.restore()
        time.sleep(0.3)
        cur5 = gs.read()
        print('   _GameSpeed=%g（应为 1.0）' % cur5['gs'])
        ok_rs2 = abs(cur5['gs'] - 1.0) < 1e-3

        CloseHandle(h)
        allok = (ok_loc and ok_read and ok_set and ok_wd and ok_pause
                 and ok_rs and ok_rs2)
        print('\n== 自检 %s ==' % ('通过' if allok else '未通过'))
        return 0 if allok else 1
    finally:
        try:
            p.kill()
        except Exception:
            pass


# ----------------------------------------------------------------------------
# 交互
# ----------------------------------------------------------------------------
_helper = {}


def install_ctrl_handler(acc, say):
    def handler(ctrl_type):
        try:
            if acc:
                acc.restore()
        finally:
            say('[退出] 已把 _GameSpeed 恢复为 1.0')
            os._exit(0)
        return True
    cb = ctypes.WINFUNCTYPE(BOOL, DWORD)(handler)
    _helper['cb'] = cb
    SetConsoleCtrlHandler(cb, True)


def read_terminal_loop(cmd_q, stop_evt):
    def worker():
        while not stop_evt.is_set():
            try:
                line = sys.stdin.readline()
            except Exception:
                return
            if line == '':
                return
            cmd_q.append(line.strip())
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return t


def print_status(g, note=''):
    cur = g.read()
    if not cur:
        print('  读取失败', flush=True)
        return
    print('  [状态] 目标 %g  _GameSpeed=%g  _GameTime=%.1f  _GameElapsedTime=%.1f  %s'
          % (g.ratio, cur['gs'], cur['gt'], cur['ge'], note), flush=True)


def print_help():
    print("""
  命令：
    任意数字           把 _GameSpeed 设成这个值（2 / 3 / 5 / 8 / 12 …）
    0 或 r             回到 1x（原版正常速度）
    f                  切换游戏内屏幕帧率显示
    i 或空行回车        看一次当前字段
    p                  打印对象地址 / 定位信息
    ?                  本帮助
    q                  退出（速度恢复为 1x）

  说明：真实倍速受 CPU/FPS 限制，会低于字段值
        （实测 3 → 约 2.6x，5 → 约 3.9x，10 → 约 7.3x）
        波次压上来时按 0 回 1x。
        游戏里按空格暂停时引擎会把 _GameSpeed 写成 0，看守不会覆盖它。
""")


def run(exe_name='TheyAreBillions.exe', pid=None, initial=None, watch_only=False,
        fps=None, topmost=True):
    SetConsoleOutputCP(65001)
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    print('=' * 66)
    print(' TAB 游戏速度修改器（内存字段版）')
    print(' 原理：定位 DXVision.DXGame 实例，只改 _GameSpeed 一个字段')
    print(' 不挂钩、不改游戏代码；退出时把速度恢复为 1x。')
    print('=' * 66)

    if pid is None:
        pid = find_pid(exe_name)
    if not pid:
        print('[等待] 没找到 %s —— 请先启动游戏再运行本工具。' % exe_name)
        return 1
    print('[进程] pid = %d' % pid)

    g = GameSpeed(pid).open()
    cmds = []
    stop_evt = threading.Event()
    read_terminal_loop(cmds, stop_evt)
    install_ctrl_handler(g, lambda s: print(s, flush=True))

    print('[定位] 扫描可执行内存里所有 movabs 立即数，再按字段指纹筛…')
    if not g.locate():
        print('[失败] 没找到引擎对象（DXGame 实例）。可能原因：')
        print('  1) 还没进入对局 —— 请先开始一局（主菜单里可能还没有这个对象），')
        print('     或者这次游戏启动后还没加载过存档。')
        print('  2) 游戏版本差异较大，字段布局不同。把上面 [诊断] 那几行发我。')
        g.close()
        return 2

    print('[成功] DXGame 实例 = 0x%X   （静态槽 0x%X）' % (g.obj, g.slot))
    inc, rate = confirm_monotonic(g.h, g.info)
    print('        _GameSpeed=%g  _MaxGameSpeed=%g(只读)  _GameTime=%.2f'
          % (g.info['gs'], g.info['mx'], g.info['gt']))
    print('        _GameTime 增长：%s（%.1f 游戏秒 / 现实秒）'
          % ('是' if inc else '否', rate))
    if not inc:
        print('        ⚠ 时间没在增长 = 当前是暂停态（暂停下 _GameSpeed 就是 0）。')
        print('          这没关系：直接输数字设速度即可，写入就会让时间跑起来。')
    print('        ' + SATURATION_NOTE)

    if watch_only:
        print('\n[只读观测] 每 2 秒打印一次字段（不写任何值）。Ctrl+C 退出。')
        try:
            t0 = time.time()
            last = g.read()
            while True:
                time.sleep(2.0)
                cur = g.read()
                if not cur:
                    break
                if last is None:
                    last = cur
                    continue
                dg = (cur['gt'] - last['gt']) / 2.0
                print('   %6.1fs  _GameSpeed=%-10g _MaxGameSpeed=%-8g _GameTime=%.1f (%+.1f/s)'
                      % (time.time() - t0, cur['gs'], cur['mx'], cur['gt'], dg), flush=True)
                last = cur
        except KeyboardInterrupt:
            pass
        g.close()
        return 0

    if fps is not None:
        g.set_fps(fps)
        print('[帧率显示] 已设为 %s' % ('开' if fps else '关'))

    if initial:
        g.set_target(initial)
        g.start_watchdog()
        print('[设置] _GameSpeed = %g' % initial)

    title = lambda r: SetConsoleTitleW('[TAB 速度] %g' % r)
    title(g.ratio)
    print_help()
    print_status(g, '（已就绪）')

    try:
        while True:
            if cmds:
                line = cmds.pop(0).lower()
                if line in ('q', 'quit', 'exit'):
                    break
                elif line in ('0', 'r', 'reset'):
                    g.set_target(1.0, force=False)
                    title(1.0)
                    print_status(g, '（已回到 1x）')
                elif line == 'f':
                    cur = g.read()
                    g.set_fps(0 if cur['fps'] else 1)
                    print('  [帧率显示] -> %s' % ('开' if not cur['fps'] else '关'))
                elif line == 'i' or line == '':
                    print_status(g)
                elif line == 'p':
                    print('  对象 0x%X  静态槽 0x%X  定位时读到 _GameSpeed=%g _MaxGameSpeed=%g(只读)'
                          % (g.obj, g.slot, g.base_gs, g.base_mx))
                elif line == '?':
                    print_help()
                else:
                    try:
                        val = float(line)
                    except ValueError:
                        val = None
                    if val is not None and val > 0:
                        g.set_target(val)
                        g.start_watchdog()
                        title(val)
                        print_status(g, '（已设置）')
                    else:
                        print('  未知命令：%s（? 看帮助；或直接输入一个正数当速度值）' % line)
            time.sleep(0.1)
    finally:
        stop_evt.set()
        g.stop_watchdog()
        g.restore()
        g.close()
        print('[退出] 已把 _GameSpeed 恢复为 1.0。')
    return 0


# ----------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    if '--make-target' in args:
        return make_target()
    if '--selftest' in args:
        return selftest()
    pid = None
    if '--pid' in args:
        pid = int(args[args.index('--pid') + 1])
    exe = 'TheyAreBillions.exe'
    if '--name' in args:
        exe = args[args.index('--name') + 1]
    initial = None
    if '--set' in args:
        initial = float(args[args.index('--set') + 1])
    fps = None
    if '--fps' in args:
        v = args[args.index('--fps') + 1].lower()
        fps = v in ('on', '1', 'true', 'yes')
    return run(exe_name=exe, pid=pid, initial=initial,
               watch_only=('--read' in args), fps=fps)


if __name__ == '__main__':
    sys.exit(main())
