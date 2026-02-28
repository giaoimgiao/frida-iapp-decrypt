/**
 * iApp Frida Hook Script
 * 
 * Hook iApp framework methods to capture decrypted scripts at runtime.
 * 
 * Usage:
 *   frida -U -f com.example.app -l iapp_hook.js
 *   frida -U -n "AppName" -l iapp_hook.js
 */

var hooked = false;
var config = {
    outputDir: "/data/local/tmp/iapp_out/",
    verbose: true
};

function log(msg) {
    if (config.verbose) {
        send(msg);
    }
}

function installHooks() {
    if (hooked) return;
    hooked = true;

    Java.perform(function() {
        var JavaFile = Java.use("java.io.File");
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        var JavaString = Java.use("java.lang.String");
        
        // Create output directory
        var dir = JavaFile.$new(config.outputDir);
        if (!dir.exists()) {
            dir.mkdirs();
            log("[+] Created output directory: " + config.outputDir);
        }
        
        var counter = 0;

        /**
         * Save content to file
         */
        function saveFile(name, content) {
            if (!content || content.length === 0) return;
            try {
                var safeName = name.replace(/[\/\\:*?"<>|]/g, "_");
                var f = JavaFile.$new(config.outputDir + safeName);
                var fos = FileOutputStream.$new(f, true);
                var bytes = JavaString.$new(content).getBytes("UTF-8");
                fos.write(bytes);
                fos.close();
                counter++;
                log("[SAVED] " + safeName + " (" + bytes.length + " bytes) [#" + counter + "]");
            } catch(e) {
                log("[ERR] saveFile: " + e);
            }
        }

        // Context tracking
        var currentScript = {
            h3: "unknown",  // UI script name
            h4: "unknown",  // Logic script name
            h7: "unknown",  // Event script name
            h3Active: false,
            h4Active: false
        };

        // ============================================
        // Core iApp Hooks
        // ============================================

        try {
            var bClass = Java.use("com.iapp.app.b");
            
            // h3 - UI loading entry point
            bClass.h3.implementation = function(ctx, str) {
                currentScript.h3 = str || "unknown";
                currentScript.h3Active = true;
                log("[h3] Loading UI: " + currentScript.h3);
                return this.h3(ctx, str);
            };
            log("[+] Hooked com.iapp.app.b.h3");

            // h4 - Logic script execution
            bClass.h4.implementation = function(ctx, str, arr) {
                currentScript.h4 = str || "unknown";
                currentScript.h4Active = true;
                log("[h4] Loading logic: " + currentScript.h4);
                return this.h4(ctx, str, arr);
            };
            log("[+] Hooked com.iapp.app.b.h4");

            // h7 - Event script
            bClass.h7.implementation = function(ctx, obj, str) {
                currentScript.h7 = str || "unknown";
                log("[h7] Event: " + currentScript.h7);
                return this.h7(ctx, obj, str);
            };
            log("[+] Hooked com.iapp.app.b.h7");

        } catch(e) {
            log("[!] Failed to hook com.iapp.app.b: " + e);
        }

        // ============================================
        // mian class hooks - capture UI/event XML
        // ============================================

        try {
            var mianClass = Java.use("com.iapp.app.run.mian");
            
            // g() - read this.r field (UI events XML)
            mianClass.g.overload().implementation = function() {
                var rField = this.r.value;
                if (rField) {
                    log("[mian.g()] r field length: " + rField.length);
                    if (currentScript.h3Active) {
                        saveFile("ui_events_" + currentScript.h3 + ".xml", rField);
                        currentScript.h3Active = false;
                    }
                }
                return this.g();
            };
            log("[+] Hooked mian.g()");

            // g(String) - capture UI element XML
            mianClass.g.overload("java.lang.String").implementation = function(str) {
                if (str && str.length > 10) {
                    log("[mian.g(str)] len=" + str.length);
                    saveFile("ui_element_" + currentScript.h3 + "_" + counter + ".xml", str);
                }
                return this.g(str);
            };
            log("[+] Hooked mian.g(String)");

        } catch(e) {
            log("[!] Failed to hook mian: " + e);
        }

        // ============================================
        // main/main2/main3 class hooks
        // ============================================

        ["com.iapp.app.run.main", "com.iapp.app.run.main2", "com.iapp.app.run.main3"].forEach(function(className) {
            try {
                var klass = Java.use(className);
                klass.g.overload("java.lang.String").implementation = function(str) {
                    if (str && str.length > 10) {
                        log("[" + className + ".g] captured");
                        saveFile(className.replace(/\./g, "_") + "_ui_" + counter + ".xml", str);
                    }
                    return this.g(str);
                };
                log("[+] Hooked " + className + ".g(String)");
            } catch(e) {
                // Class may not exist in all iApp versions
            }
        });

        // ============================================
        // Code execution hooks
        // ============================================

        try {
            var eClass = Java.use("com.iapp.app.e");
            eClass.ah.implementation = function(arr, str) {
                if (str && str.length > 0) {
                    log("[e.ah] code length: " + str.length);
                    if (currentScript.h4Active) {
                        saveFile("code_" + currentScript.h4 + ".txt", str);
                        currentScript.h4Active = false;
                    }
                }
                return this.ah(arr, str);
            };
            log("[+] Hooked com.iapp.app.e.ah");
        } catch(e) {
            log("[!] e.ah hook skipped: " + e);
        }

        // ============================================
        // BeanShell interpreter hook
        // ============================================

        try {
            var Interpreter = Java.use("bsh.Interpreter");
            Interpreter.eval.overload("java.io.Reader").implementation = function(reader) {
                log("[bsh.eval] BeanShell script executing for: " + currentScript.h7);
                return this.eval(reader);
            };
            log("[+] Hooked bsh.Interpreter.eval");
        } catch(e) {
            log("[!] bsh hook skipped: " + e);
        }

        // ============================================
        // Function definition extraction
        // ============================================

        try {
            var wClass = Java.use("c.b.a.a.w");
            var cField = wClass.c;
            if (cField && cField.value) {
                var hashMap = Java.cast(cField.value, Java.use("java.util.HashMap"));
                var keys = hashMap.keySet().toArray();
                log("[w.c] Found " + keys.length + " functions");
                for (var i = 0; i < keys.length; i++) {
                    var key = keys[i].toString();
                    var val = hashMap.get(keys[i]);
                    if (val) {
                        saveFile("fn_" + key + ".myu", "fn " + val.toString() + "\nend fn");
                    }
                }
            }
        } catch(e) {
            log("[!] w.c extraction: " + e);
        }

        log("\n[*] ALL HOOKS INSTALLED!");
        log("[*] Output directory: " + config.outputDir);
        log("[*] Interact with the app to trigger script loading...\n");
    });
}

// ============================================
// Entry point with classloader wait
// ============================================

Java.perform(function() {
    function waitAndInstall() {
        try {
            Java.use("com.iapp.app.b");
            log("[*] iApp classes found! Installing hooks...");
            installHooks();
        } catch(e) {
            log("[*] Waiting for iApp classes to load...");
            setTimeout(waitAndInstall, 500);
        }
    }
    waitAndInstall();
});
