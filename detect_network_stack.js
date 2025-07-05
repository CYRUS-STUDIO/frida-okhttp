/**
 * 检测 Android 应用中是否使用了 OkHttp（打印版本号）、TTNet、HttpURLConnection
 */
Java.perform(function () {
    console.log("=== Detecting Network Stack Usage ===");

    function checkOkHttp() {
        try {
            const OkHttpClient = Java.use('okhttp3.OkHttpClient');
            console.log("[✓] Detected OkHttp usage: okhttp3.OkHttpClient");

            // === 优先检测 OkHttp 4（静态字段 VERSION） ===
            try {
                const OkHttp = Java.use("okhttp3.OkHttp");
                const version = OkHttp.VERSION.value;
                console.log("[✓] OkHttp Version (via okhttp3.OkHttp.VERSION): " + version);
                return;
            } catch (e) {
                console.log("[!] OkHttp.VERSION not available (likely not OkHttp 4)");
            }

            // === 回退检测 OkHttp 3（userAgent 方法） ===
            try {
                const Version = Java.use("okhttp3.internal.Version");
                const userAgent = Version.userAgent();
                console.log("[✓] OkHttp Version (via okhttp3.internal.Version): " + userAgent);
            } catch (e) {
                console.log("[!] OkHttp version not found via okhttp3.internal.Version");
            }

        } catch (e) {
            console.log("[-] OkHttp not used.");
        }
    }

    function checkTTNet() {
        try {
            const TTNetInit = Java.use('com.bytedance.ttnet.TTNetInit');
            console.log("[✓] Detected TTNet usage: com.bytedance.ttnet.TTNetInit");
        } catch (e) {
            console.log("[-] TTNet not used.");
        }
    }

    function checkHttpURLConnection() {
        try {
            const HttpURLConnection = Java.use('java.net.HttpURLConnection');
            console.log("[✓] Detected HttpURLConnection usage (java.net.HttpURLConnection)");
        } catch (e) {
            console.log("[-] HttpURLConnection not used.");
        }
    }

    checkOkHttp();
    checkTTNet();
    checkHttpURLConnection();

    console.log("=== Detection Complete ===");
});


// frida -H 127.0.0.1:1234 -F -l detect_network_stack.js