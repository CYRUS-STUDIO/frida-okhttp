function printOkHttpInterceptors() {
    Java.perform(function () {
        const OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
        const JavaList = Java.use("java.util.List");

        OkHttpClientBuilder.build.implementation = function () {
            const client = this.build(); // 调用原始 build() 方法返回 OkHttpClient 实例

            const interceptors = Java.cast(client.interceptors(), JavaList);
            const networkInterceptors = Java.cast(client.networkInterceptors(), JavaList);

            console.log("\n✅ OkHttpClient build.");
            console.log(`📎 Interceptors (${interceptors.size()}):`);
            for (let i = 0; i < interceptors.size(); i++) {
                const itc = interceptors.get(i);
                console.log(`   [App] ➜ ${itc.$className}`);
            }

            console.log(`📡 Network Interceptors (${networkInterceptors.size()}):`);
            for (let i = 0; i < networkInterceptors.size(); i++) {
                const itc = networkInterceptors.get(i);
                console.log(`   [Net] ➜ ${itc.$className}`);
            }

            return client;
        };
    });
}


setImmediate(printOkHttpInterceptors);


// frida -H 127.0.0.1:1234 -l print_okhttp_interceptors.js -f com.ss.android.ugc.aweme
// frida -H 127.0.0.1:1234 -l print_okhttp_interceptors.js -f com.ss.android.ugc.aweme --runtime=v8 --debug