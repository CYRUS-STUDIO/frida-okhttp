> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# OkHttp



OkHttp 是一个高效的 HTTP 客户端库，由 Square 公司开发，广泛应用于 Android 开发中。它支持同步和异步请求、连接池、压缩、缓存、拦截器等高级特性，是 Android 网络请求的主流选择之一。



开源地址：[https://github.com/square/okhttp](https://github.com/square/okhttp)



OkHttp 的核心特点：

- 支持 HTTP/1.1 和 HTTP/2

- 自动连接重用与请求队列复用

- 支持透明的 GZIP 压缩

- 支持缓存响应数据以减少重复请求

- 支持自定义拦截器（用于日志、请求修改、认证等）

- 异步请求基于线程池，不阻塞主线程



# 在 Android Studio 中使用 OkHttp



在 build.gradle(:app) 中加入 OkHttp 的依赖项：

```
dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
```


可选：日志拦截器（用于打印请求和响应）


```
implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
```


# Kotlin 封装的 OkHttpClient 单例



**功能说明：** 

- 单例模式（线程安全）

- 可选注册日志拦截器

- 封装常用请求方法：GET、POST(JSON / 表单)、PUT、DELETE

- 支持 全局请求头（如 Authorization Token）

- 支持 协程版 suspend 函数（适合 ViewModelScope 等使用）

- 支持 文件上传 Multipart 请求

- 保留原有 Callback 异步接口（兼容老代码）



```
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.logging.HttpLoggingInterceptor
import okhttp3.Headers.Companion.toHeaders
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

object NetworkClient {

    private var loggingEnabled = false
    private val JSON = "application/json; charset=utf-8".toMediaType()
    private val FORM = "application/x-www-form-urlencoded".toMediaType()

    private var globalHeaders: MutableMap<String, String> = mutableMapOf()

    private val client: OkHttpClient by lazy {
        val builder = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)

        if (loggingEnabled) {
            val logging = HttpLoggingInterceptor().apply {
                level = HttpLoggingInterceptor.Level.BODY
            }
            builder.addInterceptor(logging)
        }

        builder.build()
    }

    // 启用日志拦截器（必须在首次请求前调用）
    fun enableLogging() {
        loggingEnabled = true
    }

    // 设置全局请求头（如 token）
    fun setGlobalHeader(key: String, value: String) {
        globalHeaders[key] = value
    }

    fun clearGlobalHeaders() {
        globalHeaders.clear()
    }

    private fun buildHeaders(custom: Map<String, String>? = null): Headers {
        val all = globalHeaders.toMutableMap()
        custom?.let { all.putAll(it) }
        return all.toHeaders()
    }

    // ========= 协程版本（推荐） =========

    suspend fun getSuspend(url: String, headers: Map<String, String>? = null): String =
        withContext(Dispatchers.IO) {
            val request = Request.Builder()
                .url(url)
                .headers(buildHeaders(headers))
                .get()
                .build()

            client.newCall(request).execute().use {
                if (!it.isSuccessful) throw IOException("Unexpected code $it")
                it.body?.string() ?: ""
            }
        }

    suspend fun postJsonSuspend(url: String, json: String, headers: Map<String, String>? = null): String =
        withContext(Dispatchers.IO) {
            val body = json.toRequestBody(JSON)
            val request = Request.Builder()
                .url(url)
                .headers(buildHeaders(headers))
                .post(body)
                .build()

            client.newCall(request).execute().use {
                if (!it.isSuccessful) throw IOException("Unexpected code $it")
                it.body?.string() ?: ""
            }
        }

    suspend fun postFormSuspend(url: String, formData: Map<String, String>, headers: Map<String, String>? = null): String =
        withContext(Dispatchers.IO) {
            val formBody = FormBody.Builder().apply {
                formData.forEach { (k, v) -> add(k, v) }
            }.build()

            val request = Request.Builder()
                .url(url)
                .headers(buildHeaders(headers))
                .post(formBody)
                .build()

            client.newCall(request).execute().use {
                if (!it.isSuccessful) throw IOException("Unexpected code $it")
                it.body?.string() ?: ""
            }
        }

    suspend fun uploadFileSuspend(
        url: String,
        file: File,
        fileField: String = "file",
        extraFormData: Map<String, String>? = null,
        headers: Map<String, String>? = null
    ): String = withContext(Dispatchers.IO) {
        val fileBody = file.asRequestBody("application/octet-stream".toMediaType())

        val multipartBody = MultipartBody.Builder().setType(MultipartBody.FORM).apply {
            addFormDataPart(fileField, file.name, fileBody)
            extraFormData?.forEach { (k, v) -> addFormDataPart(k, v) }
        }.build()

        val request = Request.Builder()
            .url(url)
            .headers(buildHeaders(headers))
            .post(multipartBody)
            .build()

        client.newCall(request).execute().use {
            if (!it.isSuccessful) throw IOException("Upload failed: $it")
            it.body?.string() ?: ""
        }
    }

    // ========= 原始 Callback 异步版本（兼容旧代码） =========

    fun get(url: String, headers: Map<String, String>? = null, callback: Callback) {
        val request = Request.Builder()
            .url(url)
            .headers(buildHeaders(headers))
            .get()
            .build()

        client.newCall(request).enqueue(callback)
    }

    fun postJson(url: String, json: String, headers: Map<String, String>? = null, callback: Callback) {
        val body = json.toRequestBody(JSON)
        val request = Request.Builder()
            .url(url)
            .headers(buildHeaders(headers))
            .post(body)
            .build()

        client.newCall(request).enqueue(callback)
    }

    fun postForm(url: String, formData: Map<String, String>, headers: Map<String, String>? = null, callback: Callback) {
        val formBody = FormBody.Builder().apply {
            formData.forEach { (k, v) -> add(k, v) }
        }.build()

        val request = Request.Builder()
            .url(url)
            .headers(buildHeaders(headers))
            .post(formBody)
            .build()

        client.newCall(request).enqueue(callback)
    }
}
```


# 示例代码



用 Jetpack Compose 构建界面，包含多个请求按钮，点击后发起不同的 NetworkClient 请求，并将响应结果显示在下方的 

Text 中。

```
package com.cyrus.example.okhttp

import NetworkClient
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import java.io.File

class OkHttpActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 启用日志拦截器
        NetworkClient.enableLogging()

        // 设置全局请求头（例如 Token）
        NetworkClient.setGlobalHeader("Authorization", "Bearer your_token")

        setContent {
            OkHttpDemoScreen()
        }
    }

    @Composable
    fun OkHttpDemoScreen() {
        var responseText by remember { mutableStateOf("请求结果将显示在这里") }
        // Jetpack Compose 中用于 在 Composable 作用域内启动协程 的标准方式。
        val coroutineScope = rememberCoroutineScope()
        // 创建滚动状态
        val scrollState = rememberScrollState()

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {

            Button(onClick = {
                coroutineScope.launch {
                    try {
                        val result = NetworkClient.getSuspend("https://httpbin.org/get")
                        responseText = "GET 成功:\n$result"
                    } catch (e: Exception) {
                        responseText = "GET 失败: ${e.message}"
                    }
                }
            }) {
                Text("GET 请求")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(onClick = {
                coroutineScope.launch {
                    try {
                        val json = """{"name": "Cyrus", "number": 30}"""
                        val result = NetworkClient.postJsonSuspend("https://httpbin.org/post", json)
                        responseText = "POST JSON 成功:\n$result"
                    } catch (e: Exception) {
                        responseText = "POST JSON 失败: ${e.message}"
                    }
                }
            }) {
                Text("POST JSON")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(onClick = {
                coroutineScope.launch {
                    try {
                        val result = NetworkClient.postFormSuspend(
                            "https://httpbin.org/post",
                            formData = mapOf("username" to "admin", "password" to "123456")
                        )
                        responseText = "POST 表单 成功:\n$result"
                    } catch (e: Exception) {
                        responseText = "POST 表单 失败: ${e.message}"
                    }
                }
            }) {
                Text("POST 表单")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(onClick = {
                coroutineScope.launch {
                    try {
                        val file = File(cacheDir, "example.txt").apply {
                            writeText("这是测试上传内容")
                        }

                        val result = NetworkClient.uploadFileSuspend(
                            url = "https://httpbin.org/post",
                            file = file,
                            fileField = "file"
                        )
                        responseText = "文件上传成功:\n$result"
                    } catch (e: Exception) {
                        responseText = "上传失败: ${e.message}"
                    }
                }
            }) {
                Text("上传文件")
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = responseText,
                color = Color.White,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f) // 让 Text 占据剩余空间（可滚动区域）
                    .verticalScroll(scrollState)
                    .padding(8.dp)
            )
        }
    }
}
```


效果如下：



![word/media/image1.png](https://gitee.com/cyrus-studio/images/raw/master/574e483036319bd4dfc896e4deda91ea.png)


# OkHttp 的拦截器责任链机制



OkHttp 中的 Chain.proceed(request: Request): Response 是 拦截器（Interceptor）机制的核心方法，它用于在拦截器链中将请求传递给下一个拦截器并获取响应。



定义在 Interceptor 接口的内部接口 Chain 中：

```
/**
 * 拦截器接口，用于在请求发出前/响应返回后对其进行处理。
 * 拦截器链采用责任链模式，每个拦截器可以拦截、修改、终止请求流程。
 */
interface Interceptor {

    /**
     * 实现拦截逻辑的方法。
     * 每个拦截器必须实现此方法，并调用 chain.proceed(request) 来继续执行请求。
     *
     * @param chain 拦截器链，包含当前请求和继续执行的能力。
     * @return 最终的 Response 对象（可能被修改过）
     */
    fun intercept(chain: Chain): Response

    /**
     * 拦截器链接口，封装了当前请求、连接、下一个拦截器等上下文。
     * 每次调用 chain.proceed(request) 都会将请求传递给下一个拦截器。
     */
    interface Chain {

        /**
         * 获取当前请求对象。
         * 拦截器可以基于此请求决定是否修改、替换或终止请求。
         */
        fun request(): Request

        /**
         * 将请求传递给下一个拦截器，并返回最终的响应。
         * 拦截器通常会调用此方法来继续执行链条中的下一个拦截器。
         *
         * 注意：只能调用一次，否则会抛出 IllegalStateException。
         *
         * @param request 可选择修改后的 Request
         * @return 最终的 Response（由下游返回，可能被缓存、重定向、网络返回等）
         */
        fun proceed(request: Request): Response
    }
}
```


OkHttp 拦截器责任链调用流程：

```
请求 --> RealCall.execute() / enqueue()
         │
         ▼
构建 RealInterceptorChain
         │
         ▼
【用户自定义拦截器】
 Interceptor1.intercept(chain) {
     chain.proceed(request1)
         │
         ▼
【用户自定义拦截器】
 Interceptor2.intercept(chain) {
     chain.proceed(request2)
         │
         ▼
【RetryAndFollowUpInterceptor】   → 自动重试、重定向处理
 chain.proceed(request3)
         ▼
【BridgeInterceptor】             → 添加 User-Agent、Content-Type 等通用头部
 chain.proceed(request4)
         ▼
【CacheInterceptor】              → 处理缓存命中与写入逻辑
 chain.proceed(request5)
         ▼
【ConnectInterceptor】            → 建立 TCP/TLS 连接，获取 Exchange 对象
 chain.proceed(request6)
         ▼
【CallServerInterceptor】         → ★ 最后一步：真正发送请求，接收响应
 └──────────────────────────────────────────────────────┐
     写入请求 → 请求体/头 → 等待响应 → 构造 Response ← 读取响应体
                                                       │
                                                    返回结果
```
在 OkHttp 中，chain.proceed(request) 会层层向下调用，最终由 CallServerInterceptor 执行网络 I/O，这是整个请求链中真正与服务器通信的部分。



# Frida hook CallServerInterceptor 打印 Request 和 Response



如果你通过 Frida hook CallServerInterceptor，理论上确实可以拿到 所有网络请求和响应的原始数据，包括请求头、请求体、响应体等。



但在实际操作上，这个 hook 有个关键点：response.body().string()**只能调用一次** ，调用后流就消耗了，可能会导致 App 崩溃或响应为空。



HttpLoggingInterceptor 是 OkHttp 提供的一个内置拦截器，用于打印请求和响应信息（包括 URL、Header、Body 等）。它是如何打印 Response.body() 的？

```
// 从响应体中获取原始 source（BufferedSource），它封装了输入流
val source = responseBody.source()

// 请求将整个响应体全部读入内存（将整个流读入 buffer 中）
source.request(Long.MAX_VALUE) // Buffer the entire body.

// 获取实际缓存数据的 buffer（原始内容现在都在这个 buffer 中）
var buffer = source.buffer

// 判断是否是 gzip 编码（压缩传输）
var gzippedLength: Long? = null
if ("gzip".equals(headers["Content-Encoding"], ignoreCase = true)) {
    gzippedLength = buffer.size  // 记录压缩前的体积

    // 解压 gzip 内容
    GzipSource(buffer.clone()).use { gzippedResponseBody ->
        buffer = Buffer()  // 新建一个空 buffer，用于存解压结果
        buffer.writeAll(gzippedResponseBody) // 将解压后的内容写入 buffer
    }
}

// 获取响应内容的字符编码类型
val contentType = responseBody.contentType()
val charset: Charset = contentType?.charset(UTF_8) ?: UTF_8

// 检查内容是否是可打印的 UTF-8 文本（不是二进制）
if (!buffer.isProbablyUtf8()) {
    logger.log("")
    logger.log("<-- END HTTP (binary ${buffer.size}-byte body omitted)")
    return response // 如果不是文本，直接跳过，不打印内容
}

// 打印响应体内容（前提是内容长度不为 0）
if (contentLength != 0L) {
    logger.log("")
    logger.log(buffer.clone().readString(charset)) // 克隆再读取，避免消费原始流
}

// 最后打印 END 标记，带上字节数统计
if (gzippedLength != null) {
    logger.log("<-- END HTTP (${buffer.size}-byte, $gzippedLength-gzipped-byte body)")
} else {
    logger.log("<-- END HTTP (${buffer.size}-byte body)")
}
```


HttpLoggingInterceptor 打印响应的核心原理是：通过 responseBody.source().buffer.clone() 克隆缓冲区内容，在不消费原始流的前提下读取并打印响应体。



# 实现 Frida 版本 HttpLoggingInterceptor



基于 HttpLoggingInterceptor 源码，实现了一个完整的 Frida hook 脚本：模拟 OkHttp 的请求和响应日志打印逻辑，包括：

- 打印请求方法、URL、请求头、请求体（支持 UTF-8 判断和输出）

- 打印响应状态码、响应头、响应体（支持 gzip 解压）

- 支持 body 长度输出与省略输出策略

```
function isProbablyUtf8(buffer) {
    const BufferCls = Java.use("okio.Buffer");
    const Character = Java.use("java.lang.Character");

    const prefix = BufferCls.$new();
    const byteCount = Math.min(buffer.size(), 64);
    buffer.copyTo(prefix, 0, byteCount);

    for (let i = 0; i < 16; i++) {
        if (prefix.exhausted()) break;

        const codePoint = prefix.readUtf8CodePoint();
        if (Character.isISOControl(codePoint) &&
            !Character.isWhitespace(codePoint)) {
            return false;
        }
    }

    return true;
}


function hookInterceptor(name) {
    Java.perform(function () {
        const CallServerInterceptor = Java.use(name);
        const BufferCls = Java.use("okio.Buffer");
        const GzipSource = Java.use("okio.GzipSource");
        // const Utf8Kt = Java.use("okhttp3.logging.Utf8Kt");

        CallServerInterceptor.intercept.implementation = function (chain) {

            const logLines = [];

            const request = chain.request();
            const method = request.method();
            const url = request.url().toString();
            const requestHeaders = request.headers();

            logLines.push("\n📤====================[ OkHttp Request ]====================📤");
            logLines.push(`➡️ ${method} ${url}`);

            let curlParts = [`curl -X ${method}`];
            curlParts.push(`'${url}'`);

            logLines.push("🔸 Headers:");
            for (let i = 0; i < requestHeaders.size(); i++) {
                const name = requestHeaders.name(i);
                const value = requestHeaders.value(i);
                logLines.push(`   ${name}: ${value}`);

                // 构造 curl header 参数
                curlParts.push(`-H '${name}: ${value}'`);
            }

            let curlBodyStr = "";
            const requestBody = request.body();
            if (requestBody != null && !requestBody.isDuplex() && !requestBody.isOneShot()) {
                const buffer = BufferCls.$new();
                requestBody.writeTo(buffer);

                if (isProbablyUtf8(buffer)) {
                    logLines.push("📝 Body:");
                    const bodyText = buffer.readUtf8();
                    const truncated = bodyText.length > 1000 ? bodyText.substring(0, 1000) + "..." : bodyText
                    logLines.push(truncated);
                    curlBodyStr = bodyText.replace(/'/g, "'\\''"); // escape single quotes for curl
                    logLines.push(`--> END ${method} (${requestBody.contentLength()}-byte body)`);
                } else {
                    logLines.push(`--> END ${method} (binary ${requestBody.contentLength()}-byte body omitted)`);
                }
            } else {
                logLines.push(`--> END ${method}`);
            }

            // 添加 curl body
            if (curlBodyStr.length > 0) {
                curlParts.push(`--data '${curlBodyStr}'`);
            }

            // 输出 curl 命令（标准）
            let curl = curlParts.join(" ")
            logLines.push("\n📦 CURL (Linux/macOS/bash):");
            logLines.push(curl);

            // 输出 curl.exe 命令（Windows PowerShell）
            logLines.push("\n📦 CURL (Windows/PowerShell):");
            logLines.push(curl.replace(/^curl\b/, "curl.exe"));

            // 执行请求
            const startNs = Java.use("java.lang.System").nanoTime();
            let response;
            try {
                response = this.intercept(chain);
            } catch (e) {
                logLines.push("<-- ❌ HTTP FAILED: " + e);
                throw e;
            }
            const tookMs = (Java.use("java.lang.System").nanoTime() - startNs) / 1000000;

            const responseBody = response.body();
            const contentLength = responseBody.contentLength();
            const responseHeaders = response.headers();

            logLines.push("\n📥====================[ OkHttp Response ]====================📥");
            logLines.push(`⬅️ ${response.code()} ${response.message()} (${tookMs}ms)`);
            logLines.push(`↩️ URL: ${response.request().url()}`);
            logLines.push("🔸 Headers:");
            for (let i = 0; i < responseHeaders.size(); i++) {
                const name = responseHeaders.name(i);
                const value = responseHeaders.value(i);
                logLines.push(`   ${name}: ${value}`);
            }

            const encoding = responseHeaders.get("Content-Encoding");

            const source = responseBody.source();
            source.request(Java.use("java.lang.Long").MAX_VALUE.value);
            let buffer = source.buffer();
            buffer = Java.cast(buffer, BufferCls);

            let gzippedLength = null;
            if (encoding !== null && encoding.toLowerCase() === "gzip") {
                gzippedLength = buffer.size();
                const gzipSource = GzipSource.$new(Java.cast(buffer.clone(), BufferCls));
                const decompressedBuffer = BufferCls.$new();
                decompressedBuffer.writeAll(gzipSource);
                buffer = decompressedBuffer;
            }

            if (!isProbablyUtf8(buffer)) {
                logLines.push("⚠️  Response body is binary. Skipped logging.");
                logLines.push(`<-- END HTTP (binary ${buffer.size()}-byte body omitted)`);
                return response;
            }

            if (contentLength !== 0) {
                const bodyText = Java.cast(buffer.clone(), BufferCls).readUtf8();
                logLines.push("📄 Body:");
                logLines.push(bodyText.length > 1000 ? bodyText.substring(0, 1000) + "..." : bodyText);
            }

            if (gzippedLength !== null) {
                logLines.push(`<-- END HTTP (${buffer.size()}-byte, ${gzippedLength}-gzipped-byte body)`);
            } else {
                logLines.push(`<-- END HTTP (${buffer.size()}-byte body)`);
            }

            logLines.push("==============================================================\n");

            console.log(logLines.join("\n"));

            return response;
        };
    });
}


setImmediate(function () {
    hookInterceptor("okhttp3.internal.http.CallServerInterceptor")
});


// frida -H 127.0.0.1:1234 -F -l okhttp.js
// frida -H 127.0.0.1:1234 -F -l okhttp.js -o log.txt
// frida -H 127.0.0.1:1234 -F -l okhttp.js --runtime=v8 --debug
```


注意：isProbablyUtf8() 并不是 okio.Buffer 的内建方法，而是 OkHttp logging-interceptor 提供的一个 Kotlin 扩展函数，它定义在 okhttp3.logging.Utf8Kt 中。



![word/media/image2.png](https://gitee.com/cyrus-studio/images/raw/master/f6122a5841160a2f115e3a17f8f14562.png)


日志打印效果如下：

```
📤====================[ OkHttp Request ]====================📤
➡️ GET https://httpbin.org/get
🔸 Headers:
   Authorization: Bearer your_token
   Host: httpbin.org
   Connection: Keep-Alive
   Accept-Encoding: gzip
   User-Agent: okhttp/4.12.0
--> END GET

📥====================[ OkHttp Response ]====================📥
⬅️ 200  (748.167054ms)
↩️ URL: https://httpbin.org/get
🔸 Headers:
   date: Thu, 26 Jun 2025 08:57:21 GMT
   content-type: application/json
   content-length: 310
   server: gunicorn/19.9.0
   access-control-allow-origin: *
   access-control-allow-credentials: true
📄 Body:
{
  "args": {},
  "headers": {
    "Accept-Encoding": "gzip",
    "Authorization": "Bearer your_token",
    "Host": "httpbin.org",
    "User-Agent": "okhttp/4.12.0",
    "X-Amzn-Trace-Id": "Root=1-685d0b71-457cdaa22f842d8a2be6ddf3"
  },
  "origin": "***.***.***.***",
  "url": "https://httpbin.org/get"
}

<-- END HTTP (310-byte body)
==============================================================


📤====================[ OkHttp Request ]====================📤
➡️ POST https://httpbin.org/post
🔸 Headers:
   Authorization: Bearer your_token
   Content-Type: application/json; charset=utf-8
   Content-Length: 31
   Host: httpbin.org
   Connection: Keep-Alive
   Accept-Encoding: gzip
   User-Agent: okhttp/4.12.0
📝 Body:
{"name": "Cyrus", "number": 30}
--> END POST (31-byte body)

📥====================[ OkHttp Response ]====================📥
⬅️ 200  (758.014711ms)
↩️ URL: https://httpbin.org/post
🔸 Headers:
   date: Thu, 26 Jun 2025 08:57:23 GMT
   content-type: application/json
   content-length: 536
   server: gunicorn/19.9.0
   access-control-allow-origin: *
   access-control-allow-credentials: true
📄 Body:
{
  "args": {},
  "data": "{\"name\": \"Cyrus\", \"number\": 16}",
  "files": {},
  "form": {},
  "headers": {
    "Accept-Encoding": "gzip",
    "Authorization": "Bearer your_token",
    "Content-Length": "31",
    "Content-Type": "application/json; charset=utf-8",
    "Host": "httpbin.org",
    "User-Agent": "okhttp/4.12.0",
    "X-Amzn-Trace-Id": "Root=1-685d0b73-6b6c466832bf7a6e3799b5ce"
  },
  "json": {
    "name": "Cyrus",
    "number": 16
  },
  "origin": "***.***.***.***",
  "url": "https://httpbin.org/post"
}

<-- END HTTP (536-byte body)
==============================================================


📤====================[ OkHttp Request ]====================📤
➡️ POST https://httpbin.org/post
🔸 Headers:
   Authorization: Bearer your_token
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 30
   Host: httpbin.org
   Connection: Keep-Alive
   Accept-Encoding: gzip
   User-Agent: okhttp/4.12.0
📝 Body:
username=admin&password=123456
--> END POST (30-byte body)

📥====================[ OkHttp Response ]====================📥
⬅️ 200  (303.02753ms)
↩️ URL: https://httpbin.org/post
🔸 Headers:
   date: Thu, 26 Jun 2025 08:57:24 GMT
   content-type: application/json
   content-length: 515
   server: gunicorn/19.9.0
   access-control-allow-origin: *
   access-control-allow-credentials: true
📄 Body:
{
  "args": {},
  "data": "",
  "files": {},
  "form": {
    "password": "123456",
    "username": "admin"
  },
  "headers": {
    "Accept-Encoding": "gzip",
    "Authorization": "Bearer your_token",
    "Content-Length": "30",
    "Content-Type": "application/x-www-form-urlencoded",
    "Host": "httpbin.org",
    "User-Agent": "okhttp/4.12.0",
    "X-Amzn-Trace-Id": "Root=1-685d0b74-198fb926040887a13664be2c"
  },
  "json": null,
  "origin": "***.***.***.***",
  "url": "https://httpbin.org/post"
}

<-- END HTTP (515-byte body)
==============================================================


📤====================[ OkHttp Request ]====================📤
➡️ POST https://httpbin.org/post
🔸 Headers:
   Authorization: Bearer your_token
   Content-Type: multipart/form-data; boundary=507d5dd8-29f1-48fe-a14a-ccd1162cf6e0
   Content-Length: 239
   Host: httpbin.org
   Connection: Keep-Alive
   Accept-Encoding: gzip
   User-Agent: okhttp/4.12.0
📝 Body:
--507d5dd8-29f1-48fe-a14a-ccd1162cf6e0
Content-Disposition: form-data; name="file"; filename="example.txt"
Content-Type: application/octet-stream
Content-Length: 24

这是测试上传内容
--507d5dd8-29f1-48fe-a14a-ccd1162cf6e0--

--> END POST (239-byte body)

📥====================[ OkHttp Response ]====================📥
⬅️ 200  (333.339564ms)
↩️ URL: https://httpbin.org/post
🔸 Headers:
   date: Thu, 26 Jun 2025 08:57:25 GMT
   content-type: application/json
   content-length: 561
   server: gunicorn/19.9.0
   access-control-allow-origin: *
   access-control-allow-credentials: true
📄 Body:
{
  "args": {},
  "data": "",
  "files": {
    "file": "\u8fd9\u662f\u6d4b\u8bd5\u4e0a\u4f20\u5185\u5bb9"
  },
  "form": {},
  "headers": {
    "Accept-Encoding": "gzip",
    "Authorization": "Bearer your_token",
    "Content-Length": "239",
    "Content-Type": "multipart/form-data; boundary=507d5dd8-29f1-48fe-a14a-ccd1162cf6e0",
    "Host": "httpbin.org",
    "User-Agent": "okhttp/4.12.0",
    "X-Amzn-Trace-Id": "Root=1-685d0b75-31bde9c37f1da8127bcdff1c"
  },
  "json": null,
  "origin": "***.***.***.***",
  "url": "https://httpbin.org/post"
}

<-- END HTTP (561-byte body)
==============================================================
```


# 增强内容：打印 curl 命令



增强后的代码片段（仅修改 Request 部分的打印）

```
console.log("\n📤====================[ OkHttp Request ]====================📤");
console.log(`➡️ ${method} ${url}`);

let curlParts = [`curl -X ${method}`];
curlParts.push(`'${url}'`);

console.log("🔸 Headers:");
for (let i = 0; i < requestHeaders.size(); i++) {
    const name = requestHeaders.name(i);
    const value = requestHeaders.value(i);
    console.log(`   ${name}: ${value}`);

    // 构造 curl header 参数
    curlParts.push(`-H '${name}: ${value}'`);
}

let curlBodyStr = "";
const requestBody = request.body();
if (requestBody != null && !requestBody.isDuplex() && !requestBody.isOneShot()) {
    const buffer = BufferCls.$new();
    requestBody.writeTo(buffer);

    if (Utf8Kt.isProbablyUtf8(buffer)) {
        console.log("📝 Body:");
        const bodyText = buffer.readUtf8();
        const truncated = bodyText.length > 1000 ? bodyText.substring(0, 1000) + "..." : bodyText
        console.log(truncated);
        curlBodyStr = bodyText.replace(/'/g, "'\\''"); // escape single quotes for curl
        console.log(`--> END ${method} (${requestBody.contentLength()}-byte body)`);
    } else {
        console.log(`--> END ${method} (binary ${requestBody.contentLength()}-byte body omitted)`);
    }
} else {
    console.log(`--> END ${method}`);
}

// 添加 curl body
if (curlBodyStr.length > 0) {
    curlParts.push(`--data '${curlBodyStr}'`);
}

// 输出 curl 命令（标准）
let curl = curlParts.join(" ")
console.log("\n📦 CURL (Linux/macOS/bash):");
console.log(curl);

// 输出 curl.exe 命令（Windows PowerShell）
console.log("\n📦 CURL (Windows/PowerShell):");
console.log(curl.replace(/^curl\b/, "curl.exe"));
```


输出效果如下：



![word/media/image3.png](https://gitee.com/cyrus-studio/images/raw/master/6fdbe5cfbfc2b879d99424a84afb25d2.png)


# OkHttp 版本检测



Frida 检测当前应用是否使用 OkHttp + 打印版本

```
function detectOkHttpVersion() {
    Java.perform(function () {
        const hasClass = (name) => {
            try {
                Java.use(name);
                return true;
            } catch (_) {
                return false;
            }
        };

        const log = [];
        log.push("🔍 Scanning for OkHttp...");

        // 优先检测公开版本字段（4.x 开始提供）
        if (hasClass("okhttp3.OkHttp")) {
            try {
                const OkHttp = Java.use("okhttp3.OkHttp");
                const version = OkHttp.VERSION.value;
                log.push(`✅ Detected OkHttp: version=${version} (via okhttp3.OkHttp.VERSION)`);
            } catch (e) {
                log.push("⚠️ Found okhttp3.OkHttp but failed to read VERSION field.");
            }
            console.log(log.join("\n"));
            return;
        }

        // 再检测内部类（3.x ~ 4.x 通用）
        if (hasClass("okhttp3.internal.Version")) {
            try {
                const Version = Java.use("okhttp3.internal.Version");
                const userAgent = Version.userAgent();
                log.push(`✅ Detected OkHttp via internal.Version: ${userAgent}`);
            } catch (e) {
                log.push("⚠️ Found okhttp3.internal.Version but failed to read userAgent.");
            }
            console.log(log.join("\n"));
            return;
        }

        log.push("❌ OkHttp not detected in current app.");
        console.log(log.join("\n"));
    });
}
```


输出效果如下：

```
[Remote::**]-> detectOkHttpVersion()
🔍 Scanning for OkHttp...
✅ Detected OkHttp via internal.Version: okhttp/***.***.***.***
```


# 完整源码



- Android 示例代码：[https://github.com/CYRUS-STUDIO/AndroidExample](https://github.com/CYRUS-STUDIO/AndroidExample)

- frida-okhttp：[https://github.com/CYRUS-STUDIO/frida-okhttp](https://github.com/CYRUS-STUDIO/frida-okhttp)





