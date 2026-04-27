package com.adblocker.dns

import android.net.VpnService
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * DNS over HTTPS (DoH) клиент — RFC 8484.
 *
 * ПРОБЛЕМА с HttpURLConnection:
 *   HUC создаёт сокет внутри JDK — мы не можем вызвать VpnService.protect()
 *   до connect(). Результат: DoH соединение идёт через VPN тоннель → зацикливание.
 *
 * РЕШЕНИЕ — raw socket pipeline:
 *   1. Создаём java.net.Socket()
 *   2. vpnService.protect(socket)            ← до connect, критично
 *   3. socket.connect(hardcoded IP, 443)     ← без DNS резолвинга (избегаем рекурсии)
 *   4. Оборачиваем в TLS через SSLSocketFactory
 *   5. Шлём HTTP/1.1 POST вручную (2-3 строки заголовков)
 *
 * CONNECTION POOL:
 *   Один keep-alive TLS сокет на сервер. TLS handshake занимает ~200ms,
 *   повторные запросы — ~5ms. При ошибке переоткрываем автоматически.
 *
 * КЭШ:
 *   LRU, max 10 000 записей, TTL из DNS ответа (30s–600s).
 *   Thread-safe через synchronized блоки на отдельных объектах.
 */
object DoHClient {

    private const val TAG             = "DoHClient"
    private const val CONNECT_TIMEOUT = 4_000
    private const val IO_TIMEOUT      = 5_000
    private const val MAX_CACHE       = 10_000
    private const val MIN_TTL_MS      = 30_000L
    private const val MAX_TTL_MS      = 600_000L

    // VpnService для protect() — устанавливается из AdBlockerVpnService.startVpn()
    private val vpnRef = AtomicReference<VpnService?>(null)

    fun setVpnService(svc: VpnService?) { vpnRef.set(svc) }

    // ── Серверы ───────────────────────────────────────────────────────────────

    private data class Server(
        val name: String,
        val ip:   String,   // Hardcoded IP — не резолвим через DNS (рекурсия)
        val host: String,   // SNI hostname для TLS
        val path: String,
        val port: Int = 443
    )

    private val SERVERS = listOf(
        Server("Cloudflare", "1.1.1.1",  "cloudflare-dns.com", "/dns-query"),
        Server("Google",     "8.8.8.8",  "dns.google",         "/dns-query"),
        Server("Quad9",      "9.9.9.9",  "dns.quad9.net",      "/dns-query")
    )

    // ── Connection pool ───────────────────────────────────────────────────────

    private class PooledConn(val server: Server) {
        private var sslSocket: SSLSocket? = null
        private val lock = Any()

        fun isAlive(): Boolean = synchronized(lock) {
            sslSocket?.let { !it.isClosed && it.isConnected } ?: false
        }

        /** Открывает новое TLS соединение, защищает raw сокет до connect. */
        fun open(vpn: VpnService?) = synchronized(lock) {
            closeInternal()
            val raw = Socket()
            try {
                vpn?.protect(raw)   // КРИТИЧНО: protect ДО connect
                raw.connect(InetSocketAddress(server.ip, server.port), CONNECT_TIMEOUT)
                raw.soTimeout = IO_TIMEOUT

                val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val ssl = sslFactory.createSocket(raw, server.host, server.port, true) as SSLSocket
                ssl.useClientMode = true
                // SNI уже задан через createSocket(host, port)
                ssl.soTimeout = IO_TIMEOUT
                ssl.startHandshake()
                sslSocket = ssl
                Log.d(TAG, "Connected to ${server.name} (${server.ip})")
            } catch (e: Exception) {
                try { raw.close() } catch (_: Exception) {}
                throw e
            }
        }

        /** Выполняет DoH запрос на существующем сокете. */
        fun query(dnsWire: ByteArray): ByteArray? = synchronized(lock) {
            val s = sslSocket ?: return null
            val out = s.outputStream
            val inp = s.inputStream

            // HTTP/1.1 POST — минимальные заголовки
            val header = "POST ${server.path} HTTP/1.1\r\n" +
                         "Host: ${server.host}\r\n" +
                         "Content-Type: application/dns-message\r\n" +
                         "Accept: application/dns-message\r\n" +
                         "Content-Length: ${dnsWire.size}\r\n" +
                         "Connection: keep-alive\r\n\r\n"

            out.write(header.toByteArray(Charsets.US_ASCII))
            out.write(dnsWire)
            out.flush()

            parseHttpResponse(inp)
        }

        fun close() = synchronized(lock) { closeInternal() }

        private fun closeInternal() {
            try { sslSocket?.close() } catch (_: Exception) {}
            sslSocket = null
        }
    }

    // Пул — по одному соединению на сервер, общий lock для выбора сервера
    private val pool     = SERVERS.map { PooledConn(it) }
    private val poolLock = Any()

    // ── LRU Cache ─────────────────────────────────────────────────────────────

    private data class CacheEntry(val data: ByteArray, val expiresAt: Long) {
        fun isExpired() = System.currentTimeMillis() > expiresAt
    }

    private val cache      = LinkedHashMap<String, CacheEntry>(1024, 0.75f, true)
    private val cacheLock  = Any()

    // ── Public ────────────────────────────────────────────────────────────────

    /**
     * Резолвит domain через DoH.
     * @param dnsWire  Сырой DNS запрос (UDP payload)
     * @param domain   Домен (для кэш-ключа и логов)
     * @return         Сырой DNS ответ (совместим с UDP) или null при ошибке
     */
    fun resolve(dnsWire: ByteArray, domain: String): ByteArray? {
        val key = domain.lowercase()

        // Кэш
        val hit = synchronized(cacheLock) { cache[key] }
        if (hit != null && !hit.isExpired()) {
            return patchTxId(hit.data, dnsWire)
        }

        val vpn = vpnRef.get()

        synchronized(poolLock) {
            for (conn in pool) {
                val response = resolveOnConn(conn, dnsWire, vpn) ?: continue
                if (response.size < 12) continue

                val ttl = extractMinTtlMs(response).coerceIn(MIN_TTL_MS, MAX_TTL_MS)
                synchronized(cacheLock) {
                    if (cache.size >= MAX_CACHE) {
                        cache.keys.firstOrNull()?.let { cache.remove(it) }
                    }
                    cache[key] = CacheEntry(response, System.currentTimeMillis() + ttl)
                }

                Log.d(TAG, "DoH $domain → ${conn.server.name} (TTL=${ttl/1000}s)")
                return response
            }
        }

        Log.w(TAG, "All DoH servers failed for $domain")
        return null
    }

    fun clearCache() { synchronized(cacheLock) { cache.clear() } }
    fun cacheSize()  = synchronized(cacheLock) { cache.size }
    fun closeAll()   { synchronized(poolLock)  { pool.forEach { it.close() } } }

    // ── Private ───────────────────────────────────────────────────────────────

    private fun resolveOnConn(conn: PooledConn, dnsWire: ByteArray, vpn: VpnService?): ByteArray? {
        // Попытка 1: использовать существующий сокет
        if (conn.isAlive()) {
            val r = runCatching { conn.query(dnsWire) }.getOrNull()
            if (r != null) return r
            Log.d(TAG, "${conn.server.name}: connection broken, reconnecting")
        }
        // Попытка 2: переоткрыть и повторить
        return runCatching {
            conn.open(vpn)
            conn.query(dnsWire)
        }.getOrElse {
            Log.d(TAG, "${conn.server.name} failed: ${it.message}")
            conn.close()
            null
        }
    }

    /**
     * HTTP/1.1 ответ-парсер.
     * Поддерживает Content-Length и chunked transfer-encoding.
     */
    private fun parseHttpResponse(inp: InputStream): ByteArray? {
        // Читаем заголовки до \r\n\r\n
        val hdrBuf = ByteArrayOutputStream(512)
        var b0 = 0; var b1 = 0; var b2 = 0
        while (true) {
            val b = inp.read().also { if (it == -1) return null }
            hdrBuf.write(b)
            if (b0 == '\r'.code && b1 == '\n'.code && b2 == '\r'.code && b == '\n'.code) break
            b0 = b1; b1 = b2; b2 = b
        }
        val headers = hdrBuf.toString(Charsets.US_ASCII.name()).lowercase()

        // HTTP статус
        val status = headers.lineSequence().firstOrNull()
            ?.split(' ')?.getOrNull(1)?.toIntOrNull() ?: return null
        if (status != 200) { Log.d(TAG, "DoH HTTP $status"); return null }

        // Тело
        val contentLength = Regex("content-length:\\s*(\\d+)")
            .find(headers)?.groupValues?.get(1)?.toIntOrNull()
        val chunked       = "transfer-encoding: chunked" in headers

        return when {
            contentLength != null -> readExactly(inp, contentLength)
            chunked               -> readChunked(inp)
            else                  -> null
        }
    }

    private fun readExactly(inp: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n); var off = 0
        while (off < n) {
            val r = inp.read(buf, off, n - off)
            if (r == -1) break
            off += r
        }
        return if (off == n) buf else buf.copyOf(off)
    }

    private fun readChunked(inp: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        while (true) {
            val size = readRawLine(inp)?.trim()?.toIntOrNull(16) ?: break
            if (size == 0) break
            out.write(readExactly(inp, size))
            readRawLine(inp) // trailing CRLF
        }
        return out.toByteArray()
    }

    private fun readRawLine(inp: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = inp.read()
            if (b == -1) return null
            if (b == '\n'.code) return sb.toString().trimEnd('\r')
            sb.append(b.toChar())
            if (sb.length > 512) return sb.toString()
        }
    }

    /** DNS transaction ID в ответе заменяем на ID из клиентского запроса */
    private fun patchTxId(response: ByteArray, query: ByteArray): ByteArray {
        if (response.size < 2 || query.size < 2) return response
        return response.copyOf().also { it[0] = query[0]; it[1] = query[1] }
    }

    private fun extractMinTtlMs(dns: ByteArray): Long {
        if (dns.size < 12) return MIN_TTL_MS
        return try {
            val anCount = ((dns[6].toInt() and 0xFF) shl 8) or (dns[7].toInt() and 0xFF)
            if (anCount == 0) return MIN_TTL_MS
            var pos = 12
            // Skip QNAME
            while (pos < dns.size) {
                val l = dns[pos].toInt() and 0xFF
                if (l == 0)             { pos++; break }
                if (l and 0xC0 == 0xC0) { pos += 2; break }
                pos += l + 1
            }
            pos += 4 // QTYPE + QCLASS
            var minTtl = Long.MAX_VALUE
            repeat(anCount) {
                if (pos >= dns.size) return@repeat
                if (dns[pos].toInt() and 0xC0 == 0xC0) pos += 2
                else while (pos < dns.size) {
                    val l = dns[pos].toInt() and 0xFF
                    if (l == 0)             { pos++; break }
                    if (l and 0xC0 == 0xC0) { pos += 2; break }
                    pos += l + 1
                }
                if (pos + 10 > dns.size) return@repeat
                pos += 4 // TYPE + CLASS
                val ttl = ByteBuffer.wrap(dns, pos, 4).int.toLong() and 0xFFFFFFFFL
                if (ttl in 1..86400) minTtl = minOf(minTtl, ttl)
                pos += 4
                val rdLen = ((dns[pos].toInt() and 0xFF) shl 8) or (dns[pos+1].toInt() and 0xFF)
                pos += 2 + rdLen
            }
            if (minTtl == Long.MAX_VALUE) MIN_TTL_MS else minTtl * 1000L
        } catch (_: Exception) { MIN_TTL_MS }
    }
}
