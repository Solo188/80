package com.adblocker.http2

import android.util.Log
import com.adblocker.proxy.AdFilter
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * HTTP/2 MITM фильтр — RFC 7540 + HPack RFC 7541.
 *
 * Что делает:
 *  - Полный парсинг бинарных HTTP/2 фреймов в обоих направлениях
 *  - HPack декодирование HEADERS (статическая таблица + динамическая + Huffman)
 *  - Клиент→Сервер: блокирует рекламные запросы через RST_STREAM
 *  - Сервер→Клиент: декодирует ответные HEADERS, синхронизирует dynTable
 *  - CONTINUATION фреймы: собирает header block fragments до END_HEADERS
 *  - PUSH_PROMISE: дропает рекламные push streams
 *
 * HUFFMAN:
 *  Полная таблица RFC 7541 Appendix B (257 символов, 0-255 + EOS).
 *  Lookup через массив из 512 записей (4-бит prefix fast-path + slow path до 30 бит).
 *
 * THREAD MODEL:
 *  Два потока: client→server и server→client.
 *  Каждый держит собственную HPack dynTable — no shared state между потоками кроме
 *  blockedStreams (ConcurrentHashSet) и stopped (AtomicBoolean).
 */
class Http2Filter(
    private val clientIn:  InputStream,
    private val clientOut: OutputStream,
    private val serverIn:  InputStream,
    private val serverOut: OutputStream,
    private val host:      String,
    private val filter:    AdFilter
) {
    companion object {
        private const val TAG = "Http2Filter"

        // Frame type constants
        private const val DATA          = 0x0
        private const val HEADERS       = 0x1
        private const val PRIORITY      = 0x2
        private const val RST_STREAM    = 0x3
        private const val SETTINGS      = 0x4
        private const val PUSH_PROMISE  = 0x5
        private const val PING          = 0x6
        private const val GOAWAY        = 0x7
        private const val WINDOW_UPDATE = 0x8
        private const val CONTINUATION  = 0x9

        // Frame flag bits
        private const val END_STREAM    = 0x01
        private const val END_HEADERS   = 0x04
        private const val PADDED        = 0x08
        private const val PRIORITY_FLAG = 0x20

        // SETTINGS_HEADER_TABLE_SIZE default
        private const val DEFAULT_HEADER_TABLE_SIZE = 4096

        private val CLIENT_PREFACE_BYTES =
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)

        // HPack static table — RFC 7541 Appendix A (62 entries, index 1..61)
        private val STATIC_TABLE: Array<Pair<String, String>> = arrayOf(
            "" to "",                                      // 0 — unused
            ":authority"          to "",
            ":method"             to "GET",
            ":method"             to "POST",
            ":path"               to "/",
            ":path"               to "/index.html",
            ":scheme"             to "http",
            ":scheme"             to "https",
            ":status"             to "200",
            ":status"             to "204",
            ":status"             to "206",               // 11
            ":status"             to "304",
            ":status"             to "400",
            ":status"             to "404",
            ":status"             to "500",
            "accept-charset"      to "",
            "accept-encoding"     to "gzip, deflate",
            "accept-language"     to "",
            "accept-ranges"       to "",
            "accept"              to "",
            "access-control-allow-origin" to "",          // 20
            "age"                 to "",
            "allow"               to "",
            "authorization"       to "",
            "cache-control"       to "",
            "content-disposition" to "",
            "content-encoding"    to "",
            "content-language"    to "",
            "content-length"      to "",
            "content-location"    to "",
            "content-range"       to "",                  // 30
            "content-type"        to "",
            "cookie"              to "",
            "date"                to "",
            "etag"                to "",
            "expect"              to "",
            "expires"             to "",
            "from"                to "",
            "host"                to "",
            "if-match"            to "",
            "if-modified-since"   to "",                  // 40
            "if-none-match"       to "",
            "if-range"            to "",
            "if-unmodified-since" to "",
            "last-modified"       to "",
            "link"                to "",
            "location"            to "",
            "max-forwards"        to "",
            "proxy-authenticate"  to "",
            "proxy-authorization" to "",
            "range"               to "",                  // 50
            "referer"             to "",
            "refresh"             to "",
            "retry-after"         to "",
            "server"              to "",
            "set-cookie"          to "",
            "strict-transport-security" to "",
            "transfer-encoding"   to "",
            "user-agent"          to "",
            "vary"                to "",
            "via"                 to "",                  // 60
            "www-authenticate"    to ""                   // 61
        )
    }

    private val stopped       = AtomicBoolean(false)
    // ConcurrentHashSet через ConcurrentHashMap
    private val blockedStreams = java.util.concurrent.ConcurrentHashMap.newKeySet<Int>()

    // HPack контекст — отдельный для каждого направления
    private val c2sCtx = HPackContext()
    private val s2cCtx = HPackContext()

    // Буферы незавершённых header block fragments (CONTINUATION)
    private val c2sContinuation = HashMap<Int, ByteBuffer>()  // streamId → accumulated
    private val s2cContinuation = HashMap<Int, ByteBuffer>()

    // ── Entry point ───────────────────────────────────────────────────────────

    fun run() {
        // Читаем и форвардим HTTP/2 client preface
        try {
            val preface = readExactly(clientIn, CLIENT_PREFACE_BYTES.size)
            serverOut.write(preface)
            serverOut.flush()
        } catch (e: Exception) {
            Log.d(TAG, "Preface error: ${e.message}"); return
        }

        // Server→Client поток
        val s2cThread = Thread({
            try {
                while (!stopped.get()) {
                    val frame = readFrame(serverIn) ?: break
                    handleServerFrame(frame)
                }
            } catch (e: Exception) {
                if (!stopped.get()) Log.d(TAG, "S→C: ${e.message}")
            } finally {
                stopped.set(true)
            }
        }, "H2-s2c-$host").apply { isDaemon = true; start() }

        // Client→Server — в текущем потоке
        try {
            while (!stopped.get()) {
                val frame = readFrame(clientIn) ?: break
                handleClientFrame(frame)
            }
        } catch (e: Exception) {
            if (!stopped.get()) Log.d(TAG, "C→S: ${e.message}")
        } finally {
            stopped.set(true)
        }

        s2cThread.join(2000)
    }

    // ── Frame I/O ─────────────────────────────────────────────────────────────

    private data class Frame(
        val length:   Int,
        val type:     Int,
        val flags:    Int,
        val streamId: Int,
        val payload:  ByteArray
    )

    private fun readFrame(inp: InputStream): Frame? {
        val hdr = try { readExactly(inp, 9) } catch (_: EOFException) { return null }
        val len      = ((hdr[0].toInt() and 0xFF) shl 16) or
                       ((hdr[1].toInt() and 0xFF) shl 8)  or
                       (hdr[2].toInt() and 0xFF)
        val type     = hdr[3].toInt() and 0xFF
        val flags    = hdr[4].toInt() and 0xFF
        val streamId = ((hdr[5].toInt() and 0x7F) shl 24) or
                       ((hdr[6].toInt() and 0xFF) shl 16) or
                       ((hdr[7].toInt() and 0xFF) shl 8)  or
                       (hdr[8].toInt() and 0xFF)
        val payload  = if (len > 0) readExactly(inp, len) else ByteArray(0)
        return Frame(len, type, flags, streamId, payload)
    }

    private fun writeFrame(out: OutputStream, f: Frame) {
        val buf = ByteArray(9 + f.payload.size)
        val b   = ByteBuffer.wrap(buf)
        b.put(((f.length shr 16) and 0xFF).toByte())
        b.put(((f.length shr 8)  and 0xFF).toByte())
        b.put((f.length          and 0xFF).toByte())
        b.put(f.type.toByte())
        b.put(f.flags.toByte())
        b.putInt(f.streamId and 0x7FFFFFFF)
        b.put(f.payload)
        synchronized(out) { out.write(buf); out.flush() }
    }

    private fun rstStream(streamId: Int): Frame {
        val p = ByteArray(4)
        ByteBuffer.wrap(p).putInt(8) // CANCEL error code
        return Frame(4, RST_STREAM, 0, streamId, p)
    }

    // ── Client → Server ───────────────────────────────────────────────────────

    private fun handleClientFrame(frame: Frame) {
        when (frame.type) {
            HEADERS -> {
                val (headerBlock, endHeaders) = extractHeaderBlock(frame, PRIORITY_FLAG)

                if (!endHeaders) {
                    // Ждём CONTINUATION
                    c2sContinuation[frame.streamId] = ByteBuffer.wrap(headerBlock.copyOf(headerBlock.size + 8192)).also {
                        it.put(headerBlock); it.limit(it.position())
                    }
                    writeFrame(serverOut, frame)
                    return
                }

                val hdrs = c2sCtx.decode(headerBlock)
                val path   = hdrs[":path"]   ?: ""
                val method = hdrs[":method"] ?: "GET"
                val url    = "https://$host$path"

                val info = AdFilter.RequestInfo(
                    host        = host, url = url, method = method,
                    referer     = hdrs["referer"],
                    accept      = hdrs["accept"],
                    contentType = hdrs["content-type"]
                )

                if (filter.shouldBlock(info)) {
                    filter.logRequest(host, url, true, 0)
                    blockedStreams.add(frame.streamId)
                    writeFrame(clientOut, rstStream(frame.streamId))
                    Log.d(TAG, "H2 blocked [$frame.streamId]: $method $url")
                    return
                }

                writeFrame(serverOut, frame)
            }

            CONTINUATION -> {
                val pending = c2sContinuation[frame.streamId]
                if (pending != null) {
                    // Накапливаем блок
                    val combined = ByteArray(pending.position() + frame.payload.size).also {
                        System.arraycopy(pending.array(), 0, it, 0, pending.position())
                        System.arraycopy(frame.payload, 0, it, pending.position(), frame.payload.size)
                    }
                    if (frame.flags and END_HEADERS != 0) {
                        c2sContinuation.remove(frame.streamId)
                        val hdrs = c2sCtx.decode(combined)
                        // Блокируем если нужно (создаём синтетический HEADERS фрейм)
                        val url = "https://$host${hdrs[":path"] ?: ""}"
                        val info = AdFilter.RequestInfo(
                            host = host, url = url,
                            method = hdrs[":method"] ?: "GET",
                            referer = hdrs["referer"], accept = hdrs["accept"],
                            contentType = hdrs["content-type"]
                        )
                        if (filter.shouldBlock(info)) {
                            blockedStreams.add(frame.streamId)
                            writeFrame(clientOut, rstStream(frame.streamId))
                            return
                        }
                    } else {
                        val buf = ByteBuffer.allocate(combined.size + 8192)
                        buf.put(combined)
                        c2sContinuation[frame.streamId] = buf
                    }
                }
                if (frame.streamId !in blockedStreams) writeFrame(serverOut, frame)
            }

            DATA -> {
                if (frame.streamId in blockedStreams) {
                    if (frame.flags and END_STREAM != 0) blockedStreams.remove(frame.streamId)
                    return
                }
                writeFrame(serverOut, frame)
            }

            else -> writeFrame(serverOut, frame)
        }
    }

    // ── Server → Client ───────────────────────────────────────────────────────

    private fun handleServerFrame(frame: Frame) {
        // Дропаем ответы на заблокированные стримы
        if (frame.streamId != 0 && frame.streamId in blockedStreams) {
            if (frame.flags and END_STREAM != 0) blockedStreams.remove(frame.streamId)
            return
        }

        when (frame.type) {
            HEADERS -> {
                // Декодируем серверные HEADERS — обновляем dynTable s2cCtx
                val (headerBlock, _) = extractHeaderBlock(frame, 0)
                try { s2cCtx.decode(headerBlock) } catch (_: Exception) {}
                writeFrame(clientOut, frame)
            }

            CONTINUATION -> {
                val pending = s2cContinuation[frame.streamId]
                if (pending != null) {
                    val combined = ByteArray(pending.position() + frame.payload.size).also {
                        System.arraycopy(pending.array(), 0, it, 0, pending.position())
                        System.arraycopy(frame.payload, 0, it, pending.position(), frame.payload.size)
                    }
                    if (frame.flags and END_HEADERS != 0) {
                        s2cContinuation.remove(frame.streamId)
                        try { s2cCtx.decode(combined) } catch (_: Exception) {}
                    } else {
                        val buf = ByteBuffer.allocate(combined.size + 8192).apply { put(combined) }
                        s2cContinuation[frame.streamId] = buf
                    }
                }
                writeFrame(clientOut, frame)
            }

            PUSH_PROMISE -> {
                // Декодируем promised headers — если реклама, шлём RST на promised stream
                if (frame.payload.size >= 4) {
                    val promisedId = ByteBuffer.wrap(frame.payload, 0, 4).int and 0x7FFFFFFF
                    val block      = if (frame.payload.size > 4) frame.payload.copyOfRange(4, frame.payload.size)
                                     else ByteArray(0)
                    try {
                        val hdrs = s2cCtx.decode(block)
                        val url  = "https://$host${hdrs[":path"] ?: ""}"
                        val info = AdFilter.RequestInfo(host = host, url = url, method = "GET",
                            referer = null, accept = null, contentType = null)
                        if (filter.shouldBlock(info)) {
                            blockedStreams.add(promisedId)
                            writeFrame(clientOut, rstStream(promisedId))
                            return
                        }
                    } catch (_: Exception) {}
                }
                writeFrame(clientOut, frame)
            }

            else -> writeFrame(clientOut, frame)
        }
    }

    // ── HPack helpers ─────────────────────────────────────────────────────────

    /**
     * Извлекает header block bytes из HEADERS фрейма.
     * Убирает padding и priority prefix если есть.
     * Возвращает (headerBlockBytes, endHeaders).
     */
    private fun extractHeaderBlock(frame: Frame, priorityFlag: Int): Pair<ByteArray, Boolean> {
        var payload = frame.payload
        var off     = 0

        if (frame.flags and PADDED != 0 && payload.isNotEmpty()) {
            val padLen = payload[off].toInt() and 0xFF
            off++
            payload = payload.copyOfRange(off, payload.size - padLen)
            off = 0
        }
        if (frame.flags and priorityFlag != 0 && payload.size - off >= 5) {
            off += 5 // exclusive dependency (4) + weight (1)
        }

        val block      = if (off > 0) payload.copyOfRange(off, payload.size) else payload
        val endHeaders = (frame.flags and END_HEADERS) != 0
        return block to endHeaders
    }

    private fun readExactly(inp: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n); var off = 0
        while (off < n) {
            val r = inp.read(buf, off, n - off)
            if (r == -1) throw EOFException("Need $n got $off")
            off += r
        }
        return buf
    }

    // ── HPack Context ─────────────────────────────────────────────────────────

    /**
     * HPack декодер — RFC 7541.
     *
     * Статическая таблица (62 записи) + динамическая (обновляется при decode).
     * Каждое соединение имеет отдельный HPackContext для каждого направления.
     * NOT thread-safe — вызывать из одного потока.
     */
    inner class HPackContext(private var maxTableSize: Int = DEFAULT_HEADER_TABLE_SIZE) {
        private val dynTable = ArrayDeque<Pair<String, String>>()
        private var dynTableBytes = 0

        fun decode(block: ByteArray): Map<String, String> {
            val result = LinkedHashMap<String, String>(16)
            val buf    = ByteBuffer.wrap(block)

            while (buf.hasRemaining()) {
                val b = buf.get().toInt() and 0xFF

                when {
                    // 7.1 Indexed Header Field (bit 7 = 1)
                    b and 0x80 != 0 -> {
                        val idx = decodeInt(buf, b and 0x7F, 7)
                        val (n, v) = getEntry(idx)
                        if (n.isNotEmpty()) result[n] = v
                    }

                    // 7.2.1 Literal with Incremental Indexing (bits 7:6 = 01)
                    b and 0xC0 == 0x40 -> {
                        val idx  = decodeInt(buf, b and 0x3F, 6)
                        val name = if (idx > 0) getEntry(idx).first else readString(buf)
                        val value = readString(buf)
                        if (name.isNotEmpty()) {
                            result[name] = value
                            insertDyn(name, value)
                        }
                    }

                    // 7.3 Dynamic Table Size Update (bits 7:5 = 001)
                    b and 0xE0 == 0x20 -> {
                        val newSize = decodeInt(buf, b and 0x1F, 5)
                        updateMaxSize(newSize)
                    }

                    // 7.2.2 Literal without Indexing (bits 7:4 = 0000)
                    // 7.2.3 Literal Never Indexed  (bits 7:4 = 0001)
                    else -> {
                        val idx   = decodeInt(buf, b and 0x0F, 4)
                        val name  = if (idx > 0) getEntry(idx).first else readString(buf)
                        val value = readString(buf)
                        if (name.isNotEmpty()) result[name] = value
                    }
                }
            }
            return result
        }

        private fun getEntry(index: Int): Pair<String, String> {
            if (index <= 0) return "" to ""
            if (index < STATIC_TABLE.size) return STATIC_TABLE[index]
            val dynIdx = index - STATIC_TABLE.size
            return if (dynIdx < dynTable.size) dynTable[dynIdx] else "" to ""
        }

        private fun insertDyn(name: String, value: String) {
            val entrySize = name.length + value.length + 32
            dynTable.addFirst(name to value)
            dynTableBytes += entrySize
            evict()
        }

        private fun updateMaxSize(newMax: Int) {
            maxTableSize  = newMax
            evict()
        }

        private fun evict() {
            while (dynTable.isNotEmpty() && dynTableBytes > maxTableSize) {
                val removed = dynTable.removeLast()
                dynTableBytes -= removed.first.length + removed.second.length + 32
            }
        }

        // HPack integer decoding — RFC 7541 §5.1
        private fun decodeInt(buf: ByteBuffer, initial: Int, n: Int): Int {
            val maxVal = (1 shl n) - 1
            if (initial < maxVal) return initial
            var value = maxVal; var shift = 0
            while (buf.hasRemaining()) {
                val b = buf.get().toInt() and 0xFF
                value += (b and 0x7F) shl shift
                shift += 7
                if (b and 0x80 == 0) break
            }
            return value
        }

        // HPack string literal — RFC 7541 §5.2
        private fun readString(buf: ByteBuffer): String {
            if (!buf.hasRemaining()) return ""
            val b       = buf.get().toInt() and 0xFF
            val huffman = (b and 0x80) != 0
            val len     = decodeInt(buf, b and 0x7F, 7)
            if (len <= 0 || buf.remaining() < len) return ""
            val bytes   = ByteArray(len).also { buf.get(it) }
            return if (huffman) Huffman.decode(bytes) else String(bytes, Charsets.ISO_8859_1)
        }
    }
}

// ── Huffman decoder — RFC 7541 Appendix B ─────────────────────────────────────
//
// Полная таблица из 257 символов (0..255 + EOS = 256).
// Fast-path: таблица из 512 слотов покрывает коды длиной 5..8 бит за O(1).
// Slow-path: для кодов 9..30 бит — linear scan (редко).

object Huffman {

    // (code, bits) для символов 0..255. Данные из RFC 7541 Appendix B.
    private val CODE  = IntArray(256)
    private val BITS  = IntArray(256)

    init {
        val table = arrayOf(
            intArrayOf(0x1ff8,13), intArrayOf(0x7fffd8,23), intArrayOf(0xfffffe2,28),
            intArrayOf(0xfffffe3,28), intArrayOf(0xfffffe4,28), intArrayOf(0xfffffe5,28),
            intArrayOf(0xfffffe6,28), intArrayOf(0xfffffe7,28), intArrayOf(0xfffffe8,28),
            intArrayOf(0xffffea,24), intArrayOf(0x3ffffffc,30), intArrayOf(0xfffffe9,28),
            intArrayOf(0xfffffea,28), intArrayOf(0x3ffffffd,30), intArrayOf(0xfffffeb,28),
            intArrayOf(0xfffffec,28), intArrayOf(0xfffffed,28), intArrayOf(0xfffffee,28),
            intArrayOf(0xfffffef,28), intArrayOf(0xffffff0,28), intArrayOf(0xffffff1,28),
            intArrayOf(0xffffff2,28), intArrayOf(0x3ffffffe,30), intArrayOf(0xffffff3,28),
            intArrayOf(0xffffff4,28), intArrayOf(0xffffff5,28), intArrayOf(0xffffff6,28),
            intArrayOf(0xffffff7,28), intArrayOf(0xffffff8,28), intArrayOf(0xffffff9,28),
            intArrayOf(0xffffffa,28), intArrayOf(0xffffffb,28), intArrayOf(0x14,6),
            intArrayOf(0x3f8,10), intArrayOf(0x3f9,10), intArrayOf(0xffa,12),
            intArrayOf(0x1ff9,13), intArrayOf(0x15,6), intArrayOf(0xf8,8),
            intArrayOf(0x7fa,11), intArrayOf(0x3fa,10), intArrayOf(0x3fb,10),
            intArrayOf(0xf9,8), intArrayOf(0x7fb,11), intArrayOf(0xfa,8),
            intArrayOf(0x16,6), intArrayOf(0x17,6), intArrayOf(0x18,6),
            intArrayOf(0x0,5), intArrayOf(0x1,5), intArrayOf(0x2,5),
            intArrayOf(0x19,6), intArrayOf(0x1a,6), intArrayOf(0x1b,6),
            intArrayOf(0x1c,6), intArrayOf(0x1d,6), intArrayOf(0x1e,6),
            intArrayOf(0x1f,6), intArrayOf(0x5c,7), intArrayOf(0xfb,8),
            intArrayOf(0x7ffc,15), intArrayOf(0x20,6), intArrayOf(0xffb,12),
            intArrayOf(0x3fc,10), intArrayOf(0x1ffa,13), intArrayOf(0x21,6),
            intArrayOf(0x5d,7), intArrayOf(0x5e,7), intArrayOf(0x5f,7),
            intArrayOf(0x60,7), intArrayOf(0x61,7), intArrayOf(0x62,7),
            intArrayOf(0x63,7), intArrayOf(0x64,7), intArrayOf(0x65,7),
            intArrayOf(0x66,7), intArrayOf(0x67,7), intArrayOf(0x68,7),
            intArrayOf(0x69,7), intArrayOf(0x6a,7), intArrayOf(0x6b,7),
            intArrayOf(0x6c,7), intArrayOf(0x6d,7), intArrayOf(0x6e,7),
            intArrayOf(0x6f,7), intArrayOf(0x70,7), intArrayOf(0x71,7),
            intArrayOf(0x72,7), intArrayOf(0xfc,8), intArrayOf(0x73,7),
            intArrayOf(0xfd,8), intArrayOf(0x1ffb,13), intArrayOf(0x7fff0,19),
            intArrayOf(0x1ffc,13), intArrayOf(0x3ffc,14), intArrayOf(0x22,6),
            intArrayOf(0x7ffd,15), intArrayOf(0x3,5), intArrayOf(0x23,6),
            intArrayOf(0x4,5), intArrayOf(0x24,6), intArrayOf(0x5,5),
            intArrayOf(0x25,6), intArrayOf(0x26,6), intArrayOf(0x27,6),
            intArrayOf(0x6,5), intArrayOf(0x74,7), intArrayOf(0x75,7),
            intArrayOf(0x28,6), intArrayOf(0x29,6), intArrayOf(0x2a,6),
            intArrayOf(0x7,5), intArrayOf(0x2b,6), intArrayOf(0x76,7),
            intArrayOf(0x2c,6), intArrayOf(0x8,5), intArrayOf(0x9,5),
            intArrayOf(0x2d,6), intArrayOf(0x77,7), intArrayOf(0x78,7),
            intArrayOf(0x79,7), intArrayOf(0x7a,7), intArrayOf(0x7b,7),
            intArrayOf(0x7ffe,15), intArrayOf(0x7fc,11), intArrayOf(0x3ffd,14),
            intArrayOf(0x1ffd,13), intArrayOf(0xffffffc,28), intArrayOf(0xfffe6,20),
            intArrayOf(0x3fffd2,22), intArrayOf(0xfffe7,20), intArrayOf(0xfffe8,20),
            intArrayOf(0x3fffd3,22), intArrayOf(0x3fffd4,22), intArrayOf(0x3fffd5,22),
            intArrayOf(0x7fffd9,23), intArrayOf(0x3fffd6,22), intArrayOf(0x7fffda,23),
            intArrayOf(0x7fffdb,23), intArrayOf(0x7fffdc,23), intArrayOf(0x7fffdd,23),
            intArrayOf(0x7fffde,23), intArrayOf(0xffffeb,24), intArrayOf(0x7fffdf,23),
            intArrayOf(0xffffec,24), intArrayOf(0xffffed,24), intArrayOf(0x3fffd7,22),
            intArrayOf(0x7fffe0,23), intArrayOf(0xffffee,24), intArrayOf(0x7fffe1,23),
            intArrayOf(0x7fffe2,23), intArrayOf(0x7fffe3,23), intArrayOf(0x7fffe4,23),
            intArrayOf(0x1fffdc,21), intArrayOf(0x3fffd8,22), intArrayOf(0x7fffe5,23),
            intArrayOf(0x3fffd9,22), intArrayOf(0x7fffe6,23), intArrayOf(0x7fffe7,23),
            intArrayOf(0xffffef,24), intArrayOf(0x3fffda,22), intArrayOf(0x1fffdd,21),
            intArrayOf(0xfffe9,20), intArrayOf(0x3fffdb,22), intArrayOf(0x3fffdc,22),
            intArrayOf(0x7fffe8,23), intArrayOf(0x7fffe9,23), intArrayOf(0x1fffde,21),
            intArrayOf(0x7fffea,23), intArrayOf(0x3fffdd,22), intArrayOf(0x3fffde,22),
            intArrayOf(0xfffff0,24), intArrayOf(0x1fffdf,21), intArrayOf(0x3fffdf,22),
            intArrayOf(0x7fffeb,23), intArrayOf(0x7fffec,23), intArrayOf(0x1fffe0,21),
            intArrayOf(0x1fffe1,21), intArrayOf(0x3fffe0,22), intArrayOf(0x1fffe2,21),
            intArrayOf(0x7fffed,23), intArrayOf(0x3fffe1,22), intArrayOf(0x7fffee,23),
            intArrayOf(0x7fffef,23), intArrayOf(0xfffea,20), intArrayOf(0x3fffe2,22),
            intArrayOf(0x3fffe3,22), intArrayOf(0x3fffe4,22), intArrayOf(0x7ffff0,23),
            intArrayOf(0x3fffe5,22), intArrayOf(0x3fffe6,22), intArrayOf(0x7ffff1,23),
            intArrayOf(0x3ffffe0,26), intArrayOf(0x3ffffe1,26), intArrayOf(0xfffeb,20),
            intArrayOf(0x7fff1,19), intArrayOf(0x3fffe7,22), intArrayOf(0x7ffff2,23),
            intArrayOf(0x3fffe8,22), intArrayOf(0x1ffffec,25), intArrayOf(0x3ffffe2,26),
            intArrayOf(0x3ffffe3,26), intArrayOf(0x3ffffe4,26), intArrayOf(0x7ffffde,27),
            intArrayOf(0x7ffffdf,27), intArrayOf(0x3ffffe5,26), intArrayOf(0xfffff1,24),
            intArrayOf(0x1ffffed,25), intArrayOf(0x7fff2,19), intArrayOf(0x1fffe3,21),
            intArrayOf(0x3ffffe6,26), intArrayOf(0x7ffffe0,27), intArrayOf(0x7ffffe1,27),
            intArrayOf(0x3ffffe7,26), intArrayOf(0x7ffffe2,27), intArrayOf(0xfffff2,24),
            intArrayOf(0x1fffe4,21), intArrayOf(0x1fffe5,21), intArrayOf(0x3ffffe8,26),
            intArrayOf(0x3ffffe9,26), intArrayOf(0xffffffd,28), intArrayOf(0x7ffffe3,27),
            intArrayOf(0x7ffffe4,27), intArrayOf(0x7ffffe5,27), intArrayOf(0xfffec,20),
            intArrayOf(0xfffff3,24), intArrayOf(0xfffed,20), intArrayOf(0x1fffe6,21),
            intArrayOf(0x3fffe9,22), intArrayOf(0x1fffe7,21), intArrayOf(0x1fffe8,21),
            intArrayOf(0x7ffff3,23), intArrayOf(0x3fffea,22), intArrayOf(0x3fffeb,22),
            intArrayOf(0x1ffffee,25), intArrayOf(0x1ffffef,25), intArrayOf(0xfffff4,24),
            intArrayOf(0xfffff5,24), intArrayOf(0x3ffffea,26), intArrayOf(0x7ffff4,23),
            intArrayOf(0x3ffffeb,26), intArrayOf(0x7ffffe6,27), intArrayOf(0x3ffffec,26),
            intArrayOf(0x3ffffed,26), intArrayOf(0x7ffffe7,27), intArrayOf(0x7ffffe8,27),
            intArrayOf(0x7ffffe9,27), intArrayOf(0x7ffffea,27), intArrayOf(0x7ffffeb,27),
            intArrayOf(0xffffffe,28), intArrayOf(0x7ffffec,27), intArrayOf(0x7ffffed,27),
            intArrayOf(0x7ffffee,27), intArrayOf(0x7ffffef,27), intArrayOf(0x7fffff0,27),
            intArrayOf(0x3ffffee,26)
        )
        table.forEachIndexed { i, (code, bits) -> CODE[i] = code; BITS[i] = bits }
    }

    // Reverse lookup: index = code shifted to top 20 bits → char (-1 = no match)
    // Покрывает коды 5..20 бит в O(1); коды 21-30 — linear fallback.
    private val FAST_TABLE: IntArray by lazy {
        val t = IntArray(1 shl 20) { -1 }
        for (c in 0..255) {
            val bits = BITS[c]
            if (bits > 20) continue
            val code    = CODE[c]
            val shift   = 20 - bits
            val entries = 1 shl shift
            for (j in 0 until entries) {
                t[((code shl shift) or j) and 0xFFFFF] = (c shl 8) or bits
            }
        }
        t
    }

    fun decode(data: ByteArray): String {
        val sb   = StringBuilder(data.size * 2)
        var bits = 0L    // accumulator (up to 64 bits)
        var nBits = 0    // how many bits are valid in accumulator

        for (b in data) {
            bits   = (bits shl 8) or (b.toLong() and 0xFF)
            nBits += 8

            while (nBits >= 5) {
                // Fast path: try top 20 bits
                val top20  = ((bits shr (nBits - 20)) and 0xFFFFF).toInt()
                val fastHit = if (nBits >= 20) FAST_TABLE[top20] else -1

                if (fastHit != -1) {
                    val sym  = (fastHit shr 8) and 0xFF
                    val len  = fastHit and 0xFF
                    if (len <= nBits) {
                        sb.append(sym.toChar())
                        nBits -= len
                        val mask = if (nBits >= 64) -1L else (1L shl nBits) - 1L
                        bits = bits and mask
                        continue
                    }
                }

                // Slow path: linear scan for codes 21..30 bits
                var matched = false
                for (c in 0..255) {
                    val len = BITS[c]
                    if (len > nBits || len <= 20) continue
                    val code = CODE[c].toLong()
                    val top  = (bits shr (nBits - len)) and ((1L shl len) - 1L)
                    if (top == code) {
                        sb.append(c.toChar())
                        nBits -= len
                        val mask = if (nBits >= 64) -1L else (1L shl nBits) - 1L
                        bits = bits and mask
                        matched = true
                        break
                    }
                }
                if (!matched) break
            }
        }
        return sb.toString()
    }
}
