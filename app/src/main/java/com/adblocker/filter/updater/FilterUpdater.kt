package com.adblocker.filter.updater

import android.content.Context
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Автообновление фильтрующих списков: EasyList, EasyPrivacy, RU AdList, uBlock Unbreak.
 * Скачивает свежие правила и сохраняет в filesDir/filters/.
 * Обновляет максимум раз в 24 часа.
 */
class FilterUpdater(private val context: Context) {

    companion object {
        private const val TAG             = "FilterUpdater"
        private const val UPDATE_INTERVAL = 24 * 60 * 60 * 1000L  // 24 ч
        private const val CONNECT_TIMEOUT = 15_000
        private const val READ_TIMEOUT    = 30_000

        val FILTER_SOURCES = listOf(
            FilterSource(
                name     = "EasyList",
                filename = "easylist.txt",
                urls     = listOf(
                    "https://easylist.to/easylist/easylist.txt",
                    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist.txt"
                )
            ),
            FilterSource(
                name     = "EasyPrivacy",
                filename = "easyprivacy.txt",
                urls     = listOf(
                    "https://easylist.to/easylist/easyprivacy.txt",
                    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easyprivacy.txt"
                )
            ),
            FilterSource(
                name     = "RU AdList",
                filename = "ruadlist.txt",
                urls     = listOf(
                    "https://raw.githubusercontent.com/nicerush/ruadlist/master/advblock.txt",
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/Russian/filter.txt"
                )
            ),
            FilterSource(
                name     = "uBlock Unbreak",
                filename = "unbreak.txt",
                urls     = listOf(
                    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt"
                )
            )
        )
    }

    data class FilterSource(val name: String, val filename: String, val urls: List<String>)

    private val filtersDir: File
        get() = File(context.filesDir, "filters").also { it.mkdirs() }

    /**
     * Возвращает актуальный файл фильтра если он существует, иначе null.
     * FilterEngine использует это чтобы решить: брать из filesDir или из assets.
     */
    fun getFilterFile(source: FilterSource): File? {
        val f = File(filtersDir, source.filename)
        return if (f.exists() && f.length() > 1024) f else null
    }

    /**
     * Обновляет все фильтры в фоне если прошло > 24 часа.
     * Вызывается из FilterEngine.initialize() уже после старта VPN — не блокирует его.
     */
    fun updateIfNeeded() {
        val now = System.currentTimeMillis()
        FILTER_SOURCES.forEach { source ->
            val f = File(filtersDir, source.filename)
            if (!f.exists() || (now - f.lastModified()) > UPDATE_INTERVAL) {
                updateSource(source, f)
            } else {
                Log.d(TAG, "${source.name}: up to date (${f.length() / 1024} KB)")
            }
        }
    }

    private fun updateSource(source: FilterSource, dest: File) {
        Log.i(TAG, "Updating ${source.name}…")
        for (url in source.urls) {
            if (downloadTo(url, dest)) {
                Log.i(TAG, "${source.name}: ${dest.length() / 1024} KB")
                return
            }
        }
        Log.w(TAG, "${source.name}: all URLs failed")
    }

    private fun downloadTo(urlStr: String, dest: File): Boolean = try {
        val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
            connectTimeout       = CONNECT_TIMEOUT
            readTimeout          = READ_TIMEOUT
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "AdBlocker/4.0 (filter-update)")
        }
        if (conn.responseCode != 200) { conn.disconnect(); false }
        else {
            val tmp = File(dest.parent, dest.name + ".tmp")
            conn.inputStream.use { i -> tmp.outputStream().use { o -> i.copyTo(o) } }
            conn.disconnect()
            if (tmp.length() < 1024) { tmp.delete(); false }
            else { tmp.renameTo(dest); true }
        }
    } catch (e: Exception) { Log.d(TAG, "Failed ($urlStr): ${e.message}"); false }
}
