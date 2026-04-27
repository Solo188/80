package com.adblocker.filter.engine

import android.content.Context
import com.adblocker.filter.parser.EasyListParser
import com.adblocker.filter.rules.FilterRule
import com.adblocker.filter.rules.RuleOption
import com.adblocker.filter.scriptlet.ScriptletEngine
import com.adblocker.filter.updater.FilterUpdater
import com.adblocker.utils.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch

class FilterEngine(private val context: Context) {

    companion object { private const val TAG = "FilterEngine" }

    private val blockTrie     = DomainTrie()
    private val exceptionTrie = DomainTrie()
    private val blockAho      = AhoCorasick()
    private val exceptionAho  = AhoCorasick()
    private val typedRules    = CopyOnWriteArrayList<TypedRule>()
    private val globalCss     = CopyOnWriteArrayList<String>()
    private val perDomainCss  = ConcurrentHashMap<String, CopyOnWriteArrayList<String>>()
    private val cssExceptions  = ConcurrentHashMap.newKeySet<String>()

    @Volatile var ruleCount = 0; private set
    private val readyLatch  = CountDownLatch(1)
    fun awaitReady()        { readyLatch.await() }
    val isReady get()       = readyLatch.count == 0L
    val filterUpdater       = FilterUpdater(context)

    suspend fun initialize() = withContext(Dispatchers.IO) {
        loadBuiltinRules()
        for (source in FilterUpdater.FILTER_SOURCES) {
            val file = filterUpdater.getFilterFile(source)
            if (file != null) loadFileSafe(file, source.name)
            else loadAssetSafe("filters/${source.filename}")
        }
        blockAho.build()
        exceptionAho.build()
        ruleCount = blockTrie.size + blockAho.patternCount + typedRules.size
        Logger.i(TAG, "Ready: $ruleCount rules, ${globalCss.size} CSS, ${perDomainCss.size} host-CSS")
        readyLatch.countDown()
        // Обновление в фоне — не блокирует старт VPN
        try { filterUpdater.updateIfNeeded() } catch (e: Exception) { Logger.w(TAG, "Update: ${e.message}") }
    }

    private fun loadFileSafe(file: File, name: String) {
        try { file.inputStream().use { parseStream(it) }
              Logger.i(TAG, "Loaded $name (${file.length()/1024}KB)") }
        catch (e: Exception) { Logger.w(TAG, "Load $name failed: ${e.message}") }
    }

    private fun loadAssetSafe(path: String) {
        try { context.assets.open(path).use { parseStream(it) } }
        catch (_: Exception) { Logger.d(TAG, "Asset missing: $path") }
    }

    private fun parseStream(stream: InputStream) =
        EasyListParser.parse(stream).forEach { addRule(it) }

    private fun loadBuiltinRules() {
        listOf(
            "doubleclick.net","googlesyndication.com","googleadservices.com",
            "googletagservices.com","googletagmanager.com","google-analytics.com",
            "adnxs.com","advertising.com","adform.net","adroll.com",
            "criteo.com","criteo.net","rubiconproject.com","openx.net",
            "pubmatic.com","casalemedia.com","smartadserver.com","contextweb.com",
            "buysellads.com","scorecardresearch.com","quantserve.com","demdex.net",
            "amazon-adsystem.com","adtechus.com","outbrain.com","taboola.com",
            "revcontent.com","mgid.com","hotjar.com","moatads.com",
            "33across.com","lijit.com","smaato.com","adsafeprotected.com",
            "omtrdc.net","chartbeat.com","addthis.com","sharethis.com",
            "pagead2.googlesyndication.com","tpc.googlesyndication.com",
            "adservice.google.com","stats.g.doubleclick.net",
            "ads.twitter.com","ads.linkedin.com","advertising.amazon.com",
            "mc.yandex.ru","an.yandex.ru","adfox.ru","bs.yandex.ru",
            "advertising.yandex.ru","yandexadexchange.net","betweendigital.com",
            "smi2.ru","smi2.net","adriver.ru","begun.ru","directadvert.ru",
            "getintent.com","marketgid.com","soloway.ru","rtb.ru","segmento.ru",
            "appnexus.com","bidswitch.net","spotxchange.com","index.exchange",
            "lkqd.net","freewheel.tv","unrulymedia.com","sovrn.com",
            "turn.com","bluekai.com","quantcast.com","atdmt.com",
            "imrworldwide.com","comscore.com","2o7.net","flurry.com",
            "appsflyer.com","adjust.com","kochava.com","segment.io",
            "amplitude.com","fullstory.com","newrelic.com","nr-data.net",
            "parsely.com","fastly-insights.com","tapad.com","tealium.com"
        ).forEach { blockTrie.insert(it) }

        listOf(
            "/ads/","/ad/","/advert/","/advertising/","/adsystem/",
            "/adserver/","/adservice/","/adtech/","/adtrack/",
            "/pagead/","/doubleclick/","/googlesyndication/",
            "/banner/","/banners/","/sponsor/","/sponsored/",
            "/tracking/","/tracker/","/pixel/","/beacon/",
            "/analytics/collect","/telemetry/","/metrics/"
        ).forEach { blockAho.addPattern(it) }

        globalCss.addAll(listOf(
            ".ad",".ads",".adv",".advert",".advertisement",".advertising",
            ".ad-container",".ad-wrapper",".ad-slot",".ad-unit",".ad-banner",
            ".ad-block",".ad-box",".ad-placeholder",".ad-frame",".ad-area",
            "[class*='advert']","[class*='-ad-']","[class*='_ad_']",
            "[id*='advert']","[id*='-ad-']","[id*='_ad_']",
            "[id^='ad-']","[id^='ads-']","[class^='ad-']","[class^='ads-']",
            ".adsbygoogle","ins.adsbygoogle","[data-ad-client]","[data-ad-slot]",
            ".yandex-ad",".ya-ad","[class*='yandex-adv']",".Y-ads",
            ".adfox-title",".adfox-body","[class*='adfox']","[id*='adfox']",
            ".banner-ad",".banner_ad",".top-banner",".sticky-ad",".floating-ad",
            ".overlay-ad",".interstitial",".popup-ad",".modal-ad",
            ".sponsored",".sponsored-content",".sponsor-box",
            "[data-sponsored]","[aria-label='Sponsored']","[aria-label='Ad']",
            "[aria-label='Реклама']","[data-testid='ad']","[data-testid='ads']",
            ".taboola","[id*='taboola']","[class*='taboola']",
            ".trc_related_container","#outbrain_widget",".OUTBRAIN",
            "[id*='outbrain']","[class*='outbrain']",
            "#mgid-container","[id*='mgid']","[class*='mgid']",
            ".adblock-notice",".adblock-warning",".anti-adblock",
            "#adblock-overlay",".no-adblock-message",".ad-blocker-notice",
            ".adblock-detector","[class*='adblock-detect']"
        ))
    }

    private fun addRule(rule: FilterRule) {
        when (rule) {
            is FilterRule.NetworkRule -> {
                val hasTypeOpt = rule.options.any { it.isResourceType() }
                if (rule.isException) {
                    if (rule.domainAnchored) exceptionTrie.insert(rule.pattern)
                    else exceptionAho.addPattern(rule.pattern)
                } else {
                    when {
                        hasTypeOpt         -> typedRules.add(TypedRule(rule.pattern, rule.domainAnchored, rule.options))
                        rule.domainAnchored -> blockTrie.insert(rule.pattern)
                        else               -> blockAho.addPattern(rule.pattern)
                    }
                }
            }
            is FilterRule.DomainRule -> {
                if (rule.isException) exceptionTrie.insert(rule.domain)
                else blockTrie.insert(rule.domain)
            }
            is FilterRule.CosmeticRule -> {
                if (rule.isException) { cssExceptions.add(rule.cssSelector); return }
                if (rule.domains.isEmpty()) globalCss.add(rule.cssSelector)
                else rule.domains.forEach { d ->
                    perDomainCss.getOrPut(d.lowercase().removePrefix("www.")) { CopyOnWriteArrayList() }
                        .add(rule.cssSelector)
                }
            }
            is FilterRule.Comment -> {}
        }
    }

    fun shouldBlock(url: String, host: String,
                    resType: ResourceType = ResourceType.OTHER,
                    thirdParty: Boolean   = true): Boolean {
        val h = host.lowercase().removePrefix("www.")
        val u = url.lowercase()
        if (exceptionTrie.matches(h)) return false
        if (exceptionAho.matches(u))  return false
        if (blockTrie.matches(h))     return true
        if (blockAho.matches(u))      return true
        for (r in typedRules) {
            val match = if (r.domainAnchored) h == r.pattern || h.endsWith(".${r.pattern}")
                        else u.contains(r.pattern)
            if (!match) continue
            val typeOpts = r.options.filter { it.isResourceType() }
            if (typeOpts.isNotEmpty() && typeOpts.none { it.matchesResourceType(resType) }) continue
            if (RuleOption.THIRD_PARTY in r.options && !thirdParty) continue
            if (RuleOption.FIRST_PARTY in r.options &&  thirdParty) continue
            return true
        }
        return false
    }

    fun getCssForHost(host: String): String {
        val h    = host.lowercase().removePrefix("www.")
        val sels = LinkedHashSet<String>(globalCss)
        perDomainCss[h]?.let { sels.addAll(it) }
        val parent = h.substringAfter('.')
        if (parent != h) perDomainCss[parent]?.let { sels.addAll(it) }
        val filtered = sels.filter { it !in cssExceptions }
        if (filtered.isEmpty()) return ""
        return filtered.joinToString(",\n") + " { display:none!important; visibility:hidden!important; }"
    }

    fun getScriptletsForHost(host: String): String =
        ScriptletEngine.getScriptletsForHost(host)

    fun hasCssRules() = globalCss.isNotEmpty()

    data class TypedRule(val pattern: String, val domainAnchored: Boolean, val options: Set<RuleOption>)
}

enum class ResourceType {
    SCRIPT, STYLESHEET, IMAGE, XMLHTTPREQUEST,
    DOCUMENT, SUBDOCUMENT, FONT, MEDIA, WEBSOCKET, PING, POPUP, OTHER;
    companion object {
        fun fromAccept(accept: String?): ResourceType {
            val a = accept?.lowercase() ?: return OTHER
            return when {
                "javascript" in a || "ecmascript" in a -> SCRIPT
                "text/css"   in a -> STYLESHEET
                "image/"     in a -> IMAGE
                "text/html"  in a -> DOCUMENT
                else              -> OTHER
            }
        }
    }
}

fun RuleOption.isResourceType() = this in setOf(
    RuleOption.SCRIPT, RuleOption.STYLESHEET, RuleOption.IMAGE,
    RuleOption.XMLHTTPREQUEST, RuleOption.DOCUMENT, RuleOption.SUBDOCUMENT,
    RuleOption.FONT, RuleOption.MEDIA, RuleOption.WEBSOCKET, RuleOption.PING, RuleOption.POPUP
)

fun RuleOption.matchesResourceType(t: ResourceType) = when (this) {
    RuleOption.SCRIPT         -> t == ResourceType.SCRIPT
    RuleOption.STYLESHEET     -> t == ResourceType.STYLESHEET
    RuleOption.IMAGE          -> t == ResourceType.IMAGE
    RuleOption.XMLHTTPREQUEST -> t == ResourceType.XMLHTTPREQUEST
    RuleOption.DOCUMENT       -> t == ResourceType.DOCUMENT
    RuleOption.SUBDOCUMENT    -> t == ResourceType.SUBDOCUMENT
    RuleOption.FONT           -> t == ResourceType.FONT
    RuleOption.MEDIA          -> t == ResourceType.MEDIA
    RuleOption.WEBSOCKET      -> t == ResourceType.WEBSOCKET
    RuleOption.PING           -> t == ResourceType.PING
    RuleOption.POPUP          -> t == ResourceType.POPUP
    else                      -> false
}
