package com.adblocker.proxy

import android.util.Log
import com.adblocker.filter.engine.FilterEngine
import com.adblocker.filter.engine.ResourceType
import com.google.gson.Gson
import com.google.gson.JsonParser
import java.nio.charset.Charset

class AdFilter(private val filterEngine: FilterEngine) {

    companion object {
        private const val TAG = "AdFilter"

        var onRequest: ((host: String, url: String, blocked: Boolean, code: Int) -> Unit)? = null

        private val INJECTION_CSS = """
.ad,.ads,.adv,.advert,.advertisement,.advertising,
.ad-container,.ad-wrapper,.ad-slot,.ad-unit,.ad-banner,
.ad-block,.ad-box,.ad-placeholder,.ad-frame,.ad-area,
.ad-wrap,.ad-row,.ad-zone,.ad-space,.ad-leaderboard,
.ad-rectangle,.ad-skyscraper,.ad-footer,.ad-header,
.ad-sidebar,.ad-center,.ad-top,.ad-bottom,.ad-right,.ad-left,
.ad-inner,.ad-outer,.ad-type-image,.ad-type-text,.ad-type-video,
.adsbygoogle,ins.adsbygoogle,
[data-ad-client],[data-ad-slot],[data-ad-unit],[data-ad-format],[data-ad-region],
[id^="div-gpt-ad"],[id^="google_ads_iframe"],[id^="google_ads_frame"],
[class*="advert"],[class*="-ad-"],[class*="_ad_"],[class^="ad-"],[class^="ads-"],
[id*="advert"],[id*="-ad-"],[id*="_ad_"],[id^="ad-"],[id^="ads-"],
.yandex-ad,.ya-ad,[class*="yandex-adv"],.Y-ads,
.adfox-title,.adfox-body,.adfox-block,.adfox-unit,
[class*="adfox"],[id*="adfox"],
.banner-ad,.banner_ad,.top-banner,.sticky-ad,.floating-ad,
.overlay-ad,.interstitial,.popup-ad,.modal-ad,
.ad-overlay,.ad-modal,.ad-notice,.ad-alert,
.sponsored,.sponsored-content,.sponsor-box,
[data-sponsored],[aria-label="Sponsored"],[aria-label="Ad"],
[aria-label="Ads"],[aria-label="Advertisement"],[aria-label="Реклама"],
[data-testid="ad"],[data-testid="ads"],[data-testid="advertisement"],
[data-ad="true"],[data-ads="true"],
.dfp-ad,.dfp-slot,.dfp-unit,[class*="dfp-"],[id*="dfp-"],
.gpt-ad,.gpt-slot,[class*="gpt-"],
.taboola,.taboola-widget,[id*="taboola"],[class*="taboola"],
.trc_related_container,#outbrain_widget,.OUTBRAIN,
[id*="outbrain"],[class*="outbrain"],
#mgid-container,[id*="mgid"],[class*="mgid"],
.smartbanner,.smartbanner-container,[class*="smartbanner"],
.adblock-notice,.adblock-warning,.anti-adblock,
#adblock-overlay,.no-adblock-message,.ad-blocker-notice,
.adblock-detector,[class*="adblock-detect"],
.ab-shim,.ab-overlay,[class*="ab-shim"],[class*="ab-overlay"],
iframe[src*="doubleclick"],iframe[src*="googlesyndication"],
iframe[src*="googleadservices"],iframe[src*="adnxs"],
iframe[src*="amazon-adsystem"],iframe[src*="taboola"],
iframe[src*="outbrain"],iframe[src*="criteo"],
#ad,#ads,#advert,#advertisement,#banner_ad,#ad_banner,
#top_ad,#sidebar_ad,#footer_ad,#header_ad,#ad_box,#ad_slot,
[id^="ad-unit"],[id^="adunit"],[id^="adspot"] {
  display: none !important;
  visibility: hidden !important;
  opacity: 0 !important;
  pointer-events: none !important;
  height: 0 !important;
  max-height: 0 !important;
  overflow: hidden !important;
}
""".trimIndent()

        // language=JavaScript
        private val INJECTION_JS = """<script id="__ab_js__">(function(){
'use strict';
var _noop=function(){};
var _obj={onDetected:_noop,onNotDetected:function(cb){if(typeof cb==='function')cb();},check:function(){return true;},setOption:_noop};
var _flags={adblock:false,adblockDetected:false,__adblockDetected:false,AdBlocker:false,adBlocker:false,
  isAdblockEnabled:false,adBlockEnabled:false,adBlockActive:false,canRunAds:true,
  blockAdBlock:_obj,FuckAdBlock:function(){return _obj;},adsBlocked:false,
  adsBypassed:true,hasAdBlocker:false,adBlockDetected:false,AdBlock:false};
Object.keys(_flags).forEach(function(k){
  try{Object.defineProperty(window,k,{get:function(){return _flags[k];},set:_noop,configurable:true,enumerable:false});}catch(e){}
});
var _adRe=/googlesyndication|doubleclick|adservice\.google|pagead2|adnxs\.com|criteo\.com|taboola\.com|outbrain\.com|moatads|adsafeprotected|amazon-adsystem|yandex\.ru\/an\//i;
var _origOpen=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,url){
  if(typeof url==='string'&&_adRe.test(url)){this.__ab=true;return;}
  return _origOpen.apply(this,arguments);
};
var _origSend=XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send=function(){
  if(this.__ab){
    try{Object.defineProperty(this,'status',{get:function(){return 200;}});}catch(e){}
    try{Object.defineProperty(this,'readyState',{get:function(){return 4;}});}catch(e){}
    try{Object.defineProperty(this,'responseText',{get:function(){return '';}});}catch(e){}
    return;
  }
  return _origSend.apply(this,arguments);
};
if(window.fetch){
  var _origFetch=window.fetch;
  window.fetch=function(input,init){
    var url=typeof input==='string'?input:(input&&input.url?input.url:'');
    if(_adRe.test(url))return Promise.resolve(new Response('',{status:200}));
    return _origFetch.apply(this,arguments);
  };
}
var _sel=[
  'ins.adsbygoogle','.adsbygoogle','[data-ad-slot]','[data-ad-client]',
  '[id^="div-gpt-ad"]','[id^="google_ads_"]',
  '[class*="taboola"]','[class*="outbrain"]',
  'iframe[src*="doubleclick"]','iframe[src*="googlesyndication"]',
  'iframe[src*="adnxs"]','iframe[src*="amazon-adsystem"]',
  '[class*="advert"]:not(html):not(body):not(head)',
  '[class*="sponsor"]:not(html):not(body):not(head)'
].join(',');
function _hide(root){
  try{(root||document).querySelectorAll(_sel).forEach(function(el){
    el.style.setProperty('display','none','important');
    el.style.setProperty('visibility','hidden','important');
    el.style.setProperty('height','0','important');
  });}catch(e){}
}
if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',function(){_hide();});}
else{_hide();}
new MutationObserver(function(ms){ms.forEach(function(m){m.addedNodes.forEach(function(n){if(n.nodeType===1){_hide(n);}});});})
  .observe(document.documentElement,{childList:true,subtree:true});
if(location.hostname.indexOf('youtube')!==-1){
  setInterval(function(){
    try{
      var s=document.querySelector('.ytp-ad-skip-button,.ytp-skip-ad-button');if(s)s.click();
      document.querySelectorAll('.ad-showing,.ytp-ad-overlay-container,.ytp-ad-module').forEach(function(e){e.style.setProperty('display','none','important');});
      var v=document.querySelector('video.ad-showing,video');
      if(v&&document.querySelector('.ad-showing')&&!isNaN(v.duration)){v.currentTime=v.duration;}
    }catch(e){}
  },300);
}
})();</script>"""

        private val YOUTUBE_AD_KEYS = setOf(
            "adPlacements","playerAds","adSlots",
            "adBreakHeartbeatParams","auxiliaryUi",
            "adBreakParams","adClientToken","adBreakServiceResponseGroup"
        )
        private val YOUTUBE_API_PATHS = setOf(
            "youtubei/v1/player","youtubei/v1/next",
            "youtubei/v1/browse","youtubei/v1/search"
        )
        private val gson = Gson()
    }

    data class RequestInfo(
        val host: String,
        val url: String,
        val method: String,
        val referer: String?,
        val accept: String?,
        val contentType: String?
    ) {
        val resourceType: ResourceType get() = ResourceType.fromAccept(accept)
        val isThirdParty: Boolean get() {
            if (referer.isNullOrBlank()) return false
            return try {
                val rh = java.net.URI(referer).host?.lowercase()?.removePrefix("www.") ?: return false
                val h  = host.lowercase().removePrefix("www.")
                !h.endsWith(rh) && !rh.endsWith(h)
            } catch (_: Exception) { false }
        }
        val isYouTubeApi: Boolean get() = YOUTUBE_API_PATHS.any { url.contains(it) }
    }

    fun shouldBlock(info: RequestInfo): Boolean =
        filterEngine.shouldBlock(info.url, info.host, info.resourceType, info.isThirdParty)

    fun processResponseBody(
        body: ByteArray,
        contentType: String,
        host: String,
        url: String,
        isYouTubeApi: Boolean
    ): ByteArray? = when {
        isYouTubeApi && "json" in contentType -> processYouTubeJson(body)
        "text/html" in contentType            -> processHtml(body, contentType, host)
        else                                  -> null
    }

    private fun processHtml(body: ByteArray, contentType: String, host: String): ByteArray? {
        val charset = extractCharset(contentType)
        val html    = String(body, charset)

        val engineCss = filterEngine.getCssForHost(host)
        val fullCss   = if (engineCss.isNotEmpty())
            "$INJECTION_CSS\n/* EasyList cosmetic */\n$engineCss"
        else INJECTION_CSS

        // Scriptlets: uBO-совместимые JS сниппеты (abort-on-property-read и др.)
        val scriptlets = com.adblocker.filter.scriptlet.ScriptletEngine.getScriptletsForHost(host)

        // Порядок: CSS → scriptlets → основной JS
        val block = "\n<style id='__ab_css__'>$fullCss</style>\n$scriptlets\n$INJECTION_JS\n"

        val headEnd   = html.indexOf("</head>", ignoreCase = true)
        val bodyStart = if (headEnd < 0) html.indexOf("<body", ignoreCase = true) else -1
        val htmlTag   = if (headEnd < 0 && bodyStart < 0) html.indexOf("<html", ignoreCase = true) else -1

        return when {
            headEnd >= 0 ->
                (html.substring(0, headEnd) + block + html.substring(headEnd)).toByteArray(charset)
            bodyStart >= 0 -> {
                val after = html.indexOf('>', bodyStart) + 1
                (html.substring(0, after) + block + html.substring(after)).toByteArray(charset)
            }
            htmlTag >= 0 -> {
                val after = html.indexOf('>', htmlTag) + 1
                (html.substring(0, after) + block + html.substring(after)).toByteArray(charset)
            }
            else -> null
        }
    }

    private fun processYouTubeJson(body: ByteArray): ByteArray? {
        return try {
            val json = String(body, Charsets.UTF_8)
            if (json.isBlank()) return null
            val root    = JsonParser.parseString(json)
            val changed = stripAdKeys(root)
            if (!changed) null else gson.toJson(root).toByteArray(Charsets.UTF_8)
        } catch (_: Exception) { null }
    }

    private fun stripAdKeys(el: com.google.gson.JsonElement): Boolean {
        var changed = false
        when {
            el.isJsonObject -> {
                val obj = el.asJsonObject
                YOUTUBE_AD_KEYS.forEach { key ->
                    if (obj.has(key)) { obj.remove(key); changed = true }
                }
                obj.entrySet().forEach { if (stripAdKeys(it.value)) changed = true }
            }
            el.isJsonArray -> el.asJsonArray.forEach { if (stripAdKeys(it)) changed = true }
        }
        return changed
    }

    /**
     * CSP убирается полностью — без этого браузер заблокирует инъектированный JS.
     */
    fun patchCsp(headers: MutableMap<String, String>) {
        headers.remove("content-security-policy")
        headers.remove("content-security-policy-report-only")
        headers.remove("x-frame-options")
    }

    fun logRequest(host: String, url: String, blocked: Boolean, code: Int) {
        try { onRequest?.invoke(host, url, blocked, code) } catch (_: Exception) {}
    }

    private fun extractCharset(contentType: String): Charset = try {
        Regex("charset=([\\w-]+)", RegexOption.IGNORE_CASE)
            .find(contentType)?.groupValues?.get(1)
            ?.let { Charset.forName(it) } ?: Charsets.UTF_8
    } catch (_: Exception) { Charsets.UTF_8 }
}
