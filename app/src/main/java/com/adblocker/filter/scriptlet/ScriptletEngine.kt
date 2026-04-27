package com.adblocker.filter.scriptlet

/**
 * Scriptlets — JS-сниппеты совместимые с uBlock Origin / AdGuard.
 *
 * Каждый scriptlet — это именованная JS функция которая нейтрализует
 * конкретный anti-adblock или рекламный механизм.
 *
 * Используется в AdFilter.processHtml() — scriptlets инжектируются
 * в <head> ПЕРЕД любыми скриптами страницы.
 *
 * Поддерживаемые scriptlets:
 *  - abort-on-property-read (aopr)    — бросает ошибку при чтении свойства
 *  - abort-on-property-write (aopw)   — бросает ошибку при записи свойства
 *  - set-constant                     — устанавливает константное значение
 *  - prevent-setTimeout               — блокирует setTimeout с matching кодом
 *  - prevent-setInterval              — блокирует setInterval с matching кодом
 *  - no-op-func                       — заменяет функцию на no-op
 *  - json-prune                       — удаляет ключи из JSON.parse результата
 *  - prevent-xhr                      — блокирует XHR к matching URL
 *  - prevent-fetch                    — блокирует fetch к matching URL
 *  - remove-class                     — удаляет CSS класс с элементов
 *  - trusted-set-cookie               — устанавливает cookie (anti-paywall)
 *  - disable-newtab-links             — отключает принудительные редиректы
 */
object ScriptletEngine {

    /**
     * Возвращает JS код для всех scriptlets применимых к данному хосту.
     * Оборачивается в IIFE и вставляется в <script> тег.
     */
    fun getScriptletsForHost(host: String): String {
        val applicable = RULES.filter { rule ->
            rule.domains.isEmpty() || rule.domains.any { d ->
                host == d || host.endsWith(".$d")
            }
        }
        if (applicable.isEmpty()) return ""

        return buildString {
            append("<script id='__ab_scriptlets__'>(function(){\n'use strict';\n")
            append(SCRIPTLET_LIBRARY)
            append("\n/* Host-specific scriptlets */\n")
            applicable.forEach { rule ->
                append(buildScriptletCall(rule))
                append("\n")
            }
            append("})();</script>")
        }
    }

    // ── Scriptlet library ─────────────────────────────────────────────────────

    private val SCRIPTLET_LIBRARY = """
/* === AdBlocker Scriptlet Library === */
var _slib={
  /* abort-on-property-read: бросает TypeError при чтении obj.prop */
  aopr:function(chain){
    var parts=chain.split('.');
    var obj=window;
    for(var i=0;i<parts.length-1;i++){
      if(!obj||typeof obj!=='object')return;
      obj=obj[parts[i]];
    }
    var last=parts[parts.length-1];
    if(!obj)return;
    try{
      Object.defineProperty(obj,last,{
        get:function(){throw new ReferenceError(last);},
        set:function(){},
        configurable:true
      });
    }catch(e){}
  },

  /* abort-on-property-write */
  aopw:function(chain){
    var parts=chain.split('.');
    var obj=window;
    for(var i=0;i<parts.length-1;i++){
      if(!obj)return;
      obj=obj[parts[i]];
    }
    var last=parts[parts.length-1];
    if(!obj)return;
    try{
      Object.defineProperty(obj,last,{
        get:function(){return undefined;},
        set:function(){throw new ReferenceError(last);},
        configurable:true
      });
    }catch(e){}
  },

  /* set-constant: устанавливает window.prop = constant значение */
  sc:function(chain,value){
    var val;
    switch(value){
      case 'true':val=true;break;
      case 'false':val=false;break;
      case 'null':val=null;break;
      case 'undefined':val=undefined;break;
      case 'noopFunc':val=function(){};break;
      case 'trueFunc':val=function(){return true;};break;
      case 'falseFunc':val=function(){return false;};break;
      case 'emptyArr':val=[];break;
      case 'emptyObj':val={};break;
      case '':val='';break;
      default:
        val=isNaN(Number(value))?value:Number(value);
    }
    var parts=chain.split('.');
    var obj=window;
    for(var i=0;i<parts.length-1;i++){
      if(obj===undefined||obj===null)return;
      if(!(parts[i] in obj))obj[parts[i]]={};
      obj=obj[parts[i]];
    }
    var last=parts[parts.length-1];
    try{
      Object.defineProperty(obj,last,{
        get:function(){return val;},
        set:function(){},
        configurable:true,
        enumerable:true
      });
    }catch(e){try{obj[last]=val;}catch(e2){}}
  },

  /* prevent-setTimeout: блокирует setTimeout если fn.toString() содержит needle */
  pst:function(needle,delay){
    var _orig=window.setTimeout;
    window.setTimeout=function(fn,d){
      var src=typeof fn==='function'?fn.toString():(fn||'').toString();
      if(needle&&src.indexOf(needle)!==-1){return 0;}
      if(delay&&d==Number(delay)){return 0;}
      return _orig.apply(this,arguments);
    };
  },

  /* prevent-setInterval */
  psi:function(needle,delay){
    var _orig=window.setInterval;
    window.setInterval=function(fn,d){
      var src=typeof fn==='function'?fn.toString():(fn||'').toString();
      if(needle&&src.indexOf(needle)!==-1){return 0;}
      if(delay&&d==Number(delay)){return 0;}
      return _orig.apply(this,arguments);
    };
  },

  /* no-op-func: заменяет obj.method на пустую функцию */
  noop:function(chain){
    _slib.sc(chain,'noopFunc');
  },

  /* json-prune: удаляет ключи из результата JSON.parse */
  jp:function(propsToRemove){
    var props=propsToRemove.split(' ');
    var _orig=JSON.parse;
    JSON.parse=function(text){
      var result=_orig.call(this,text);
      if(result&&typeof result==='object'){
        props.forEach(function(p){
          if(p in result)delete result[p];
        });
      }
      return result;
    };
  },

  /* prevent-xhr: блокирует XHR к URL содержащему needle */
  pxhr:function(needle){
    var _orig=XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(m,url){
      if(url&&url.toString().indexOf(needle)!==-1){this.__blocked=true;return;}
      return _orig.apply(this,arguments);
    };
    var _send=XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send=function(){
      if(this.__blocked)return;
      return _send.apply(this,arguments);
    };
  },

  /* prevent-fetch */
  pfetch:function(needle){
    if(!window.fetch)return;
    var _orig=window.fetch;
    window.fetch=function(input,init){
      var url=typeof input==='string'?input:(input&&input.url?input.url:'');
      if(url.indexOf(needle)!==-1)return Promise.resolve(new Response('',{status:200}));
      return _orig.apply(this,arguments);
    };
  },

  /* remove-class: удаляет className с элементов matching selector */
  rc:function(className,selector,apply){
    selector=selector||'*';
    function _remove(){
      document.querySelectorAll(selector).forEach(function(el){
        el.classList.remove(className);
      });
    }
    if(document.readyState!=='loading')_remove();
    else document.addEventListener('DOMContentLoaded',_remove);
    if(apply==='stay'){new MutationObserver(_remove).observe(document,{subtree:true,childList:true,attributes:true});}
  }
};
"""

    // ── Rules ─────────────────────────────────────────────────────────────────

    data class ScriptletRule(
        val domains: List<String>,  // пусто = все сайты
        val scriptlet: String,
        val args: List<String>
    )

    private val RULES: List<ScriptletRule> = listOf(

        // ── Глобальные (все сайты) ────────────────────────────────────────────

        // Отключаем детекторы adblock
        ScriptletRule(emptyList(), "aopr", listOf("blockAdBlock")),
        ScriptletRule(emptyList(), "aopr", listOf("FuckAdBlock")),
        ScriptletRule(emptyList(), "aopr", listOf("adsBlocked")),
        ScriptletRule(emptyList(), "sc",   listOf("canRunAds", "true")),
        ScriptletRule(emptyList(), "sc",   listOf("adblockDetected", "false")),
        ScriptletRule(emptyList(), "sc",   listOf("adBlockDetected", "false")),
        ScriptletRule(emptyList(), "sc",   listOf("adblockEnabled", "false")),

        // Отключаем Google Analytics tracking
        ScriptletRule(emptyList(), "sc",   listOf("ga", "noopFunc")),
        ScriptletRule(emptyList(), "sc",   listOf("gtag", "noopFunc")),
        ScriptletRule(emptyList(), "sc",   listOf("dataLayer.push", "noopFunc")),

        // JSON prune для рекламных ключей
        ScriptletRule(emptyList(), "jp",   listOf("adPlacements playerAds adSlots")),

        // ── YouTube ───────────────────────────────────────────────────────────
        ScriptletRule(listOf("youtube.com"), "jp",
            listOf("adPlacements playerAds adSlots adBreakHeartbeatParams auxiliaryUi")),
        ScriptletRule(listOf("youtube.com"), "pxhr",  listOf("doubleclick")),
        ScriptletRule(listOf("youtube.com"), "pfetch", listOf("googlesyndication")),

        // ── Forbes ────────────────────────────────────────────────────────────
        ScriptletRule(listOf("forbes.com"), "sc",    listOf("googletag.cmd.push", "noopFunc")),
        ScriptletRule(listOf("forbes.com"), "aopr",  listOf("adBlocker")),
        ScriptletRule(listOf("forbes.com"), "pst",   listOf("adblock", "")),

        // ── Twitch ────────────────────────────────────────────────────────────
        ScriptletRule(listOf("twitch.tv"), "pxhr",   listOf("usher.twitchapps.com")),
        ScriptletRule(listOf("twitch.tv"), "pxhr",   listOf("doubleclick.net")),

        // ── Reddit ────────────────────────────────────────────────────────────
        ScriptletRule(listOf("reddit.com"), "sc",    listOf("adblock", "false")),
        ScriptletRule(listOf("reddit.com"), "sc",    listOf("adBlocker", "false")),

        // ── Wired / Condé Nast ────────────────────────────────────────────────
        ScriptletRule(listOf("wired.com", "vanityfair.com", "newyorker.com"),
            "aopr", listOf("adblock")),
        ScriptletRule(listOf("wired.com"), "rc",
            listOf("is-paywall", "html", "stay")),

        // ── Mail.ru / VK ──────────────────────────────────────────────────────
        ScriptletRule(listOf("mail.ru", "ok.ru", "vk.com"),
            "pxhr", listOf("top.mail.ru")),
        ScriptletRule(listOf("mail.ru", "ok.ru", "vk.com"),
            "sc",   listOf("adsbygoogle.loaded", "true")),

        // ── Yandex ────────────────────────────────────────────────────────────
        ScriptletRule(listOf("yandex.ru", "yandex.com"),
            "pxhr", listOf("an.yandex.ru")),

        // ── Generic anti-adblock bypass ───────────────────────────────────────
        ScriptletRule(emptyList(), "pst",  listOf("adblock", "")),
        ScriptletRule(emptyList(), "pst",  listOf("ads.js", "")),
        ScriptletRule(emptyList(), "psi",  listOf("adblock", "")),

        // Отключаем попапы anti-adblock
        ScriptletRule(emptyList(), "aopr", listOf("AntiAdBlocker")),
        ScriptletRule(emptyList(), "aopr", listOf("adblock_popup")),
        ScriptletRule(emptyList(), "sc",   listOf("adblock_popup_shown", "true")),
        ScriptletRule(emptyList(), "sc",   listOf("adblockNoticeShown", "true")),
        ScriptletRule(emptyList(), "sc",   listOf("localStorage.adblock_notice", "1"))
    )

    private fun buildScriptletCall(rule: ScriptletRule): String {
        val args = rule.args.joinToString(",") { "'${it.replace("'", "\\'")}'" }
        return "_slib.${rule.scriptlet}($args);"
    }
}
