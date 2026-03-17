(function () {
  var body = ($response && $response.body) || "";
  if (!body) {
    $done({});
    return;
  }

  var arg = {};
  try {
    arg = JSON.parse($argument || "{}");
  } catch (e) {}

  function isArray(v) {
    return Object.prototype.toString.call(v) === "[object Array]";
  }

  function isObject(v) {
    return v !== null && typeof v === "object" && !isArray(v);
  }

  function shouldDropByKey(key) {
    var k = String(key || "").toLowerCase();
    if (!k) {
      return false;
    }
    if (k === "adplacements" || k === "playerads" || k === "adbreakheartbeatparams") {
      return true;
    }
    if (k.indexOf("adslot") >= 0) {
      return true;
    }
    if (k.indexOf("promoted") >= 0) {
      return true;
    }
    return false;
  }

  function itemLooksLikeAd(item) {
    if (!isObject(item)) {
      return false;
    }
    for (var k in item) {
      if (!Object.prototype.hasOwnProperty.call(item, k)) {
        continue;
      }
      var lower = String(k).toLowerCase();
      if (lower.indexOf("ad") >= 0 || lower.indexOf("promoted") >= 0) {
        return true;
      }
    }
    return false;
  }

  function scrubAny(node) {
    if (isArray(node)) {
      for (var i = node.length - 1; i >= 0; i--) {
        if (itemLooksLikeAd(node[i])) {
          node.splice(i, 1);
          continue;
        }
        scrubAny(node[i]);
      }
      return;
    }

    if (!isObject(node)) {
      return;
    }

    var keys = [];
    for (var k in node) {
      if (Object.prototype.hasOwnProperty.call(node, k)) {
        keys.push(k);
      }
    }

    for (var j = 0; j < keys.length; j++) {
      var key = keys[j];
      if (shouldDropByKey(key)) {
        delete node[key];
        continue;
      }
      scrubAny(node[key]);
    }
  }

  function patchWatchHTML(input, styleCleanup) {
    var injected = "";
    if (styleCleanup) {
      injected += "<style id='gomitm-youtube-lite-style'>.ytp-ad-module,.ytp-ad-overlay-container,.video-ads,ytd-display-ad-renderer,ytd-ad-slot-renderer,ytd-promoted-sparkles-web-renderer,ytm-promoted-sparkles-web-renderer{display:none !important;visibility:hidden !important;}</style>";
    }
    injected += "<script id='gomitm-youtube-lite-js'>(function(){try{if(window.ytInitialPlayerResponse){delete window.ytInitialPlayerResponse.adPlacements;delete window.ytInitialPlayerResponse.playerAds;delete window.ytInitialPlayerResponse.adBreakHeartbeatParams;}var kill=function(){var sel=['.ytp-ad-module','.ytp-ad-overlay-container','.video-ads','ytd-display-ad-renderer','ytd-ad-slot-renderer','ytd-promoted-sparkles-web-renderer'];for(var i=0;i<sel.length;i++){var nodes=document.querySelectorAll(sel[i]);for(var j=0;j<nodes.length;j++){nodes[j].remove();}}};kill();setInterval(kill,1200);}catch(e){}})();</script>";

    if (input.indexOf("gomitm-youtube-lite-style") >= 0 || input.indexOf("gomitm-youtube-lite-js") >= 0) {
      return input;
    }

    var out = input;
    if (/<\/head>/i.test(out)) {
      out = out.replace(/<\/head>/i, injected + "</head>");
    } else {
      out = injected + out;
    }
    out = out.replace(/<title>(.*?)<\/title>/i, "<title>$1 · Lite</title>");
    return out;
  }

  var mode = String(arg.mode || "").toLowerCase();
  if (mode === "watch") {
    $done({ body: patchWatchHTML(body, arg.styleCleanup !== false) });
    return;
  }

  try {
    var obj = JSON.parse(body);
    scrubAny(obj);
    $done({ body: JSON.stringify(obj) });
  } catch (e) {
    $done({});
  }
})();
