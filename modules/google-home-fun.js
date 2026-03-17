(function () {
  var body = ($response && $response.body) || "";
  if (!body) {
    $done({});
    return;
  }

  var args = {};
  try {
    args = JSON.parse($argument || "{}");
  } catch (e) {}

  var message = args.message || "今天也要快乐摸鱼";
  var badge = "<div id='gomitm-fun-banner' style='position:fixed;z-index:999999;top:16px;left:50%;transform:translateX(-50%);background:#ffde59;color:#111;padding:10px 16px;border-radius:999px;font:700 14px/1.2 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.2)'>🛜 " + message + " · via gomitm</div>";

  if (body.indexOf("gomitm-fun-banner") === -1) {
    body = body.replace(/<body([^>]*)>/i, "<body$1>" + badge);
    body = body.replace(/<title>(.*?)<\/title>/i, "<title>$1 · 已被 gomitm 俏皮改造</title>");
  }

  $done({ body: body });
})();
