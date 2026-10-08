// Applies the saved theme before first paint. A separate file (not inline)
// so the Content-Security-Policy can stay script-src 'self'.
(function () {
  var t;
  try { t = localStorage.getItem('v2ray-theme'); } catch (e) {}
  if (t !== 'light' && t !== 'dark') t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  document.documentElement.dataset.theme = t;
})();
