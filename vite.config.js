import { defineConfig } from "vite";

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function singleFileBundle() {
  return {
    name: "single-file-bundle",
    apply: "build",
    enforce: "post",
    generateBundle(_options, bundle) {
      const htmlEntry = Object.values(bundle).find(item => item.type === "asset" && item.fileName.endsWith(".html"));
      if (!htmlEntry) return;

      let html = String(htmlEntry.source);
      for (const [fileName, item] of Object.entries(bundle)) {
        if (item === htmlEntry) continue;
        const relativeName = `./${fileName}`;
        const escapedFile = escapeRegExp(fileName);
        const escapedRelative = escapeRegExp(relativeName);

        if (item.type === "chunk" && fileName.endsWith(".js")) {
          // Inline script text must not contain a literal </script>, even inside
          // JS strings or regexps, otherwise browsers terminate the script tag
          // early and render the remaining bundle as page text.
          const safeCode = item.code.replace(/<\/script/gi, "<\\/script");
          const script = `<script type="module">\n${safeCode}\n</script>`;
          html = html.replace(new RegExp(`<script([^>]*)src=["'](?:${escapedFile}|${escapedRelative})["']([^>]*)></script>`, "g"), () => script);
          delete bundle[fileName];
        } else if (item.type === "asset" && fileName.endsWith(".css")) {
          const safeCss = String(item.source).replace(/<\/style/gi, "<\\/style");
          const style = `<style>\n${safeCss}\n</style>`;
          html = html.replace(new RegExp(`<link([^>]*)href=["'](?:${escapedFile}|${escapedRelative})["']([^>]*)>`, "g"), () => style);
          delete bundle[fileName];
        } else if (item.type === "asset") {
          // This app should not emit extra static assets. Drop unreferenced leftovers
          // so dist/ contains only index.html.
          delete bundle[fileName];
        }
      }
      htmlEntry.source = html;
    },
  };
}

export default defineConfig({
  base: "./",
  build: {
    cssCodeSplit: false,
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
  },
  plugins: [singleFileBundle()],
});
