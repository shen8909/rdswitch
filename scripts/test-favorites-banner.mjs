// 「最愛檔損毀」橫幅與星號停用的前端測試（不引入任何相依）。
//
//   node --test scripts/test-favorites-banner.mjs
//
// 作法同 check-i18n.mjs：用 node:vm 在隔離環境執行 src/i18n.js 與 src/app.js，
// 以最小的假 DOM 與假的 window.__TAURI__ 驅動，檢查渲染結果。
// 這不是真實瀏覽器：版面、顏色對比、焦點行為不在驗證範圍內。

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel) => readFileSync(join(root, rel), "utf8");

class FakeEl {
  constructor() {
    this.hidden = false;
    this.textContent = "";
    this.innerHTML = "";
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.dataset = {};
    this.style = {};
    this.classList = { add() {}, remove() {} };
  }
  addEventListener() {}
  setAttribute() {}
  removeAttribute() {}
  querySelector() {
    return new FakeEl();
  }
}

/** 載入前端並等第一次 get_state 渲染完成，回傳假 DOM 元素表。 */
async function boot(stateFromBackend) {
  const els = new Map();
  const getEl = (id) => {
    if (!els.has(id)) els.set(id, new FakeEl());
    return els.get(id);
  };
  const calls = [];
  const ctx = {
    navigator: { language: "zh-TW" },
    document: {
      documentElement: {},
      getElementById: getEl,
      querySelectorAll: () => [],
      addEventListener() {},
      visibilityState: "hidden",
    },
    setInterval: () => 0,
    setTimeout,
    clearTimeout,
    Date,
    Set,
    Map,
    String,
  };
  ctx.window = ctx;
  ctx.addEventListener = () => {};
  ctx.__TAURI__ = {
    core: {
      invoke: async (cmd, args) => {
        calls.push([cmd, args]);
        if (cmd === "get_state") return stateFromBackend;
        if (cmd === "check_servers") return [];
        return undefined;
      },
    },
    event: { listen: () => {} },
  };
  vm.createContext(ctx);
  vm.runInContext(read("src/i18n.js"), ctx);
  vm.runInContext(read("src/app.js"), ctx);
  for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
  return { getEl, calls };
}

const baseState = (over) => ({
  platform: "windows",
  elevated: true,
  needs_admin: false,
  service_unsupported: false,
  autostart: false,
  lang: "zh-TW",
  lang_setting: "auto",
  version: "0.0.0",
  update: null,
  current: "",
  profiles: [
    { name: "Default", server: "", relay: "", api: "", key: "", builtin: true, favorite: false },
    { name: "a", server: "a.example:21116", relay: "", api: "", key: "", builtin: false, favorite: false },
  ],
  favorites_error: null,
  ...over,
});

test("最愛正常：不顯示橫幅，星號可按", async () => {
  const { getEl } = await boot(baseState());
  assert.equal(getEl("fav-warn").hidden, true);
  assert.equal(getEl("fav-warn-err").textContent, "");
  const html = getEl("groups").innerHTML;
  assert.ok(html.includes('class="star"'));
  assert.ok(!html.includes("disabled"));
});

test("最愛損毀：顯示橫幅與錯誤訊息，所有星號停用並說明原因", async () => {
  const { getEl } = await boot(baseState({ favorites_error: "favorites.json 格式錯誤：x" }));
  assert.equal(getEl("fav-warn").hidden, false);
  assert.equal(getEl("fav-warn-err").textContent, "favorites.json 格式錯誤：x");
  const html = getEl("groups").innerHTML;
  const stars = html.match(/<button class="star"[^>]*>/g) ?? [];
  assert.equal(stars.length, 2, "兩個 profile 都要有星號");
  for (const s of stars) {
    assert.ok(s.includes(" disabled"), `星號未停用：${s}`);
    assert.ok(s.includes("我的最愛暫時無法使用"), `缺少停用說明：${s}`);
  }
  // 切換與更多選單不受影響
  assert.ok(html.includes('data-act="use"'));
  assert.ok(html.includes('data-act="more"'));
});

test("後端錯誤訊息只以 textContent 輸出，不會變成 HTML", async () => {
  const evil = '<img src=x onerror="alert(1)">';
  const { getEl } = await boot(baseState({ favorites_error: evil }));
  assert.equal(getEl("fav-warn-err").textContent, evil);
  assert.ok(!getEl("fav-warn-err").innerHTML.includes("<img"));
  assert.ok(!getEl("groups").innerHTML.includes("<img"));
  assert.ok(!getEl("cur-info").innerHTML.includes("<img"));
});
