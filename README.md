# ✍️ 手搓笔记本

一个零依赖、单文件的个人记录本：每日待办 / 习惯打卡、周计划、目标追踪（里程碑 + 进度条）、看板式笔记板。

- **在线版（推荐）**：https://shousuo-notebook.pages.dev — 注册账号登录后数据云端自动同步，iPhone 可"添加到主屏幕"当 App 用
- **本地使用**：下载 `index.html`，浏览器双击打开即可，数据存在浏览器 localStorage
- **多端同步**：① 登录账号自动云同步（Cloudflare Pages Functions + D1）；② 或导出 JSON 放 iCloud Drive，Mac 上用 Chrome/Edge 绑定该文件自动读写

技术：前端零依赖单文件；后端 `functions/api/[[path]].js`（会话 token + PBKDF2 密码加密）；数据库结构见 `schema.sql`；部署配置见 `wrangler.toml`。

> 仓库里只有应用代码，不含任何个人数据；你的记录始终只在你自己的浏览器和 iCloud Drive 里。
