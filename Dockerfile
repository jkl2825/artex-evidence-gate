# syntax=docker/dockerfile:1
#
# 多阶段构建：前端静态导出 → Go 单二进制（内嵌前端）→ 运行镜像。
# 原 Docker Hub 镜像源（autumn27/artex）已失效，本仓库自此支持从纯源码自助构建：
#   docker compose build        # 或 docker build -t artex:local .
# TARGETARCH 由 buildx 自动注入（amd64/arm64），Go 交叉编译无需 QEMU；
# 运行层只装工具，编译全部在构建阶段完成。
# 国内网络可覆盖模块源（默认已对国内友好）：
#   --build-arg GOPROXY=https://goproxy.cn,direct
#   --build-arg NPM_REGISTRY=https://registry.npmmirror.com
# Release 使用 --build-arg ARTEX_BINARY_SOURCE=prebuilt，复用校验过的发布二进制；
# 默认仍从源码构建，无需下载任何预编译的 ARTEX 产物。
ARG ARTEX_BINARY_SOURCE=source

########## 阶段 1：前端静态导出 ##########
FROM --platform=$BUILDPLATFORM node:22-bookworm AS web
ARG NPM_REGISTRY=https://registry.npmmirror.com
WORKDIR /web
# --ignore-scripts：跳过 prepare(husky)——容器里没有 .git，husky 会失败；
# Next.js/Biome 的平台二进制走 optionalDependencies，不依赖生命周期脚本。
COPY web/package.json web/package-lock.json ./
RUN npm config set registry "$NPM_REGISTRY" && npm ci --ignore-scripts
COPY web/ ./
RUN NEXT_EXPORT=1 npm run build:static

########## 阶段 2：Go 后端（内嵌前端，静态编译）##########
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS gobuild
ARG TARGETOS
ARG TARGETARCH
ARG ARTEX_BUILD_VERSION=dev
ARG GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct
WORKDIR /src
COPY go.mod go.sum ./
# 本仓库通过 replace 使用本地 norma；下载依赖前必须先提供它的模块声明。
COPY norma/go.mod norma/go.sum ./norma/
RUN go mod download
COPY . .
# 前端静态产物从 web 阶段拷入（.dockerignore 已排除宿主 dist，不会冲突）
COPY --from=web /web/out/ server/webui/dist/
RUN version="${ARTEX_BUILD_VERSION#v}" \
    && CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build \
       -tags embedui -trimpath -ldflags "-s -w -X main.version=${version}" \
       -o /out/artex ./cmd/artex

FROM scratch AS source
COPY --from=gobuild /out/artex /out/artex

########## Release 可选输入：不重新编译已验证的二进制 ##########
FROM scratch AS prebuilt
ARG TARGETARCH
COPY dist/${TARGETARCH}/artex /out/artex

FROM ${ARTEX_BINARY_SOURCE} AS binary

########## 阶段 3：运行镜像（同原版：工具 + Playwright 预装）##########
FROM python:3.12-slim-bookworm AS runtime
ARG NPM_REGISTRY=https://registry.npmmirror.com
# 与下方 MCP/CLI 的精确依赖对齐，避免工具寻找另一版未安装的 Chromium。
ARG PLAYWRIGHT_VERSION=1.64.0-alpha-1790635538000
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
ARG PLAYWRIGHT_CLI_VERSION=0.1.22
ARG PLAYWRIGHT_DOWNLOAD_HOST
# npm 源可覆盖；浏览器默认使用官方 CDN，也可通过 build arg 指定镜像站。
ENV npm_config_registry=$NPM_REGISTRY \
    PLAYWRIGHT_DOWNLOAD_HOST=$PLAYWRIGHT_DOWNLOAD_HOST
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 与前端构建统一使用 22.x，避免继续使用已结束维护的 20.x。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" \
      "@playwright/cli@${PLAYWRIGHT_CLI_VERSION}" "playwright@${PLAYWRIGHT_VERSION}" \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && node -e 'const fs = require("node:fs"), cp = require("node:child_process"); const root = cp.execFileSync("npm", ["root", "-g"], {encoding:"utf8"}).trim(); fs.symlinkSync(require(root + "/playwright").chromium.executablePath(), "/usr/local/bin/artex-chromium");' \
    && rm -rf /var/lib/apt/lists/*
# MCP/CLI 默认使用容器已安装的 Chromium，无需 Chrome、显示服务器或运行时下载。
# 容器以 root 运行，Chromium 的进程沙箱不可用；可在自定义非 root 部署中覆盖。
ENV PLAYWRIGHT_MCP_EXECUTABLE_PATH=/usr/local/bin/artex-chromium \
    PLAYWRIGHT_MCP_HEADLESS=true \
    PLAYWRIGHT_MCP_SANDBOX=false
WORKDIR /app
# 内置 browser MCP 使用 npx @playwright/mcp。npm exec 不保证解析全局包；
# 将预装依赖暴露到应用的本地依赖路径，子工作目录也可离线启动同一版本。
RUN ln -s "$(npm root -g)" /app/node_modules \
    && npx --offline --no-install @playwright/mcp --help > /dev/null

# ↓↓↓ 以下为本地追加：工具链固化层（源自旧部署的 Dockerfile.artex-toolchain）
#     目的：把 89 个工具固化进镜像层，容器重建不再丢（2026-10-15 实际丢过一次）
#     基底与上游一致（python:3.12-slim-bookworm），故整段可直接复用
# ============================================================================
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/toolchain/bin:${PATH}"

# ★ 本地补丁 2：换国内 Debian 源 + 开启重试
#   原因：本机构建时 deb.debian.org 下载 .deb 会间歇性 Unable to connect（大文件抖动），
#         导致 apt 批 exit 100。官方源与阿里云实测均可达，故切阿里云并加重试提高容错。
RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i 's|http://deb.debian.org/debian-security|https://mirrors.aliyun.com/debian-security|g; \
              s|http://deb.debian.org/debian|https://mirrors.aliyun.com/debian|g' \
          /etc/apt/sources.list.d/debian.sources; \
      echo "--- 换源后 debian.sources ---"; cat /etc/apt/sources.list.d/debian.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
      sed -i 's|http://deb.debian.org/debian|https://mirrors.aliyun.com/debian|g' /etc/apt/sources.list || true; \
    fi; \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' \
      > /etc/apt/apt.conf.d/99local-retries

# ① apt 批：探测式安装（Debian 12 源里缺一个包会让整条 apt exit 100）
RUN apt-get -o Acquire::Retries=5 update && PKGS=""; \
    for p in \
        ca-certificates curl wget git jq unzip xz-utils \
        bc xxd file procps zip xxhash \
        default-jre-headless ruby-full \
        sqlmap whatweb sslscan dirb gobuster \
        hydra john hashcat medusa ncrack \
        masscan tcpdump tshark zmap \
        bind9-dnsutils dnsenum dnsrecon fierce \
        ldap-utils nbtscan onesixtyone snmp \
        binwalk gdb aircrack-ng bettercap \
    ; do \
      if apt-cache show "$p" >/dev/null 2>&1; then PKGS="$PKGS $p"; \
      else echo "[skip] $p 不在当前源里"; fi; \
    done; \
    echo "将安装:$PKGS"; \
    apt-get install -y --no-install-recommends --fix-missing $PKGS \
    && rm -rf /var/lib/apt/lists/*

# ② pip 批（web 侦察 / TLS / 代理 / pwn）—— 逐个装，任一失败不拖垮其余
RUN for p in wafw00f dirsearch arjun sslyze mitmproxy pwntools ropgadget; do \
      pip3 install --no-cache-dir --break-system-packages -i https://pypi.tuna.tsinghua.edu.cn/simple "$p" || echo "[skip] $p 装不上"; \
    done

# ③ pip 批（域渗透 / fuzz / 云审计）
RUN for p in impacket wfuzz selenium scoutsuite checkov; do \
      pip3 install --no-cache-dir --break-system-packages -i https://pypi.tuna.tsinghua.edu.cn/simple "$p" || echo "[skip] $p 装不上"; \
    done

# ④ Go 系静态二进制：COPY 进镜像（不用 bind mount —— /etc/profile 会覆盖 PATH）
# ★ 2026-10-17：工具链改用【独立构建上下文】引入（不再放在主 context 里），
#   这样 gobuild 阶段的 `COPY . .` 不会把 500MB 工具链拷进编译阶段。
#   对应构建参数：--build-context toolchain-bin=<assets>/toolchain
COPY --from=toolchain-bin bin/ /opt/toolchain/bin/
RUN chmod +x /opt/toolchain/bin/* 2>/dev/null || true

# ⑤ 修 login shell 的 PATH（/etc/profile 会硬编码覆盖，靠 profile.d 追加）
RUN printf 'export PATH="/opt/toolchain/bin:$PATH"\n' > /etc/profile.d/00-toolchain.sh \
    && chmod +x /etc/profile.d/00-toolchain.sh

# ⑥ 补充批：Web / 云 / 内网工具（从本机快照 COPY 解包，不依赖 GitHub 可达性）
# 同上：--build-context toolchain-extra=<assets>/toolchain-extra
COPY --from=toolchain-extra ./ /opt/toolchain-extra/

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bsdextrautils; \
    rm -rf /var/lib/apt/lists/*; \
    tar xzf /opt/toolchain-extra/app-tools.tar.gz -C /app; \
    tar xzf /opt/toolchain-extra/bin-extra.tar.gz -C /usr/local/bin; \
    chmod +x /usr/local/bin/xsstrike /usr/local/bin/testssl.sh || true; \
    grep -v '@ git+' /opt/toolchain-extra/pip-extra.txt > /tmp/piplist.txt || true; \
    while read -r p; do if [ -n "$p" ]; then python3 -m pip install --break-system-packages -q -i https://pypi.tuna.tsinghua.edu.cn/simple "$p" || echo "[skip] $p"; fi; done < /tmp/piplist.txt; \
    cp -f /opt/toolchain-extra/wfuzz-patch/loader.py /usr/local/lib/python3.12/site-packages/wfuzz/externals/moduleman/loader.py || true; \
    cp -f /opt/toolchain-extra/wfuzz-patch/registrant.py /usr/local/lib/python3.12/site-packages/wfuzz/externals/moduleman/registrant.py || true; \
    for t in naabu dalfox feroxbuster amass shuffledns trivy nikto dirsearch commix graphql-cop wapiti prowler kube-hunter pacu arjun testssl.sh checkov xsstrike wfuzz rustscan; do \
        command -v "$t" >/dev/null 2>&1 && echo "[ok] $t" || echo "[MISS] $t"; \
    done

# ⑦ 自检：装上了什么写进构建日志
RUN set -e; echo "=== 工具链自检 ==="; \
    for t in sqlmap whatweb sslscan dirb gobuster hydra john hashcat medusa ncrack \
             masscan nmap tcpdump tshark zmap dig dnsenum dnsrecon fierce \
             ldapsearch nbtscan onesixtyone snmpget binwalk gdb aircrack-ng bettercap \
             java ruby jq curl wget unzip wafw00f dirsearch sslyze mitmdump \
             nuclei subfinder httpx dnsx katana ffuf gau waybackurls websocat cloudflared; do \
      command -v "$t" >/dev/null 2>&1 && printf "  [ok]   %-14s\n" "$t" || printf "  [MISS] %-14s\n" "$t"; \
    done; \
    echo "=== login shell PATH 自检 ==="; \
    bash -lc 'for t in nuclei subfinder ffuf nmap sqlmap; do printf "  [%-4s] %s\n" "$(command -v $t >/dev/null 2>&1 && echo ok || echo MISS)" "$t"; done'

# 构建阶段产出的单二进制（内嵌前端）


# 构建阶段产出的单二进制（内嵌前端）
COPY --from=binary /out/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
