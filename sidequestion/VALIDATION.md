# `/btw` 测试指南

旁路提问的验证重点是上下文隔离、预算、并发、恢复和界面行为。测试使用可丢弃的 PostgreSQL 数据库与受控模型夹具；数据库用例需设置 `ARTEX_PG_DSN`，不得指向生产库。

## 工程检查

| 范围 | 代表用例 |
| --- | --- |
| 结构化消息深拷贝与完整快照边界 | `TestCheckpointDeepCopyAndBoundaries` |
| 排除半段回复并保留实际模型池成员 | `TestSnapshotExcludesPartialStreamAndSelectsPoolMember` |
| 工具配对、回放裁剪与输入预算 | `TestBuildRequestCompactionToolPairingAndBudget` |
| 主旁路并行与双向取消隔离 | `TestMainSideConcurrencyAndIndependentCancellation` |
| 无工具执行及失败时的用量保存 | `TestServiceNoToolsAndUsageOnFailure` |
| 20 组边界、重启与摘要恢复 | `TestSideTwentyExchangeBoundaryAndRestart` |
| 按内容估算预算及长上下文分块 | `TestSideBudgetCountsContentNotJSONCharacters`、`TestSideLongExchangeAndSnapshotCompactionAreBounded` |
| 单次溢出恢复、失败用量和无缩减时停止 | `TestSideOverflowRecoveryOnceAndFailureUsage`、`TestSideOverflowWithoutReductionDoesNotRepeatAnswer` |
| 摘要取消、失败、调用上限与小窗口 | `TestSideSummaryCancellationAndFailureDoNotAdvanceMemory`、`TestSideSummaryCallCapAndStaticBudget`、`TestSideTwentyLongRepliesRespectSmallWindow` |
| 历史分页、幂等、重启与迟到写入 | 数据库旁路测试 |
| 认证、父资源归属、全局并发和 SSE | 服务接口旁路测试 |
| 任务归档、恢复与旧格式兼容 | `TestSideTaskArchiveVersions` |

核心回归：

```sh
go test -race ./sidequestion -count=1
```

配置独立测试库后，运行相关包的隔离与归档用例：

```sh
go test -race ./agent ./db ./server ./sidequestion ./llmrec ./llmpool \
  -run 'Test(Side|Checkpoint|Snapshot|BuildRequest|Service|MainSide|CaptureRun|TaskArchive|CompleteForwards|StopIntent|CancelIntent)' -count=1
```

前端检查在 `web` 目录执行：

```sh
npx tsc --noEmit
npx biome check src/lib/side-questions.ts src/hooks/use-side-questions.ts src/components/side-question-workspace.tsx
npm run build
```

## 界面检查

在桌面和窄屏布局分别检查：

- 主会话运行时提交 `/btw`，主内容继续更新，旁路独立显示。
- 连续追问与停止；停止旁路不取消主任务，已有回答保留。
- 关闭面板、刷新及 SSE 重连后恢复历史和当前状态。
- 普通聊天、任务 MainAgent 与不同 Worker 的历史互相隔离。
- 清空确认后只删除旁路历史，保留主快照，并阻止迟到结果恢复已清理数据。
- 长问题、长回答、摘要阶段与失败后草稿恢复正常，无横向溢出。

## 外部模型兼容性

需要验证外部 Provider 时，使用专用测试配置和合成上下文，检查流式、非流式、取消和 usage 返回。端点未返回 usage 时，记录的零用量不能解释为没有计费。答案质量检查不能替代并发、工具隔离和持久化断言。

本指南描述复现方法，不代表全量测试已经通过。既有清理时序、图范围及 norma 用例失败应按实际运行结果记录，不能以旁路定向测试通过代替全量验收。
