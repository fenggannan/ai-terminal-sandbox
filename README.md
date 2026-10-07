# AI Terminal（安全沙箱版）

一个带 AST 安全沙箱的本地 AI 编程终端。接入智谱 GLM（兼容 OpenAI SDK），让 AI 在对话中写代码，自动在本地沙箱里执行并返回结果。

## 特性

- **AI 聊天**：流式输出，支持深度思考过程显示
- **代码自动执行**：AI 输出 ```python 代码块后自动在本地运行
- **AST 安全沙箱**：
  - 模块白名单（只允许 math/random/turtle 等纯计算模块）
  - 禁止 eval/exec/open/compile/getattr/setattr/globals/locals 等危险函数
  - 禁止双下划线属性访问（`__class__`、`__bases__` 等）
  - 常量折叠检测：拦截 `"__im"+"port__"`、f-string 拼接绕过
  - 禁止星号导入
- **turtle 绘图支持**：自动接管窗口关闭逻辑
- **input() 交互**：支持需要用户输入的小程序
- **资源限制**：普通程序 10 秒超时，绘图 5 分钟超时，输出截断 5000 字符
- **配置持久化**：API key、模型选择自动保存到本地

## 快速开始

```bash
pip install openai
python ai_terminal.py
```

首次运行后，输入你的智谱 GLM API key：

```
你：设置GLM key：你的API key
```

然后正常对话即可。

## 指令

| 指令 | 作用 |
|---|---|
| `clear` | 清空聊天记忆 |
| `开启深度思考模式` | 显示 AI 思考过程 |
| `关闭深度思考模式` | 隐藏思考过程 |
| `切换模型：模型名` | 切换模型 |
| `设置GLM key：xxx` | 配置 API key |
| `设置GLM接口：xxx` | 配置自定义接口地址 |
| `保存代码` | 把上一次 AI 写的代码存成 .py 文件 |
| `"""` | 进入多行输入模式 |
| `exit` | 退出 |

## 安全说明

本程序不是隔离虚拟机，只是 AST 层面的白名单检查。适合个人学习使用，不要在不可信环境运行 AI 生成的代码。

## License

MIT
