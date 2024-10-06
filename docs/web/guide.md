# Web

> 0xGame 2024 Web 入门 & 环境配置: [https://www.bilibili.com/video/BV1fz1BYfEpK/](https://www.bilibili.com/video/BV1fz1BYfEpK/)

## 什么是 Web 安全

通俗一点来讲, 就是如何黑掉 (入侵) Web 网站, 以及如何保护 Web 网站不被黑掉 (入侵)

## 知识点

Web 安全的知识点涉及到各种漏洞, 这些漏洞可能会泄露目标网站的敏感信息 (管理员账号密码, 服务器敏感文件), 甚至获取 Web 服务器的控制权限 (俗称 RCE 或 Getshell)

- HTTP 协议
- SQL 注入 (MySQL, PostgreSQL, SQLite, Oracle, SQL Server, MongoDB)
- 文件上传, 文件读取, 文件包含
- XSS, CSRF, XSLeaks, CSP 绕过, CSS 注入
- XXE, SSRF, SSTI, 命令注入, 反序列化
- PHP/Node.js/Go/Java 语言特性

学习资源

- [https://websec.readthedocs.io/](https://websec.readthedocs.io/)

- [https://github.com/JnuSimba/MiscSecNotes](https://github.com/JnuSimba/MiscSecNotes)

- [https://github.com/CHYbeta/Web-Security-Learning](https://github.com/CHYbeta/Web-Security-Learning)

- [https://wiki.wgpsec.org/knowledge/](https://wiki.wgpsec.org/knowledge/)

- [https://hello-ctf.com/HC_Web/](https://hello-ctf.com/HC_Web/)

初期需要对各个漏洞有一个基本的理解, 知道他们是干什么的? 有什么危害? 如何检测? 如何利用?

(可以边做 CTF 题边学)

## 如何做题

两大方向: 黑盒测试 & 白盒测试

- 黑盒测试: 仅仅给出 Web 网站的 URL, 通过猜测、扫描等信息收集手段, 尝试利用各种可能存在的安全漏洞

- 白盒测试: 给出 Web 网站的 URL 和源码, 通过对源码进行代码审计, 找出可能存在的安全漏洞, 并尝试在远程服务器上利用

**黑盒测试重在信息收集 (robots.txt, HTTP 头, 弱口令, 敏感目录, 备份文件), 而白盒测试重在对程序代码的理解**

在做题时可以结合题目的名称、描述、源码, 利用 Google 搜索并学习对应知识点, 参考类似的题目

适当的借助 AI, 例如 [ChatGPT](https://chat.openai.com/)