# 从 0 到 1

## 学习建议

- 新手刚开始学习某一个方面的内容 (例如编程语言, Linux, Docker) 时, **不需要一股脑从头学到尾**, 初期先有个基本的知识即可
- 入门阶段最重要的是快速上手实践, 对于 CTF 来说就是边学边练, 一边结合网上的文章/视频学习, 一边自己动手在本地环境/刷题平台上结合具体题目进行实践
- 在学习时选择一个合适的搜索引擎能够节省很多时间, **优先使用 Google**, 如果没有网络条件, 则可以使用 Bing, **永远都不要使用百度**
- 可以参考网上的教程使用 GitHub Pages + Hexo/Hugo 搭建一个静态博客, 日常记录自己的 Writeup (刷题记录) 和笔记

## 计算机基础知识

面向完全零基础同学的计算机基础课程

- Crash Course Computer Science: [https://www.bilibili.com/video/BV1EW411u7th/](https://www.bilibili.com/video/BV1EW411u7th/)

## 浏览器插件

- 沉浸式翻译: [https://immersivetranslate.com/](https://immersivetranslate.com/)

## Google 语法

Google 语法是一种利用搜索引擎精确查询数据的的语法,虽然名字里带 Google, 但实际上对于其它搜索引擎 (例如 Bing) 也是适用的

熟练掌握 Google 语法能够使我们快速准确的找到我们想要的内容

- [https://segmentfault.com/a/1190000038432191](https://segmentfault.com/a/1190000038432191)

```bash
# 搜索 xz.aliyun.com 网站下关于 SQL 注入的内容
site:xz.aliyun.com SQL 注入

# 搜索 XSS, 但是排除 CSDN 相关的结果
XSS -csdn
```

## Markdown 语法

Markdown 是一种轻量级的标记语言, 它允许人们使用易读易写的纯文本格式编写文档

与 Microsoft Office 或 WPS 相比, Markdown 非常容易上手, 在格式和排版上面几乎不用花费精力

- [https://markdown.com.cn/](https://markdown.com.cn/)
- [https://www.runoob.com/markdown/md-tutorial.html](https://www.runoob.com/markdown/md-tutorial.html)

一般而言, 我们推荐使用 [Visual Studio Code](https://code.visualstudio.com/) 和 [Typora](https://typora.io/) 这两个软件编写 Markdown

## Git 版本管理

Git 是一个分布式版本控制软件, 学习如何使用 Git 也是成为一名 CTFer 的必经之路

- 廖雪峰的 Git 教程: [https://liaoxuefeng.com/books/git/](https://liaoxuefeng.com/books/git/)
- Learn Git Branching: [https://learngitbranching.js.org/](https://learngitbranching.js.org/)

## Python 语言

这里我们建议优先学习 Python 而不是 C 语言, 因为 Python 简单易上手, 而且各个方向都会用到

对于 Python 的学习, 只需要掌握一些基本知识即可, 例如变量、控制结构、数据类型、类与对象、文件操作

同时还需要了解一些标准库和第三方库的运用, 例如 re、os、sys、json、socket、requests、pwntools

- Python Tutorial: [https://www.pythontutorial.net/](https://www.pythontutorial.net/)
- 廖雪峰的 Python 教程: [https://liaoxuefeng.com/books/python/](https://liaoxuefeng.com/books/python/)
- Python 3 小时快速入门视频: [https://www.bilibili.com/video/BV1944y1x7SW/](https://www.bilibili.com/video/BV1944y1x7SW/)

## Linux 系统基础

Linux 是一种开源的操作系统, 在学习 CTF 的过程中, 无论什么方向, 都需要和 Linux 接触

- 中科大 LUG 协会《Linux 101》: [https://101.lug.ustc.edu.cn/](https://101.lug.ustc.edu.cn/)

## Docker 快速上手

在制作 CTF 题目的过程中, 需要用到 Docker 来制作镜像

刚入门时可以先掌握 Docker 的一些基础概念和用法, 例如镜像、容器的概念, 如何启动、停止容器, 如何编写 Dockerfile 和 docker-compose.yml

- Docker 从入门到实践: [https://yeasy.gitbook.io/docker_practice/](https://yeasy.gitbook.io/docker_practice/)