# koishi-plugin-mai-suangua

[![npm](https://img.shields.io/npm/v/koishi-plugin-mai-suangua?style=flat-square)](https://www.npmjs.com/package/koishi-plugin-mai-suangua)

# 📚 描述
可以使用QQ官方机器人MD，通过腾讯的OCR服务进行图像文字识别的插件，如果安装了translator依赖，可以同时进行翻译
# ✨使用方式

koishi插件市场中搜索mai-ocr，并安装

## 配置设置
- QQ官方bot+MD模板
    - 登入腾讯云申请secret_id和secret_key。
    - 填写配置项中的secret_id和secret_key,MDid（在qq开放平台申请）
    - 翻译服务默认目标语言为中文，通过更改语言代码更改
    - 填写配置项中的两个插值名称（开放平台申请时设置，需要全文本的插值）
- 非QQ官方bot+不使用MD模板
    - 登入腾讯云申请secret_id和secret_key。
    - 填写配置项中的secret_id和secret_key。
    - 翻译服务默认目标语言为中文，通过更改语言代码更改