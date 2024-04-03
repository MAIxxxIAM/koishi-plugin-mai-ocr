import { Context, Dict, Schema ,Element} from 'koishi'
import crypto, { BinaryToTextEncoding } from 'crypto'
import {} from 'koishi-plugin-text-censor'
import https from 'https'

export const name = 'mai-ocr'

export const inject ={
  optional:['translator','censor']
}

export interface Config {
  SECRET_ID: string
  SECRET_KEY: string
  接入地域: string
  action: string
  是否翻译: boolean
  目标语言: string
  使用MD:boolean
  MD模板id:string
  key1:string
  key2:string
}

export const Config= Schema.intersect([
  Schema.object({
    SECRET_ID: Schema.string().role('secret').required(),
    SECRET_KEY: Schema.string().role('secret').required(),
  }).description('腾讯云 OCR 密钥'),
  Schema.object({
    接入地域: Schema.union([
      Schema.const('ap-guangzhou').description('华南地区(广州) '),
      Schema.const('ap-shanghai').description('华东地区(上海)'),
      Schema.const('ap-beijing').description('华北地区(北京)'),
      Schema.const('ap-chengdu').description('西南地区(成都)'),
      Schema.const('ap-hongkong').description('港澳台地区(中国香港)')
    ]).role('radio'),
    action: Schema.union([
      Schema.const('GeneralHandwritingOCR').description('手写体识别'),
      Schema.const('GeneralBasicOCR').description('通用印刷文字识别')
    ]).role('radio').required()
  }).description('腾讯云 OCR 配置'),
    Schema.object({
      是否翻译: Schema.boolean().default(false),
    }).description('翻译配置'),
    Schema.union([
      Schema.object({
        是否翻译: Schema.const(true).required(),
        目标语言: Schema.string().description(`请输入目标语言代码，具体查看translator服务\n\n例如：中文 百度zh  有道zh-CHS`).default('zh'),
      }),
      Schema.object({}),
    ]),
    Schema.object({
      使用MD: Schema.boolean().default(false),
    }).description('翻译配置'),
    Schema.union([
      Schema.object({
        使用MD: Schema.const(true).required(),
        MD模板id: Schema.string().required(),
        key1: Schema.string().default('text1').description('原文'),
        key2: Schema.string().default('text2').description('译文'),
      }),
      Schema.object({}),
    ]),
])

export function apply(ctx: Context, config: Config) {

  //注册指令
  ctx.command('ocr <img:text>', 'OCR 识别')
    .action(async ({ session }, img) => {
      if(!img) return `输入指令时需要带上识别（翻译）图片`
      const text = img.match(/src="([^"]*)"/)[1]
      //定义变量
      const TOKEN=''
      const host = `ocr.tencentcloudapi.com`
      const service = "ocr"
      const region = config.接入地域
      const action = config.action
      const version = "2018-11-19"
      const timestamp = parseInt(String(new Date().getTime() / 1000))
      const date = getDate(timestamp)
      const payload = `{\"ImageUrl\":\"${text}\"}`
      //拼接请求串
      const signedHeaders = "content-type;host"
      const hashedRequestPayload = getHash(payload)
      const httpRequestMethod = "POST"
      const canonicalUri = "/"
      const canonicalQueryString = ""
      const canonicalHeaders =
        "content-type:application/json; charset=utf-8\n" + "host:" + host + "\n"

      const canonicalRequest =
        httpRequestMethod +
        "\n" +
        canonicalUri +
        "\n" +
        canonicalQueryString +
        "\n" +
        canonicalHeaders +
        "\n" +
        signedHeaders +
        "\n" +
        hashedRequestPayload
      //拼接签名字符串
      const algorithm = "TC3-HMAC-SHA256"
      const hashedCanonicalRequest = getHash(canonicalRequest)
      const credentialScope = date + "/" + service + "/" + "tc3_request"
      const stringToSign =
        algorithm +
        "\n" +
        timestamp +
        "\n" +
        credentialScope +
        "\n" +
        hashedCanonicalRequest
      //计算签名
      const kDate = sha256(date,"TC3" + config.SECRET_KEY, "hex")
      const kService = sha256(service, kDate, "hex")
      const kSigning = sha256("tc3_request",kService, "hex")
      const signature = sha256(stringToSign, kSigning, "hex")
      //拼接 Authorization
      const authorization =
        algorithm +
        " " +
        "Credential=" +
        config.SECRET_ID +
        "/" +
        credentialScope +
        ", " +
        "SignedHeaders=" +
        signedHeaders +
        ", " +
        "Signature=" +
        signature

      //构造请求
      const headers = {
        Authorization: authorization,
        "Content-Type": "application/json; charset=utf-8",
        Host: host,
        "X-TC-Action": action,
        "X-TC-Timestamp": timestamp,
        "X-TC-Version": version,
      }

      if (region) {
        headers["X-TC-Region"] = region
      }
      if (TOKEN) {
        headers["X-TC-Token"] = TOKEN
      }

      const options = {
        hostname: host,
        method: httpRequestMethod,
        headers,
      }
      const req = https.request(options, (res) => {
        let data = ""
        res.on("data", (chunk) => {
          data += chunk
        })
      
        res.on("end", async () => {
          const parsedData = JSON.parse(data)
          const characters = parsedData?.Response.TextDetections.map(detection => {
            if(config.action==='GeneralHandwritingOCR'){
              return {
                character: detection.DetectedText,
                Polygon: parsedData?.Response.TextDetections[0].Polygon[0],  // 假设 Polygon 数组的第一个对象代表字符的位置
              }
            }
              return {
                character: detection.DetectedText,
                Polygon: {X:detection.ItemPolygon.X,Y:detection.ItemPolygon.Y},  // 假设 Polygon 数组的第一个对象代表字符的位置
              }
          }).flat() // 使用 flat 方法将嵌套数组转换为一维数组
          characters.sort((a, b) => {
            const aPosition = a.Polygon
            const bPosition = b.Polygon
            if (aPosition.Y < bPosition.Y) {
              return -1
            } else if (aPosition.Y > bPosition.Y) {
              return 1
            }
            if (aPosition.X < bPosition.X) {
              return -1
            } else if (aPosition.X > bPosition.X) {
              return 1
            }
            return 0
          })
          const characterString =await censorText(ctx, characters.map(characterObject => characterObject.character).join(' ').replace(/\./g, "۔"))
          if (config.是否翻译) {
            const translation =await censorText(ctx,  await session.app['translator'].translate({target:config.目标语言 ,input:characterString}))
            if(config.使用MD){
              const c1 = mdCreate(characterString,translation,session)
              await session.bot.internal.sendMessage(session.guildId,c1)
              return
            }
            await session.send(`${characterString}\n翻译：\n${translation.replace(/\./g, "。")}`)
            return
          }
          if(config.使用MD){
            const c1 = mdCreate(characterString,'请开启翻译功能',session)
            await session.bot.internal.sendMessage(session.guildId,c1)
            return
          }
          await session.send(characterString)
        })
      })
      
      req.on("error", (error) => {
        console.error(error)
      })
      
      req.write(payload)
      
      req.end()

    })



  //函数
  function sha256(message: crypto.BinaryLike, secret = "", encoding: BinaryToTextEncoding) {
    const hmac = crypto.createHmac("sha256", secret)
    return hmac.update(message).digest(encoding)
  }
  function getHash(message, encoding: BinaryToTextEncoding = "hex") {
    const hash = crypto.createHash("sha256")
    return hash.update(message).digest(encoding)
  }
  function getDate(timestamp) {
    const date = new Date(timestamp * 1000)
    const year = date.getUTCFullYear()
    const month = ("0" + (date.getUTCMonth() + 1)).slice(-2)
    const day = ("0" + date.getUTCDate()).slice(-2)
    return `${year}-${month}-${day}`
  }
  function mdCreate(a,b,c){
    return {
      content: "111",
      msg_type: 2,
      markdown: {
        custom_template_id:config.MD模板id,
        params: [
          {
            key:config.key1,
            values: [a]
          },
          {
            key:config.key2,
            values: [`\r\r> 翻译：${b}`]
          }
        ]
      },
      keyboard: {
        content: {
          rows: [
            {
              "buttons": [
                {
                  "id": "1",
                  "render_data": {
                    "label": "🖊每日签到",
                    "visited_label": "签到"
                  },
                  "action": {
                    "type": 2,
                    "permission": {
                      "type": 2
                    },
                    "unsupport_tips": "兼容文本",
                    "data": '/签到',
                    "enter": true
                  },
                }, {
                  "id": "2",
                  "render_data": {
                    "label": "👁重新识别",
                    "visited_label": "重新识别"
                  },
                  "action": {
                    "type": 2,
                    "permission": {
                      "type": 2
                    },
                    "unsupport_tips": "兼容文本",
                    "data": "/ocr",
                    "enter": false
                  },
                }]
            }
          ]
        }
      },
      msg_id:c.messageId,
      timestamp: c.timestamp,
      msg_seq: Math.floor(Math.random()*500)
    }
  }
}

export async function censorText(ctx,text: string) {
  const a:Element[]=[Element('text',{content:text})]
  const [b]=await ctx.censor.transform(a)
  return b.attrs.content
}
