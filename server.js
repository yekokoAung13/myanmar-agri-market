require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_AUTH_FILE = path.join(__dirname, "data", "admin-auth.json");
function verifyAdminPassword(password) {
  try {
    const saved = JSON.parse(fs.readFileSync(ADMIN_AUTH_FILE, "utf8"));
    const salt = Buffer.from(saved.salt, "hex");
    const expected = Buffer.from(saved.hash, "hex");
    const actual = crypto.scryptSync(password, salt, 64);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch (e) { return false; }
}

app.use(helmet({contentSecurityPolicy:false, crossOriginEmbedderPolicy:false}));
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "database.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const defaultData = {
  crops: [
    { id: 1, name: "ကြက်သွန်နီ", image: "onion" },
    { id: 2, name: "ကြက်သွန်ဖြူ", image: "garlic" },
    { id: 3, name: "ငရုတ်သီး", image: "chili" },
    { id: 4, name: "မတ်ပဲ", image: "blackgram" },
    { id: 5, name: "ပဲတီစိမ်း", image: "mungbean" },
    { id: 6, name: "ပဲစင်းငုံ", image: "pigeonpea" },
    { id: 7, name: "ကုလားပဲ", image: "chickpea" },
    { id: 8, name: "ပဲကြီး", image: "bean" },
    { id: 9, name: "ပဲစာဉ", image: "bean" },
    { id: 10, name: "ပဲငပိ", image: "soybean" },
    { id: 11, name: "နှမ်းနက်", image: "black-sesame" },
    { id: 12, name: "နှမ်းဖြူ", image: "white-sesame" },
    { id: 13, name: "နှမ်းညို", image: "brown-sesame" },
    { id: 14, name: "မြေပဲ", image: "peanut" },
    { id: 15, name: "ပြောင်း", image: "corn" },
    { id: 16, name: "ဆန်စပါး", image: "rice" }
  ],
  prices: [],
  news: [],
  knowledge: [],
  posts: []
};

if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(defaultData, null, 2));
}

function readData() {
  const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  if (!Array.isArray(data.aiHistory)) data.aiHistory = [];
  return data;
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

const adminTokens = new Map();
const loginAttempts = new Map();
const TOKEN_LIFETIME = 12 * 60 * 60 * 1000;

function adminAuth(req, res, next) {
  const token = req.headers["x-admin-token"];
  const expiresAt = adminTokens.get(token);

  if (!token || !expiresAt || Date.now() >= expiresAt) {
    if (token) adminTokens.delete(token);
    return res.status(401).json({
      success: false,
      message: "Admin Login ပြန်ဝင်ပါ"
    });
  }
  next();
}

function newId() {
  return Date.now() + Math.floor(Math.random() * 1000);
}

function removeAdminRecord(data, key, id) {
  if (!Number.isSafeInteger(id) || id <= 0) return 400;
  const items = Array.isArray(data[key]) ? data[key] : [];
  const filtered = items.filter(item => Number(item.id) !== id);
  if (filtered.length === items.length) return 404;
  data[key] = filtered;
  saveData(data);
  return 200;
}

function clean(value) {
  return String(value || "").trim();
}

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Myanmar Agri Market Server အလုပ်လုပ်နေပါပြီ"
  });
});

app.get("/api/public", (req, res) => {
  const data = readData();

  res.json({
    success: true,
    crops: data.crops,
    prices: data.prices,
    news: data.news,
    knowledge: data.knowledge,
    posts: data.posts
  });
});

app.post("/api/posts", (req, res) => {
  const text = clean(req.body.text);

  if (!text || text.length > 3000) {
    return res.status(400).json({
      success: false,
      message: "စာသားကို စစ်ဆေးပါ"
    });
  }

  const data = readData();

  const post = {
    id: newId(),
    text,
    createdAt: new Date().toLocaleString("my-MM", {
      timeZone: "Asia/Yangon"
    })
  };

  data.posts.unshift(post);
  saveData(data);

  res.json({
    success: true,
    message: "မျှဝေပြီးပါပြီ",
    post
  });
});

app.post("/api/admin/login", (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  let attempt = loginAttempts.get(ip);

  if (attempt && attempt.blockedUntil > now) {
    return res.status(429).json({
      success: false,
      message: "Login ခဏပိတ်ထားပါသည်။ ၁၅ မိနစ်အကြာ ပြန်ကြိုးစားပါ။"
    });
  }

  if (!attempt || now - attempt.windowStart >= 15 * 60 * 1000) {
    attempt = { count: 0, windowStart: now, blockedUntil: 0 };
  }

  const password = clean(req.body.password);

  if (!verifyAdminPassword(password)) {
    attempt.count++;
    if (attempt.count >= 5) {
      attempt.blockedUntil = now + 15 * 60 * 1000;
    }
    loginAttempts.set(ip, attempt);
    return res.status(401).json({
      success: false,
      message: attempt.count >= 5
        ? "Password ၅ ကြိမ်မှားနေပါသည်။ ၁၅ မိနစ်အကြာ ပြန်ကြိုးစားပါ။"
        : "Password မှားနေပါသည်"
    });
  }

  loginAttempts.delete(ip);

  const token = crypto.randomBytes(32).toString("hex");
  adminTokens.set(token, now + TOKEN_LIFETIME);

  res.json({
    success: true,
    token,
    message: "Admin Login အောင်မြင်ပါသည်"
  });
});

app.get("/api/admin/data", adminAuth, (req, res) => {
  res.json({
    success: true,
    data: readData()
  });
});

app.post("/api/admin/crops", adminAuth, (req, res) => {
  const name = clean(req.body.name);
  const image = clean(req.body.image) || "crop";

  if (!name) {
    return res.status(400).json({
      success: false,
      message: "သီးနှံအမည် ထည့်ပါ"
    });
  }

  const data = readData();

  if (data.crops.some(c => c.name === name)) {
    return res.status(400).json({
      success: false,
      message: "သီးနှံရှိပြီးသားပါ"
    });
  }

  const crop = { id: newId(), name, image };
  data.crops.push(crop);
  saveData(data);

  res.json({ success: true, crop });
});

app.delete("/api/admin/crops/:id", adminAuth, (req, res) => {
  const data = readData();
  const status = removeAdminRecord(data, "crops", Number(req.params.id));
  if (status !== 200) {
    return res.status(status).json({
      success: false,
      message: status === 404 ? "သီးနှံ မတွေ့ပါ" : "ID မှားယွင်းနေပါသည်"
    });
  }
  res.json({ success: true });
});

app.post("/api/admin/prices", adminAuth, (req, res) => {
  const cropName = clean(req.body.cropName || req.body.crop);
  const market = clean(req.body.market);
  const unit = clean(req.body.unit);
  const grade = clean(req.body.grade || req.body.quality);
  const price = Number(req.body.price);

  if (!cropName || !market || !unit || !Number.isFinite(price) || price <= 0) {
    return res.status(400).json({success:false,message:"ဈေးနှုန်းအချက်အလက်များ မှန်ကန်စွာဖြည့်ပါ"});
  }

  const data = readData();
  if (!Array.isArray(data.prices)) data.prices = [];
  const previous = data.prices.find(p =>
    (p.cropName || p.crop) === cropName &&
    p.market === market && p.unit === unit &&
    (p.grade || p.quality || "") === grade
  );

  const record = {
    id:newId(), cropName, market, unit, grade, price,
    previousPrice:previous ? previous.price : null,
    change:previous ? price - previous.price : null,
    updatedAt:new Date().toLocaleString("my-MM",{timeZone:"Asia/Yangon"}),
    source:clean(req.body.source) || "Admin ထည့်သွင်းချက်"
  };
  data.prices.unshift(record);
  saveData(data);
  res.json({success:true,message:"ဈေးနှုန်း သိမ်းဆည်းပြီးပါပြီ",record});
});

app.put("/api/admin/prices/:id", adminAuth, (req, res) => {
  const data = readData();
  const id = Number(req.params.id);
  const index = (data.prices || []).findIndex(p => String(p.id) === String(id));
  if (index < 0) return res.status(404).json({success:false,message:"ဈေးနှုန်း မတွေ့ပါ"});

  const old = data.prices[index];
  const cropName = clean(req.body.cropName || req.body.crop);
  const market = clean(req.body.market);
  const unit = clean(req.body.unit);
  const grade = clean(req.body.grade || req.body.quality);
  const price = Number(req.body.price);

  if (!cropName || !market || !unit || !Number.isFinite(price) || price <= 0) {
    return res.status(400).json({success:false,message:"ဈေးနှုန်းအချက်အလက်များ မှန်ကန်စွာဖြည့်ပါ"});
  }

  data.prices[index] = {
    ...old, cropName, market, unit, grade, price,
    previousPrice:old.price,
    change:price - old.price,
    updatedAt:new Date().toLocaleString("my-MM",{timeZone:"Asia/Yangon"}),
    source:clean(req.body.source) || old.source || "Admin ထည့်သွင်းချက်"
  };
  saveData(data);
  res.json({success:true,message:"ဈေးနှုန်း ပြင်ဆင်ပြီးပါပြီ",record:data.prices[index]});
});

app.delete("/api/admin/prices/:id", adminAuth, (req, res) => {
  const data = readData();
  const status = removeAdminRecord(data, "prices", Number(req.params.id));
  if (status !== 200) {
    return res.status(status).json({
      success: false,
      message: status === 404 ? "ဈေးနှုန်း မတွေ့ပါ" : "ID မှားယွင်းနေပါသည်"
    });
  }
  res.json({ success: true });
});

app.post("/api/admin/news", adminAuth, (req, res) => {
  const title = clean(req.body.title);
  const content = clean(req.body.content);

  if (!title || !content) {
    return res.status(400).json({
      success: false,
      message: "သတင်းခေါင်းစဉ်နှင့် အကြောင်းအရာ ဖြည့်ပါ"
    });
  }

  const data = readData();

  const item = {
    id: newId(),
    title,
    content,
    createdAt: new Date().toLocaleString("my-MM", {
      timeZone: "Asia/Yangon"
    })
  };

  data.news.unshift(item);
  saveData(data);

  res.json({ success: true, item });
});

app.delete("/api/admin/news/:id", adminAuth, (req, res) => {
  const data = readData();
  const status = removeAdminRecord(data, "news", Number(req.params.id));
  if (status !== 200) {
    return res.status(status).json({
      success: false,
      message: status === 404 ? "သတင်း မတွေ့ပါ" : "ID မှားယွင်းနေပါသည်"
    });
  }
  res.json({ success: true });
});

app.post("/api/admin/knowledge", adminAuth, (req, res) => {
  const title = clean(req.body.title);
  const content = clean(req.body.content);

  if (!title || !content) {
    return res.status(400).json({
      success: false,
      message: "ခေါင်းစဉ်နှင့် အကြောင်းအရာ ဖြည့်ပါ"
    });
  }

  const data = readData();

  const item = {
    id: newId(),
    title,
    content,
    createdAt: new Date().toLocaleString("my-MM", {
      timeZone: "Asia/Yangon"
    })
  };

  data.knowledge.unshift(item);
  saveData(data);

  res.json({ success: true, item });
});

app.delete("/api/admin/knowledge/:id", adminAuth, (req, res) => {
  const data = readData();
  const status = removeAdminRecord(data, "knowledge", Number(req.params.id));
  if (status !== 200) {
    return res.status(status).json({
      success: false,
      message: status === 404 ? "ဗဟုသုတ မတွေ့ပါ" : "ID မှားယွင်းနေပါသည်"
    });
  }
  res.json({ success: true });
});


app.put("/api/admin/crops/:id", adminAuth, (req, res) => {
  const data = readData();
  const id = Number(req.params.id);
  const index = (data.crops || []).findIndex(c => String(c.id) === String(id));
  if (index < 0) return res.status(404).json({success:false,message:"သီးနှံ မတွေ့ပါ"});

  const name = clean(req.body.name);
  const image = clean(req.body.image) || data.crops[index].image || "crop";
  if (!name) return res.status(400).json({success:false,message:"သီးနှံအမည် ထည့်ပါ"});
  if (data.crops.some((c,i) => i !== index && c.name === name)) {
    return res.status(400).json({success:false,message:"သီးနှံရှိပြီးသားပါ"});
  }

  data.crops[index] = {...data.crops[index], name, image};
  saveData(data);
  res.json({success:true,message:"သီးနှံ ပြင်ဆင်ပြီးပါပြီ",item:data.crops[index]});
});

app.put("/api/admin/news/:id", adminAuth, (req, res) => {
  const data = readData();
  const id = Number(req.params.id);
  const index = (data.news || []).findIndex(n => String(n.id) === String(id));
  if (index < 0) return res.status(404).json({success:false,message:"သတင်း မတွေ့ပါ"});

  const title = clean(req.body.title);
  const content = clean(req.body.content);
  if (!title || !content) return res.status(400).json({success:false,message:"ခေါင်းစဉ်နှင့် အကြောင်းအရာ ဖြည့်ပါ"});

  data.news[index] = {...data.news[index], title, content, updatedAt:new Date().toLocaleString("my-MM",{timeZone:"Asia/Yangon"})};
  saveData(data);
  res.json({success:true,message:"သတင်း ပြင်ဆင်ပြီးပါပြီ",item:data.news[index]});
});

app.put("/api/admin/knowledge/:id", adminAuth, (req, res) => {
  const data = readData();
  const id = Number(req.params.id);
  const index = (data.knowledge || []).findIndex(k => String(k.id) === String(id));
  if (index < 0) return res.status(404).json({success:false,message:"ဗဟုသုတ မတွေ့ပါ"});

  const title = clean(req.body.title);
  const content = clean(req.body.content);
  if (!title || !content) return res.status(400).json({success:false,message:"ခေါင်းစဉ်နှင့် အကြောင်းအရာ ဖြည့်ပါ"});

  data.knowledge[index] = {...data.knowledge[index], title, content, updatedAt:new Date().toLocaleString("my-MM",{timeZone:"Asia/Yangon"})};
  saveData(data);
  res.json({success:true,message:"ဗဟုသုတ ပြင်ဆင်ပြီးပါပြီ",item:data.knowledge[index]});
});

app.delete("/api/admin/posts/:id", adminAuth, (req, res) => {
  const data = readData();
  const status = removeAdminRecord(data, "posts", Number(req.params.id));
  if (status !== 200) {
    return res.status(status).json({
      success: false,
      message: status === 404 ? "Post မတွေ့ပါ" : "ID မှားယွင်းနေပါသည်"
    });
  }
  res.json({ success: true });
});

app.post("/api/admin/logout", adminAuth, (req, res) => {
  adminTokens.delete(req.headers["x-admin-token"]);
  res.json({ success: true });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/api/market/automatic",async(req,res)=>{
 try{
  const r=await fetch("https://market.mpbmsma.org/web/api/market-price/yrcci-daily-rate?date=default");
  const j=await r.json();
  if(j.status!=="success")throw Error();
  const data=readData();
  if(!Array.isArray(data.history))data.history=[];
  const record={date:j.date,source:"MPBMSMA Bayintnaung",prices:j.market_rate};
  const index=data.history.findIndex(x=>x.date===j.date&&x.source===record.source);
  if(index>=0)data.history[index]=record;
  else data.history.push(record);
  data.history.sort((a,b)=>b.date.localeCompare(a.date));
  saveData(data);
  res.json({success:true,source:record.source,date:j.date,prices:j.market_rate});
 }catch(e){res.status(502).json({success:false,message:"ဈေးနှုန်းရယူမရပါ"});}
});
app.get("/api/market/history",(req,res)=>{
 const data=readData();
 res.json({success:true,history:data.history||[]});
});
const doaMarkets={
  9:"ကျောက်ဆည်ကုန်စည်ဒိုင်",
  24:"မြင်းခြံကုန်စည်ဒိုင်",
  10:"မိတ္ထီလာကုန်စည်ဒိုင်",
  7:"ပြင်ဦးလွင်ကုန်စည်ဒိုင်",
  27:"အောင်ပန်းကုန်စည်ဒိုင်"
};

app.get("/api/market/doa",async(req,res)=>{
  console.log("DOA ROUTE HIT:",req.originalUrl);
 try{
  const id=String(req.query.seller||"24");
  if(!doaMarkets[id]) return res.status(400).json({
   success:false,message:"ဒိုင် ID မမှန်ပါ",markets:doaMarkets
  });
  const url="https://www.doa.gov.mm/mis_market/index.php?filter_seller="+id+"&route=market%2Fweekly_crop_price_by_seller";
  const response=await fetch(url,{signal:AbortSignal.timeout(20000)});
  if(!response.ok) throw Error("DOA source unavailable");
  const html=await response.text();
  const body=html.match(/<tbody[^>]*>([\s\S]*?)<\/tbody>/i);
  if(!body) throw Error("Price table not found");

  const clean=v=>v.replace(/<[^>]*>/g," ")
   .replace(/&nbsp;/gi," ").replace(/&amp;/gi,"&")
   .replace(/&#39;|&apos;/gi,"'")
   .replace(/\s+/g," ").trim();

  let category="";
  const prices=[];
  for(const row of body[1].matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)){
   const cells=[...row[1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map(x=>clean(x[1]));
   if(cells.length===1){category=cells[0];continue;}
   if(cells.length<6)continue;
   const min=cells[4].replace(/,/g,"");
   const max=cells[5].replace(/,/g,"");
   if(!min&&!max)continue;
   prices.push({
    category,name:cells[1],unit:cells[2],
    quantity:cells[3],
    min_price:min||null,max_price:max||null
   });
  }
  if(prices.length===0){
   return res.json({
    success:false,source:"DOA",market:doaMarkets[id],
    date:(html.match(/name="filter_date_start" value="([^"]+)"/i)||[])[1]||null,
    count:0,message:"တရားဝင်ရင်းမြစ်တွင် ဈေးနှုန်းမပါသေးပါ"
   });
  }
  const data=readData();
  if(!Array.isArray(data.history))data.history=[];
  const record={
   date:(html.match(/name="filter_date_start" value="([^"]+)"/i)||[])[1]||null,
        fetched_at:new Date().toISOString(),
   source:"DOA",
   market:doaMarkets[id],
   seller_id:id,
   frequency:"အပတ်စဉ်",
   prices
  };
  const index=data.history.findIndex(x=>x.source==="DOA"&&x.seller_id===id&&x.date===record.date);
  if(index>=0)data.history[index]=record;
  else data.history.push(record);
  data.history.sort((a,b)=>b.date.localeCompare(a.date));
  saveData(data);
  res.json({
   success:true,source:"DOA",
   market:doaMarkets[id],seller_id:id,
   date:record.date,fetched_at:record.fetched_at,frequency:"အပတ်စဉ်",
   count:prices.length,prices
  });
 }catch(e){
  res.status(502).json({success:false,message:"DOA ဈေးနှုန်းရယူမရပါ"});
 }
});



app.post("/api/ai/chat", async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();
    const deviceId = String(req.body.deviceId || "").trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(deviceId)) {
      return res.status(400).json({success:false,message:"အသုံးပြုသူ ID မမှန်ပါ။"});
    }

    if (!message || message.length > 2000) {
      return res.status(400).json({
        success: false,
        message: "မေးခွန်းကို စစ်ဆေးပါ။ စာလုံးရေ ၂၀၀၀ အထိသာ ရေးနိုင်ပါသည်။"
      });
    }

    if (!process.env.GROQ_API_KEY) {
      return res.status(503).json({
        success: false,
        message: "AI API Key မသတ်မှတ်ရသေးပါ။"
      });
    }

    const Groq = require("groq-sdk");
    const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

    const completion = await groq.chat.completions.create({
      model: "qwen/qwen3.8-27b",
      messages: [
        {
          role: "system",
          content: "သင်သည် Myanmar Agri Market အတွင်းရှိ မြန်မာတောင်သူများအတွက် စိုက်ပျိုးရေးအကူအညီပေးသော AI ဖြစ်သည်။ မြန်မာဘာသာဖြင့် ရှင်းလင်းလွယ်ကူစွာ ဖြေပါ။ စိုက်ပျိုးနည်း၊ ပိုးမွှားနှင့် ရောဂါ၊ မြေဩဇာနှင့် စိုက်ပျိုးရေးဆိုင်ရာ မေးခွန်းများကို တတ်နိုင်သမျှ တိကျစွာ ဖြေပါ။ မသေချာပါက မသေချာကြောင်း ပြောပါ။ လက်ရှိဈေးနှုန်းကို အချက်အလက်မရှိဘဲ မခန့်မှန်းပါနှင့်။ ပိုးသတ်ဆေးအသုံးပြုမှုအတွက် ဆေးဘူး Label နှင့် ဒေသခံ စိုက်ပျိုးရေးပညာရှင်၏ အကြံပြုချက်ကို လိုက်နာရန် သတိပေးပါ။"
        },
        { role: "user", content: message }
      ],
      temperature: 0.3,
      max_tokens: 700
    });

    const answer = completion.choices[0].message.content || "အဖြေမရရှိပါ။";
    const data = readData();
    data.aiHistory.unshift({
      id: newId(),
      deviceId,
      question: message,
      answer,
      createdAt: new Date().toLocaleString("my-MM", {timeZone:"Asia/Yangon"})
    });
    data.aiHistory = data.aiHistory.slice(0, 300);
    saveData(data);
    res.json({ success: true, answer });

  } catch (e) {
    console.error("AI chat error:", e.message);
    res.status(502).json({
      success: false,
      message: "AI ဖြေဆိုမှု မအောင်မြင်ပါ။ ခဏနေ ပြန်ကြိုးစားပါ။"
    });
  }
});


const doaKnowledgeCategories = [
  {id:33,name:"စပါးနှင့်အခြားနှံစားသီးနှံများ"},
  {id:73,name:"ဆီထွက်သီးနှံများ"},
  {id:102,name:"ပန်းမန်နှင့်အလှစိုက်ပင်များ"},
  {id:34,name:"စက်မှုကုန်ကြမ်းသီးနှံများ"},
  {id:105,name:"မျိုးစေ့နည်းပညာ"},
  {id:106,name:"သီးနှံကာကွယ်ရေး"},
  {id:108,name:"စိုက်ပျိုးပညာပေး"},
  {id:110,name:"စိုက်ပျိုးနည်းစနစ်များ"},
  {id:127,name:"စိုက်ပျိုးစီးပွား"}
];
app.get("/api/knowledge/doa", async (req,res) => {
  const category=Number(req.query.category || 108);
  const selected=doaKnowledgeCategories.find(c=>c.id===category);
  if(!selected) return res.status(400).json({success:false,message:"အမျိုးအစား မမှန်ပါ"});
  try {
    const url="https://www.doa.gov.mm/elibrary/index.php?route=product/category&path="+category;
    const response=await fetch(url,{headers:{"User-Agent":"Mozilla/5.0"}});
    if(!response.ok) throw Error("DOA HTTP "+response.status);
    const html=await response.text();
    const decode=t=>t.replace(/&amp;/g,"&").replace(/&quot;/g,'"').replace(/&#39;|&apos;/g,"'").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&nbsp;/g," ").replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Number(n))).replace(/&#x([0-9a-f]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16)));
    const items=[];
    const seen=new Set();
    for(const m of html.matchAll(/<a\b[^>]*href=["']([^"']*product_id=\d+[^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi)){
      const href=decode(m[1]);
      const title=decode(m[2].replace(/<[^>]*>/g," ").replace(/\s+/g," ").trim());
      const link=new URL(href,"https://www.doa.gov.mm/elibrary/").href;
      if(title && !seen.has(link)){seen.add(link);items.push({title,url:link});}
    }
    res.json({success:true,source:"စိုက်ပျိုးရေးဦးစီးဌာန (DOA)",category:selected,categories:doaKnowledgeCategories,items});
  } catch(e) {
    console.error("[DOA KNOWLEDGE]",e.message);
    res.status(502).json({success:false,message:"DOA ဗဟုသုတ ရယူ၍မရပါ။ ခဏနေ ပြန်ကြိုးစားပါ။"});
  }
});

// AI_HISTORY_SAVE
app.get("/api/ai/history", (req, res) => {
  const deviceId = String(req.get("x-device-id") || "").trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(deviceId)) {
    return res.status(400).json({success:false,message:"အသုံးပြုသူ ID မမှန်ပါ။"});
  }
  const data = readData();
  const history = (data.aiHistory || []).filter(x => x.deviceId === deviceId);
  res.json({success:true, history});
});


// GEMINI PLANT PHOTO ANALYSIS
app.post("/api/plant/analyze", async (req, res) => {
  try {
    if (!process.env.GEMINI_API_KEY) {
      return res.status(503).json({
        success: false,
        message: "Gemini API Key မသတ်မှတ်ရသေးပါ။"
      });
    }

    const imageBase64 = String(req.body.imageBase64 || "");
    const mimeType = String(req.body.mimeType || "").toLowerCase();
    const deviceId = String(req.body.deviceId || "").trim();

    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(deviceId)) {
      return res.status(400).json({success:false,message:"အသုံးပြုသူ ID မမှန်ပါ။"});
    }

    if (!["image/jpeg", "image/png", "image/webp"].includes(mimeType)) {
      return res.status(400).json({success:false,message:"JPG, PNG သို့မဟုတ် WebP ပုံသာ တင်နိုင်ပါသည်။"});
    }

    if (!imageBase64 || imageBase64.length > 1700000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(imageBase64)) {
      return res.status(400).json({success:false,message:"ဓာတ်ပုံမမှန်ပါ သို့မဟုတ် အရွယ်အစားကြီးနေပါသည်။"});
    }

    const { GoogleGenAI } = require("@google/genai");
    const ai = new GoogleGenAI({apiKey:process.env.GEMINI_API_KEY});

    const response = await ai.models.generateContent({
      model: "gemini-3.8-flash",
      contents: [{
        role: "user",
        parts: [
          {
            text: "သင်သည် မြန်မာတောင်သူများကို ကူညီပေးသော အပင်ရောဂါနှင့် ပိုးမွှားစစ်ဆေးရေး AI ဖြစ်သည်။ ဤဓာတ်ပုံကို မြန်မာဘာသာဖြင့် စစ်ဆေးပြီး (၁) မြင်ရသော အပင်အမျိုးအစား (၂) မြင်ရသော လက္ခဏာများ (၃) ဖြစ်နိုင်သော ရောဂါ သို့မဟုတ် ပိုးမွှားနှင့် ယုံကြည်မှုအဆင့် (၄) ဖြစ်နိုင်သော အကြောင်းရင်း (၅) လက်တွေ့ကာကွယ်ကုသနည်း (၆) ထပ်မံစစ်ဆေးရန် လိုအပ်သော အချက်များကို ခွဲခြားရှင်းပြပါ။ ဓာတ်ပုံတစ်ပုံတည်းဖြင့် အတည်မပြုနိုင်ပါက မသေချာကြောင်း ရှင်းပြပါ။ ဆေးအမည်၊ ဆေးနှုန်းနှင့် ဆေးပမာဏကို မခန့်မှန်းပါနှင့်။ ဆေးအသုံးပြုရာတွင် တရားဝင် Label နှင့် ဒေသခံ စိုက်ပျိုးရေးပညာရှင်၏ အကြံပြုချက်ကို လိုက်နာရန် သတိပေးပါ။"
          },
          {
            inlineData: {
              mimeType,
              data: imageBase64
            }
          }
        ]
      }]
    });

    res.json({
      success: true,
      answer: response.text || "ဓာတ်ပုံမှ အဖြေမရရှိပါ။"
    });

  } catch (e) {
    console.error("[PLANT AI]", e.message);
    res.status(502).json({
      success: false,
      message: "အပင်ဓာတ်ပုံ စစ်ဆေး၍မရပါ။ ခဏနေ ပြန်ကြိုးစားပါ။"
    });
  }
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "စာမျက်နှာ မတွေ့ပါ"
  });
});





async function AUTO_MARKET_REFRESH(){
  const sources=[
    ["MPBMSMA","http://127.0.0.1:"+PORT+"/api/market/automatic"],
    ...Object.keys(doaMarkets).map(id=>["DOA "+id,"http://127.0.0.1:"+PORT+"/api/market/doa?seller="+id])
  ];
  for(const [name,url] of sources){
    try{
      const r=await fetch(url,{signal:AbortSignal.timeout(25000)});
      const j=await r.json();
      console.log("[AUTO PRICE]",name,j.success?"OK "+(j.date||""):"မရရှိပါ");
    }catch(e){console.log("[AUTO PRICE]",name,"မရရှိပါ");}
  }
}

app.listen(PORT, "0.0.0.0", () => {
  console.log("GROQ_API_KEY present:", Boolean(process.env.GROQ_API_KEY));
  console.log("Myanmar Agri Market Server");
  console.log("Server running on port " + PORT);
  setTimeout(AUTO_MARKET_REFRESH,5000);
  setInterval(AUTO_MARKET_REFRESH,6*60*60*1000);
});

