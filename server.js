import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import { createClient } from "@libsql/client";

const app=express(),port=Number(process.env.PORT||3000);
const db=process.env.TURSO_DATABASE_URL&&process.env.TURSO_AUTH_TOKEN?createClient({url:process.env.TURSO_DATABASE_URL,authToken:process.env.TURSO_AUTH_TOKEN}):null;
const setupKey=process.env.ADMIN_SETUP_KEY||"";
app.set("trust proxy",1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"4mb"}));
app.use("/api",rateLimit({windowMs:60_000,limit:100,standardHeaders:true,legacyHeaders:false}));
app.use("/api/admin/login",rateLimit({windowMs:15*60_000,limit:8,standardHeaders:true,legacyHeaders:false}));
app.use(express.static("public",{maxAge:"1h",etag:true}));

const schema=[
"CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,sku TEXT UNIQUE NOT NULL,price REAL NOT NULL,sale_price REAL,stock INTEGER NOT NULL DEFAULT 0,description TEXT NOT NULL DEFAULT '',category TEXT NOT NULL DEFAULT 'Accessories',sizes TEXT NOT NULL DEFAULT 'One Size',colors TEXT NOT NULL DEFAULT '',featured INTEGER NOT NULL DEFAULT 0,archived INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS product_images (id INTEGER PRIMARY KEY AUTOINCREMENT,product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,image_data TEXT NOT NULL,sort_order INTEGER NOT NULL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE NOT NULL,active INTEGER NOT NULL DEFAULT 1)",
"CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'admin',created_at INTEGER NOT NULL)",
"CREATE TABLE IF NOT EXISTS admin_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT,admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,token_hash TEXT UNIQUE NOT NULL,csrf_token TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL)",
"CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT,order_number TEXT UNIQUE NOT NULL,email TEXT NOT NULL,full_name TEXT NOT NULL,phone TEXT NOT NULL,address TEXT NOT NULL,region TEXT NOT NULL,instructions TEXT,status TEXT NOT NULL DEFAULT 'Payment Pending',subtotal REAL NOT NULL,delivery_fee REAL NOT NULL,total REAL NOT NULL,created_at INTEGER NOT NULL)",
"CREATE TABLE IF NOT EXISTS order_items (id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL REFERENCES orders(id),product_id INTEGER NOT NULL,product_name TEXT NOT NULL,sku TEXT NOT NULL,quantity INTEGER NOT NULL,unit_price REAL NOT NULL,size TEXT,color TEXT)",
"CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL REFERENCES orders(id),provider TEXT NOT NULL,reference TEXT UNIQUE NOT NULL,status TEXT NOT NULL,amount REAL NOT NULL,created_at INTEGER NOT NULL)",
"CREATE TABLE IF NOT EXISTS order_status_history (id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL REFERENCES orders(id),status TEXT NOT NULL,note TEXT,created_at INTEGER NOT NULL)",
"CREATE INDEX IF NOT EXISTS idx_orders_phone ON orders(phone)","CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)","CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token_hash)"
];
const seeds=[
["Noor Embroidered Abaya","PL-ABA-001",2850,2450,12,"Flowing black abaya with champagne embroidery.","Abayas","M","Black",1],
["Amara Structured Handbag","PL-BAG-014",1950,null,8,"Structured burgundy handbag with gold-tone hardware.","Handbags","One Size","Burgundy",1],
["Zahra Pearl Slingbacks","PL-SHO-008",1650,1350,6,"Champagne slingbacks with pearl details.","Shoes","39","Champagne",1],
["Layla Satin Abaya","PL-ABA-009",2600,null,4,"Fluid satin abaya with clean tailoring.","Abayas","L","Midnight",0],
["Pearl Drop Jewelry Set","PL-ACC-021",850,null,18,"Gold-tone necklace and earrings with pearl drops.","Accessories","One Size","Gold",0],
["Mariam Mini Bag","PL-BAG-022",1250,null,0,"Compact evening bag for your essentials.","Handbags","One Size","Black",0]
];
async function init(){
 if(!db){console.warn("Turso is not configured; data APIs are unavailable.");return}
 for(const sql of schema)await db.execute(sql);
 const cols=new Set((await db.execute("PRAGMA table_info(products)")).rows.map(r=>String(r.name)));
 const additions={category:"TEXT NOT NULL DEFAULT 'Accessories'",sizes:"TEXT NOT NULL DEFAULT 'One Size'",colors:"TEXT NOT NULL DEFAULT ''",featured:"INTEGER NOT NULL DEFAULT 0",archived:"INTEGER NOT NULL DEFAULT 0",created_at:"INTEGER NOT NULL DEFAULT 0",updated_at:"INTEGER NOT NULL DEFAULT 0"};
 for(const [name,type] of Object.entries(additions))if(!cols.has(name))await db.execute(`ALTER TABLE products ADD COLUMN ${name} ${type}`);
 for(const name of ["Abayas","Handbags","Shoes","Accessories","Jewelry"])await db.execute({sql:"INSERT OR IGNORE INTO categories(name) VALUES(?)",args:[name]});
 const count=Number((await db.execute("SELECT COUNT(*) n FROM products")).rows[0].n);
 if(!count){const now=Date.now();for(const s of seeds)await db.execute({sql:"INSERT INTO products(name,sku,price,sale_price,stock,description,category,sizes,colors,featured,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",args:[...s,now,now]})}
 await db.execute({sql:"DELETE FROM admin_sessions WHERE expires_at<?",args:[Date.now()]});
 console.log("PEARL LUXE database ready");
}
const clean=(v,max=250)=>String(v??"").trim().slice(0,max);
const emailOk=v=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const phoneOk=v=>/^\+?\d{9,15}$/.test(v.replace(/\s/g,""));
const parseCookies=req=>Object.fromEntries((req.headers.cookie||"").split(";").filter(Boolean).map(x=>{const i=x.indexOf("=");return[decodeURIComponent(x.slice(0,i).trim()),decodeURIComponent(x.slice(i+1))]}));
const hash=v=>crypto.createHash("sha256").update(v).digest("hex");
const safeAdmin=a=>({id:Number(a.id),email:String(a.email),name:String(a.name),role:String(a.role)});
async function auth(req,res,next){
 if(!db)return res.status(503).json({error:"Database unavailable."});
 const token=parseCookies(req).pl_admin;if(!token)return res.status(401).json({error:"Sign in required."});
 const out=await db.execute({sql:"SELECT a.*,s.csrf_token FROM admin_sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>?",args:[hash(token),Date.now()]});
 if(!out.rows.length)return res.status(401).json({error:"Session expired."});
 req.admin=out.rows[0];
 if(!["GET","HEAD"].includes(req.method)&&req.headers["x-csrf-token"]!==req.admin.csrf_token)return res.status(403).json({error:"Security check failed. Refresh and try again."});
 next();
}
const validImage=v=>typeof v==="string"&&/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(v)&&v.length<=750_000;
const normalizeProduct=b=>{
 const p={name:clean(b.name,120),sku:clean(b.sku,60).toUpperCase(),description:clean(b.description,1200),category:clean(b.category,60),sizes:clean(b.sizes,200),colors:clean(b.colors,200),price:Number(b.price),salePrice:b.salePrice===""||b.salePrice==null?null:Number(b.salePrice),stock:Number(b.stock),featured:b.featured?1:0};
 if(!p.name||!p.sku||!p.category||!Number.isFinite(p.price)||p.price<0||!Number.isInteger(p.stock)||p.stock<0)throw Error("Complete all required product fields correctly.");
 if(p.salePrice!==null&&(!Number.isFinite(p.salePrice)||p.salePrice<0||p.salePrice>=p.price))throw Error("Sale price must be lower than the regular price.");
 return p;
};

app.get("/healthz",(_,res)=>res.json({ok:true,database:Boolean(db),manager:"Alhagie Jallow"}));
app.get("/api/products",async(_,res)=>{try{if(!db)return res.status(503).json({error:"Store database unavailable."});const out=await db.execute("SELECT p.*, (SELECT image_data FROM product_images WHERE product_id=p.id ORDER BY sort_order LIMIT 1) image FROM products p WHERE archived=0 ORDER BY featured DESC,created_at DESC");res.json(out.rows.map(r=>({...r,id:Number(r.id),price:Number(r.price),salePrice:r.sale_price==null?null:Number(r.sale_price),stock:Number(r.stock),featured:Boolean(r.featured),image:r.image||null})))}catch(e){console.error(e);res.status(500).json({error:"Could not load products."})}});

app.get("/api/admin/setup-status",async(_,res)=>{if(!db)return res.status(503).json({error:"Database unavailable."});const n=Number((await db.execute("SELECT COUNT(*) n FROM admins")).rows[0].n);res.json({needsSetup:n===0})});
app.post("/api/admin/setup",async(req,res)=>{try{if(!db)return res.status(503).json({error:"Database unavailable."});const n=Number((await db.execute("SELECT COUNT(*) n FROM admins")).rows[0].n);if(n)return res.status(409).json({error:"Administrator already created."});if(!setupKey||!crypto.timingSafeEqual(Buffer.from(hash(clean(req.body.setupKey,200))),Buffer.from(hash(setupKey))))return res.status(403).json({error:"Invalid setup key."});const email=clean(req.body.email,150).toLowerCase(),name=clean(req.body.name,100),password=String(req.body.password||"");if(!emailOk(email)||!name||password.length<12)return res.status(400).json({error:"Use a valid email and a password of at least 12 characters."});await db.execute({sql:"INSERT INTO admins(email,name,password_hash,created_at) VALUES(?,?,?,?)",args:[email,name,await bcrypt.hash(password,12),Date.now()]});res.status(201).json({ok:true})}catch(e){console.error(e);res.status(500).json({error:"Could not create administrator."})}});
app.post("/api/admin/login",async(req,res)=>{try{if(!db)return res.status(503).json({error:"Database unavailable."});const email=clean(req.body.email,150).toLowerCase(),password=String(req.body.password||""),out=await db.execute({sql:"SELECT * FROM admins WHERE email=?",args:[email]});if(!out.rows.length||!await bcrypt.compare(password,String(out.rows[0].password_hash)))return res.status(401).json({error:"Invalid email or password."});const token=crypto.randomBytes(32).toString("hex"),csrf=crypto.randomBytes(24).toString("hex"),now=Date.now();await db.execute({sql:"INSERT INTO admin_sessions(admin_id,token_hash,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)",args:[out.rows[0].id,hash(token),csrf,now+7*864e5,now]});res.cookie("pl_admin",token,{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"strict",maxAge:7*864e5,path:"/"});res.json({admin:safeAdmin(out.rows[0]),csrf})}catch(e){res.status(500).json({error:"Could not sign in."})}});
app.get("/api/admin/session",auth,(req,res)=>res.json({admin:safeAdmin(req.admin),csrf:req.admin.csrf_token}));
app.post("/api/admin/logout",auth,async(req,res)=>{const token=parseCookies(req).pl_admin;await db.execute({sql:"DELETE FROM admin_sessions WHERE token_hash=?",args:[hash(token)]});res.clearCookie("pl_admin",{path:"/"});res.json({ok:true})});
app.get("/api/admin/products",auth,async(_,res)=>{const products=(await db.execute("SELECT * FROM products ORDER BY archived,updated_at DESC")).rows;for(const p of products)p.images=(await db.execute({sql:"SELECT id,image_data,sort_order FROM product_images WHERE product_id=? ORDER BY sort_order",args:[p.id]})).rows;res.json(products)});
app.post("/api/admin/products",auth,async(req,res)=>{try{const p=normalizeProduct(req.body),images=Array.isArray(req.body.images)?req.body.images.slice(0,5):[];if(images.some(x=>!validImage(x)))return res.status(400).json({error:"Use JPG, PNG or WebP images under 550 KB each."});const now=Date.now(),out=await db.execute({sql:"INSERT INTO products(name,sku,price,sale_price,stock,description,category,sizes,colors,featured,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id",args:[p.name,p.sku,p.price,p.salePrice,p.stock,p.description,p.category,p.sizes,p.colors,p.featured,now,now]});const id=Number(out.rows[0].id);for(let i=0;i<images.length;i++)await db.execute({sql:"INSERT INTO product_images(product_id,image_data,sort_order) VALUES(?,?,?)",args:[id,images[i],i]});res.status(201).json({id})}catch(e){res.status(400).json({error:e.message.includes("UNIQUE")?"That SKU already exists.":e.message})}});
app.put("/api/admin/products/:id",auth,async(req,res)=>{try{const id=Number(req.params.id),p=normalizeProduct(req.body),images=Array.isArray(req.body.images)?req.body.images.slice(0,5):[];if(!Number.isInteger(id)||images.some(x=>!validImage(x)))return res.status(400).json({error:"Invalid product or image."});await db.execute({sql:"UPDATE products SET name=?,sku=?,price=?,sale_price=?,stock=?,description=?,category=?,sizes=?,colors=?,featured=?,updated_at=? WHERE id=?",args:[p.name,p.sku,p.price,p.salePrice,p.stock,p.description,p.category,p.sizes,p.colors,p.featured,Date.now(),id]});await db.execute({sql:"DELETE FROM product_images WHERE product_id=?",args:[id]});for(let i=0;i<images.length;i++)await db.execute({sql:"INSERT INTO product_images(product_id,image_data,sort_order) VALUES(?,?,?)",args:[id,images[i],i]});res.json({ok:true})}catch(e){res.status(400).json({error:e.message.includes("UNIQUE")?"That SKU already exists.":e.message})}});
app.delete("/api/admin/products/:id",auth,async(req,res)=>{const id=Number(req.params.id);await db.execute({sql:"UPDATE products SET archived=1,updated_at=? WHERE id=?",args:[Date.now(),id]});res.json({ok:true})});

app.post("/api/orders",async(req,res)=>{
 try{if(!db)return res.status(503).json({error:"Ordering is temporarily unavailable."});const b=req.body||{},fullName=clean(b.fullName,100),phone=clean(b.phone,20).replace(/\s/g,""),email=clean(b.email,150).toLowerCase(),address=clean(b.address,300),region=clean(b.region,100),instructions=clean(b.instructions,300),reference=clean(b.paymentReference,80),items=Array.isArray(b.items)?b.items.slice(0,25):[];
 if(!fullName||!phoneOk(phone)||!emailOk(email)||!address||!region||!reference||!items.length)return res.status(400).json({error:"Complete all delivery and Wave payment fields."});
 let subtotal=0,verified=[];for(const x of items){if(!Number.isInteger(x.productId)||!Number.isInteger(x.quantity)||x.quantity<1||x.quantity>20)return res.status(400).json({error:"Invalid cart item."});const row=(await db.execute({sql:"SELECT * FROM products WHERE id=? AND archived=0",args:[x.productId]})).rows[0];if(!row||Number(row.stock)<x.quantity)return res.status(409).json({error:`${clean(x.name,120)} does not have enough stock.`});const unit=Number(row.sale_price??row.price);subtotal+=unit*x.quantity;verified.push({x,row,unit})}
 const delivery=subtotal>=3500?0:150,total=subtotal+delivery,year=new Date().getUTCFullYear(),number=`PL-${year}-${String(Date.now()).slice(-5)}`,now=Date.now();if((await db.execute({sql:"SELECT 1 FROM payments WHERE reference=?",args:[reference]})).rows.length)return res.status(409).json({error:"This Wave reference has already been used."});
 const inserted=await db.execute({sql:"INSERT INTO orders(order_number,email,full_name,phone,address,region,instructions,status,subtotal,delivery_fee,total,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id",args:[number,email,fullName,phone,address,region,instructions||null,"Payment Pending",subtotal,delivery,total,now]});const orderId=Number(inserted.rows[0].id),statements=[];
 for(const {x,row,unit} of verified){statements.push({sql:"INSERT INTO order_items(order_id,product_id,product_name,sku,quantity,unit_price,size,color) VALUES(?,?,?,?,?,?,?,?)",args:[orderId,row.id,row.name,row.sku,x.quantity,unit,clean(x.size,40),clean(x.color,40)]},{sql:"UPDATE products SET stock=stock-? WHERE id=? AND stock>=?",args:[x.quantity,row.id,x.quantity]})}
 statements.push({sql:"INSERT INTO payments(order_id,provider,reference,status,amount,created_at) VALUES(?,?,?,?,?,?)",args:[orderId,"Wave",reference,"submitted_pending_verification",total,now]},{sql:"INSERT INTO order_status_history(order_id,status,note,created_at) VALUES(?,?,?,?)",args:[orderId,"Payment Pending","Wave reference submitted; awaiting verification.",now]});await db.batch(statements,"write");res.status(201).json({orderNumber:number,status:"Payment Pending",total})
 }catch(e){console.error("order_create_failed",e);res.status(500).json({error:"Could not place the order. Contact PEARL LUXE on WhatsApp."})}
});
app.get("/api/orders/track",async(req,res)=>{try{if(!db)return res.status(503).json({error:"Tracking is temporarily unavailable."});const order=clean(req.query.order,30).toUpperCase(),phone=clean(req.query.phone,20).replace(/\s/g,""),out=await db.execute({sql:"SELECT order_number,status,created_at FROM orders WHERE order_number=? AND phone=?",args:[order,phone]});if(!out.rows.length)return res.status(404).json({error:"No matching order was found."});res.json({orderNumber:out.rows[0].order_number,status:out.rows[0].status,updatedAt:out.rows[0].created_at})}catch(e){res.status(500).json({error:"Tracking is temporarily unavailable."})}});
app.get("/admin",(_,res)=>res.sendFile("admin.html",{root:"public"}));
app.use((req,res)=>res.sendFile("index.html",{root:"public"}));
init().then(()=>app.listen(port,"0.0.0.0",()=>console.log(`PEARL LUXE listening on ${port}`))).catch(e=>{console.error(e);process.exit(1)});
