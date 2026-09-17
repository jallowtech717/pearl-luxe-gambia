import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { createClient } from "@libsql/client";

const app=express();
const port=Number(process.env.PORT||3000);
const db=process.env.TURSO_DATABASE_URL&&process.env.TURSO_AUTH_TOKEN?createClient({url:process.env.TURSO_DATABASE_URL,authToken:process.env.TURSO_AUTH_TOKEN}):null;
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"100kb"}));
app.use("/api",rateLimit({windowMs:60_000,limit:80,standardHeaders:true,legacyHeaders:false}));
app.use(express.static("public",{maxAge:"1h",etag:true}));

const schema=[
"CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY,name TEXT NOT NULL,sku TEXT UNIQUE NOT NULL,price REAL NOT NULL,sale_price REAL,stock INTEGER NOT NULL DEFAULT 0,description TEXT NOT NULL DEFAULT '')",
"CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT,order_number TEXT UNIQUE NOT NULL,email TEXT NOT NULL,full_name TEXT NOT NULL,phone TEXT NOT NULL,address TEXT NOT NULL,region TEXT NOT NULL,instructions TEXT,status TEXT NOT NULL DEFAULT 'Payment Pending',subtotal REAL NOT NULL,delivery_fee REAL NOT NULL,total REAL NOT NULL,created_at INTEGER NOT NULL)",
"CREATE TABLE IF NOT EXISTS order_items (id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL REFERENCES orders(id),product_id INTEGER NOT NULL,product_name TEXT NOT NULL,sku TEXT NOT NULL,quantity INTEGER NOT NULL,unit_price REAL NOT NULL,size TEXT,color TEXT)",
"CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL REFERENCES orders(id),provider TEXT NOT NULL,reference TEXT UNIQUE NOT NULL,status TEXT NOT NULL,amount REAL NOT NULL,created_at INTEGER NOT NULL)",
"CREATE TABLE IF NOT EXISTS order_status_history (id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL REFERENCES orders(id),status TEXT NOT NULL,note TEXT,created_at INTEGER NOT NULL)",
"CREATE INDEX IF NOT EXISTS idx_orders_phone ON orders(phone)",
"CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)"
];
async function init(){if(!db){console.warn("Turso is not configured; order APIs are unavailable.");return}for(const sql of schema)await db.execute(sql);console.log("PEARL LUXE database ready")}
const clean=(v,max=250)=>String(v??"").trim().slice(0,max);
const emailOk=v=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const phoneOk=v=>/^\+?\d{9,15}$/.test(v.replace(/\s/g,""));

app.get("/healthz",(_,res)=>res.json({ok:true,database:Boolean(db),manager:"Alhagie Jallow"}));
app.post("/api/orders",async(req,res)=>{
 try{
  if(!db)return res.status(503).json({error:"Ordering is temporarily unavailable."});
  const b=req.body||{},fullName=clean(b.fullName,100),phone=clean(b.phone,20).replace(/\s/g,""),email=clean(b.email,150).toLowerCase(),address=clean(b.address,300),region=clean(b.region,100),instructions=clean(b.instructions,300),reference=clean(b.paymentReference,80);
  const items=Array.isArray(b.items)?b.items.slice(0,25):[];
  if(!fullName||!phoneOk(phone)||!emailOk(email)||!address||!region||!reference||!items.length)return res.status(400).json({error:"Complete all delivery and Wave payment fields."});
  let subtotal=0;
  for(const x of items){
   if(!Number.isInteger(x.productId)||!Number.isInteger(x.quantity)||x.quantity<1||x.quantity>20||!Number.isFinite(x.unitPrice))return res.status(400).json({error:"Invalid cart item."});
   await db.execute({sql:"INSERT OR IGNORE INTO products(id,name,sku,price,stock,description) VALUES(?,?,?,?,?,?)",args:[x.productId,clean(x.name,120),clean(x.sku,60),x.unitPrice,Number(x.stock)||0,clean(x.description,500)]});
   const row=(await db.execute({sql:"SELECT * FROM products WHERE id=?",args:[x.productId]})).rows[0];
   if(!row||Number(row.stock)<x.quantity)return res.status(409).json({error:`${x.name} does not have enough stock.`});
   subtotal+=Number(row.sale_price??row.price)*x.quantity;
  }
  const delivery=subtotal>=3500?0:150,total=subtotal+delivery,year=new Date().getUTCFullYear(),number=`PL-${year}-${String(Date.now()).slice(-5)}`,now=Date.now();
  const duplicate=await db.execute({sql:"SELECT 1 FROM payments WHERE reference=?",args:[reference]});if(duplicate.rows.length)return res.status(409).json({error:"This Wave reference has already been used."});
  const inserted=await db.execute({sql:"INSERT INTO orders(order_number,email,full_name,phone,address,region,instructions,status,subtotal,delivery_fee,total,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id",args:[number,email,fullName,phone,address,region,instructions||null,"Payment Pending",subtotal,delivery,total,now]});
  const orderId=Number(inserted.rows[0].id);
  const statements=[];
  for(const x of items){statements.push({sql:"INSERT INTO order_items(order_id,product_id,product_name,sku,quantity,unit_price,size,color) VALUES(?,?,?,?,?,?,?,?)",args:[orderId,x.productId,clean(x.name,120),clean(x.sku,60),x.quantity,x.unitPrice,clean(x.size,40),clean(x.color,40)]});statements.push({sql:"UPDATE products SET stock=stock-? WHERE id=? AND stock>=?",args:[x.quantity,x.productId,x.quantity]})}
  statements.push({sql:"INSERT INTO payments(order_id,provider,reference,status,amount,created_at) VALUES(?,?,?,?,?,?)",args:[orderId,"Wave",reference,"submitted_pending_verification",total,now]},{sql:"INSERT INTO order_status_history(order_id,status,note,created_at) VALUES(?,?,?,?)",args:[orderId,"Payment Pending","Wave reference submitted; awaiting verification.",now]});
  await db.batch(statements,"write");res.status(201).json({orderNumber:number,status:"Payment Pending",total});
 }catch(e){console.error("order_create_failed",e);res.status(500).json({error:"Could not place the order. Contact PEARL LUXE on WhatsApp."})}
});
app.get("/api/orders/track",async(req,res)=>{
 try{if(!db)return res.status(503).json({error:"Tracking is temporarily unavailable."});const order=clean(req.query.order,30).toUpperCase(),phone=clean(req.query.phone,20).replace(/\s/g,"");const out=await db.execute({sql:"SELECT order_number,status,created_at FROM orders WHERE order_number=? AND phone=?",args:[order,phone]});if(!out.rows.length)return res.status(404).json({error:"No matching order was found."});res.json({orderNumber:out.rows[0].order_number,status:out.rows[0].status,updatedAt:out.rows[0].created_at})}catch(e){res.status(500).json({error:"Tracking is temporarily unavailable."})}
});
app.get("*",(req,res)=>res.sendFile("index.html",{root:"public"}));
init().then(()=>app.listen(port,"0.0.0.0",()=>console.log(`PEARL LUXE listening on ${port}`))).catch(e=>{console.error(e);process.exit(1)});
