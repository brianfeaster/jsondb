#![allow(non_snake_case)]

use std::{
    env, io::{Write}, error::Error,
    time::{Duration, SystemTime, UNIX_EPOCH}, sync::{Arc, Mutex},
    str::{from_utf8}};

use log::{
    error, warn, info, Record,
    Level::{self, Warn, Info, Debug, Trace}};
use env_logger::fmt::{Formatter, Color};

use ::openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_web::{
    web, App, HttpRequest, HttpMessage, HttpServer, HttpResponse, Route,
    http::header::HeaderMap};

use awc::{Client};

use serde_json::{json, Value};
use regex::{Regex};


////////////////////////////////////////////////////////////////////////////////

pub type Bresult<T> = Result<T, Box<dyn Error>>;

////////////////////////////////////////////////////////////////////////////////

fn logger_formatter (buf: &mut Formatter, rec: &Record) -> std::io::Result<()> {
    let mut style = buf.style();
    style.set_color(
        match rec.level() {
            Level::Error => Color::Red,
            Warn  => Color::Yellow,
            Info  => Color::Green,
            Debug => Color::Cyan,
            Trace => Color::Magenta
        });
    let pre = style.value(format!("{} {}:{}", rec.level(), rec.target(), rec.line().unwrap()));
    writeln!(buf, "{} {:?}", pre, rec.args())
}

fn logger_init () {
    env_logger::builder()
    .format(logger_formatter)
    .init();
}

pub fn bytes2json (body: &[u8]) -> Bresult<Value> {
    Ok( serde_json::from_str( from_utf8(&body)? )? )
}

fn headersCompact (hm: &HeaderMap) -> Vec<String> {
    hm.iter()
    .map(|(k,v)| format!("{}:{}", k, v.to_str().unwrap_or("?")))
    .collect::<Vec<String>>()
}


fn dbReq (req: &HttpRequest, body: &web::Bytes) {
    info!(" \x1b[1;35m{} \x1b[0;35m{:?} \x1b[33m{:?} \x1b[0m{}",
        req.peer_addr().map(|sa|sa.ip().to_string()).as_deref().unwrap_or("?"),
        req.uri(),
        body,
        headersCompact(req.headers()).join("  "));
}

////////////////////////////////////////////////////////////////////////////////

// https://docs.rs/http/0.2.8/src/http/status.rs.html

fn httpResponseOkBody (val: String) -> HttpResponse {
    let resp = HttpResponse::Ok().body(val.clone());
    info!("200/OK \x1b[33m{:?}\x1b[0m {}\n", val, headersCompact(resp.headers()).join("  "));
    resp
}

fn httpResponseOkJsonContentType (val: &Value, ct: Option<String>) -> HttpResponse {
    let mut resp = HttpResponse::Ok();
    if let Some(ct) = ct { resp.content_type(ct); }
    let resp = resp.json(val.clone());
    info!("<= 200/OK \x1b[33m{}\x1b[0m {}\n", val, headersCompact(resp.headers()).join("  "));
    resp
}

fn httpResponseNotFound () -> HttpResponse {
    let resp = HttpResponse::NotFound().finish();
    error!("404/NotFound {}\n", headersCompact(resp.headers()).join("  "));
    resp
}

fn httpResponseNotAcceptableJson (val: Value) -> HttpResponse {
    let resp = HttpResponse::NotAcceptable().json(val.clone());
    error!("406/NotAcceptable \x1b[33m{}\x1b[0m {}\n", val, headersCompact(resp.headers()).join("  "));
    resp
}

fn httpResponseBadRequestJson (val: Value) -> HttpResponse {
    let resp = HttpResponse::BadRequest().json(val.clone());
    error!("400/BadRequest \x1b[33m{}\x1b[0m {}\n", val, headersCompact(resp.headers()).join("  "));
    resp
}

async fn httpsjson (url: &Value, val: &Value) -> Bresult<Value> {
    info!("<= \x1b[34m{} \x1b[1m{}\x1b[0m", url, val.to_string());
    let mut res =
        Client::default()
        .post(url.as_str().ok_or(format!("{{notStringy {:?}}}", url))?)
        .insert_header(("User-Agent", "TMBot"))
        .timeout(Duration::new(90,0))
        .send_json(&val)
        .await?;
    let body = res.body().await;
    info!("=> \x1b[34m{:?} \x1b[1m{:?}\x1b[0m  {}",
        res.status(),
        body.as_ref().unwrap_or(&web::Bytes::from("?")),
        headersCompact(&res.headers()).join("  "));
    Ok(bytes2json(&body?)?)
}

async fn httpsbody (url: &str, body: &str) -> Bresult<String> {
    info!("<= \x1b[34m{} \x1b[1m{:?}\x1b[0m", url, body);
    let mut res =
        Client::default()
        .post(url)
        .insert_header(("User-Agent", "TMBot"))
        .timeout(Duration::new(90,0))
        .send_body(body.to_string())
        .await?;
    let body = res.body().await;
    // Log it
    info!("=> \x1b[34m{:?} \x1b[1m{:?}\x1b[0m  {}",
        res.status(),
        body.as_ref().unwrap_or(&web::Bytes::from("?")),
        headersCompact(&res.headers()).join("  "));
    Ok(from_utf8(&body?)?.into())
}

// Log remotely incoming request details
async fn lgReq (req: &HttpRequest, body: &web::Bytes, remoteLogUrl: &str) -> Bresult<String> {
    httpsbody(
        &remoteLogUrl,
        &format!("{} {} {}\n{}",
            req.headers().get(actix_web::http::header::USER_AGENT).and_then(|hv|hv.to_str().ok()).unwrap_or("?"),
            req.peer_addr().map(|sa|sa.ip().to_string()).unwrap_or("?".into()),
            req.path(),
            from_utf8(body).unwrap_or("?"))) //body.unwrp_or("?")
    .await
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct EnvStruct {
    dbfile: String,
    jsondb: Value     // The base JSON dictionary (holds every user database)
}

type Env = Arc<Mutex<EnvStruct>>;

impl From<EnvStruct> for Env {
    fn from (envstruct: EnvStruct) -> Self {
        Arc::new(Mutex::new(envstruct))
    }
}

impl EnvStruct {
  fn new(dbfile: String) -> Bresult<Env> {
    Ok(EnvStruct{
        dbfile: dbfile.clone(),
        jsondb: serde_json::from_str(
           std::fs::read_to_string(dbfile)
          .as_deref()
          .map_err (|e| warn!("{:?}", e))
          .unwrap_or(r#"{}"#))?
    }.into())
  }
}

////////////////////////////////////////////////////////////////////////////////

trait ToNum<T> { fn toNum (&self) -> Bresult<T>; }

impl ToNum<usize> for Value {
    fn toNum (&self) -> Bresult<usize> {
        self.as_u64()
        .or_else(
            || self.as_f64()
            .map(|n|n as u64) )
        .map(|n| n as usize)
        .ok_or("{notU64able}".into())
    }
}

impl ToNum<u64> for Value {
    fn toNum (&self) -> Bresult<u64> {
        self.as_u64()
        .or_else(
            || self.as_f64()
            .map(|n|n as u64) )
        .ok_or("{notU64able}".into())
    }
}

impl ToNum<f64> for Value {
    fn toNum (&self) -> Bresult<f64> {
        self.as_f64()
        .ok_or("{notF64able}".into())
    }
}

////////////////////////////////////////////////////////////////////////////////

trait ToStr {
  fn to_str (&self) -> String;
}

impl ToStr for Value {
  fn to_str (&self) -> String {
    self.as_str()
    .map(<str>::to_string)
    .unwrap_or_else(||self.to_string())
  }
}

////////////////////////////////////////////////////////////////////////////////

fn asNum<T> (value: &Value) -> Bresult<T>
where T: From<u8>, Value: ToNum<T>
{
    value.toNum()
    .or_else( |e|
      match value {
          Value::Number(_) => Err(e),
          Value::Null | Value::Bool(false)
                           => Ok(0.into()),
                         _ => Ok(1.into())
      })
}

////////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
enum Atom {
   Val(Value),
   Sym(Value)
}

struct Prog {
   atoms: Vec<Atom>
}

impl Prog {
    fn new (code: &str) -> Prog {
        let mut atoms =
        Regex::new(r#"(?x)
            ( \s | ;[^\n]*(\n|$) )*     # comment
            (                             # any 3
                (-?\d*[.]\d+ | -?\d+[.]?) # number 4
                | ("( \\" | [^"] )*")     # string 5
                | ([^\s;]+) )             # symbol 7
            ( \s | ;[^\n]*(\n|$) )*     # comment
        "#).unwrap()
        .captures_iter(code) // CaptureMatches
        .map(|caps|
           caps.get(3)
           .map(|mtch| mtch.as_str())
           .unwrap_or("'parseError"))
        .map(|tok|
            serde_json::from_str(tok)
            .map(Atom::Val)
            .unwrap_or_else( |_|
                if Some('\'') == tok.chars().next() {
                    Atom::Val(Value::from(&tok[1..]))
                } else {
                    Atom::Sym(Value::from(tok))
                } ) )
        .collect::<Vec<Atom>>();
        atoms.reverse();
        Prog{atoms}
    }
    fn next (&mut self) -> Option<Atom> {
        self.atoms.pop()
    }
}



struct RPN<'c> {
   env: &'c Env,
   key: &'c str, // The database name (key in base JSON dictionary) lives as long as env.
   prog: Vec<Prog>,
   stk: Vec<Value>
}

trait Rpn<'c> {
    fn new (env: &'c Env, key: &'c str, code: &str) -> Self;
    fn stkLen (&self) -> usize;
    fn stk (&mut self) -> &mut Vec<Value>;
    fn pop (&mut self) -> Bresult<Value>;
    fn push (&mut self, v: Value) -> Bresult<()>;
    fn popPush (&mut self, count: usize, v: Value) -> Bresult<()>;
    fn peek (&self, i: usize) -> Bresult<& Value>;
    fn peekMut (&mut self, i: usize) -> Bresult<&mut Value>;
    fn peekAsNum<U> (&mut self, i: usize) -> Bresult<U>
    where
        U: From<u8>,
        Value: ToNum<U>;
    fn popArgCount (&mut self) -> Bresult<usize>;
    fn apply<F,U> (&mut self, f: F) -> Bresult<()>
    where
        Value: From<U> + ToNum<U>,
        U: From<u8>,
        F: Fn(U,U)->U;
    fn assign(&mut self) -> Bresult<()>;
    fn pathAssign (&mut self) -> Bresult<()>;
    fn pathLookup (&mut self) -> Bresult<()>;
    fn cap(&mut self) -> Option<Atom>;
}

impl<'c> Rpn<'c> for RPN<'c>
{
    fn new (env: &'c Env, key: &'c str, code: &str) -> Self {
      let prog = Prog::new(code);
      let mut progs = Vec::new();
      progs.push(prog);
      Self{ env, key, prog:progs, stk:Vec::new() }
    }
    fn stkLen (&self) -> usize { self.stk.len() }
    fn stk (&mut self) -> &mut Vec<Value> { &mut self.stk }
    fn pop (&mut self) -> Bresult<Value> {
        self.stk()
        .pop()
        .ok_or("popUnderflow".into())
    }
    fn push (&mut self, v: Value) -> Bresult<()> {
        Ok(self.stk().push(v))
    }
    fn popPush (&mut self, count: usize, v: Value) -> Bresult<()> {
        let len = self.stkLen();
        if len < count { Err("popPushUnderflow".into()) }
        else {
            self.stk().truncate(len - count);
            self.push(v)
        }
    }
    fn peek (&self, i: usize) -> Bresult<&Value> {
        let len = self.stkLen();
        if len <= i { Err("peekUnderflow")? }
        Ok(&self.stk[len-i-1])
    }
    fn peekMut (&mut self, i: usize) -> Bresult<&mut Value> {
        let len = self.stkLen();
        if len <= i { Err("peekMutUnderflow")? }
        Ok(&mut self.stk()[len-i-1])
    }
    fn peekAsNum<U> (&mut self, i: usize) -> Bresult<U>
    where
        U: From<u8>,
        Value: ToNum<U>
    {
        self.peek(i)
        .and_then( |v|
            v.toNum()
            .or_else( |e|
              match v {
                  Value::Number(_) => Err(e),
                  Value::Null | Value::Bool(false)
                                   => Ok(0.into()),
                                 _ => Ok(1.into())
              }))
    }
    fn popArgCount (&mut self) -> Bresult<usize> {
        let n = self.peekAsNum::<usize>(0)?;
        self.peek(n)?;
        self.pop()?;
        Ok(n)
    }
    fn apply<F,U> (&mut self, f:F) -> Bresult<()>
    where
        Value: From<U> + ToNum<U>,
        U: From<u8>,
        F: Fn(U,U)->U,
    {
        let a = self.peekAsNum(0)?;
        let b = self.peekAsNum(1)?;
        self.popPush(2, f(a,b).into())
    }
    fn assign (&mut self) -> Bresult<()>
    {
        self.peek(1)?;
        let key = self.pop()?;
        let val = self.pop()?;
        self.env.lock().unwrap().jsondb[self.key][key.as_str().ok_or("assignKeyBad")?] = val;
        Ok(())
    }
    fn pathAssign (&mut self) -> Bresult<()>
    {
        let path = self.peek(0)?.as_str().ok_or("pathNotStr")?;
        let val  = self.peek(1)?.clone();

        self.env.lock().unwrap().jsondb[self.key]
        .pointer_mut(path)
        .map(|v| *v = val)
        .ok_or("badPath")?;

        self.pop()?;
        self.pop()?;
        Ok(())
    }
    fn pathLookup (&mut self) -> Bresult<()>
    {
        let path = self.peek(0)?.as_str().ok_or("pathNotStr")?;
        let ret =
            self.env.lock().unwrap().jsondb[self.key]
            .pointer(path)
            .map(|v|v.clone())
            .ok_or("badPath")?;

        self.popPush(1, ret)
    }
    fn cap(&mut self) -> Option<Atom> {
        loop {
          match self.prog.last() {
              None => return None,
              Some(v) =>
                  if v.atoms.len() != 0 { break }
                  else {
                      self.prog.pop();
                  }
          }
        }
        self.prog.last_mut().and_then(|p|p.next())
    }
} // impl Rpn for RPN


fn makeArray (rpn: &mut RPN) -> Bresult<()> {
    let n = rpn.popArgCount()?;
    let mut v = Vec::new();
    for _ in 0..n { v.push( rpn.pop()? ) }
    rpn.push(Value::from(v))
}

fn makeDictionary (rpn: &mut RPN) -> Bresult<()> {
    let n = rpn.popArgCount()?;
    let mut j = json!({});
    let db = &rpn.env.lock().unwrap().jsondb[rpn.key];
    for _ in 0..n {
       let key = rpn.pop()?;
       let keys = key.as_str().ok_or("keyNotStr")?;
       j[keys] = db[keys].clone();
    }
    rpn.push( j )
}

fn has (rpn: &mut RPN) -> Bresult<()> {
    let key = rpn.peek(0)?;
    let blob = rpn.peek(1)?;

    let ret =
    if key.as_str()
       .map(|s| Some('/') == s.chars().next())
       .unwrap_or(false)
    {
        Ok(blob.pointer(key.as_str().unwrap()).map(|_v|Value::Bool(true)).unwrap_or_else(||Value::Bool(false)))
    } else {
        if blob.is_array() {
            blob.as_array()
            .ok_or("impossible".into()) // result
            .and_then( |ary|              //result
                asNum::<usize>(&key) // result
                .and_then( |k|       //result
                    Ok(ary.get(k)
                    .map( |_v| Value::Bool(true) )
                    .unwrap_or_else(||Value::Bool(false)))))
        } else if blob.is_string() {
            blob.as_str()
            .ok_or("impossible".into())
            .and_then( |s|
                asNum::<usize>(&key)
                .and_then( |k|
                    Ok(s.chars()
                    .nth(k)
                    .map(|_c| Value::Bool(true) )
                    .unwrap_or_else(||Value::Bool(false) ) )))
        } else if blob.is_object() {
            blob.as_object()
            .ok_or("impossible".into())
            .and_then( |o|
                Ok(o.get(&key.to_str())
                .map(|_c| Value::Bool(true) )
                .unwrap_or_else(||Value::Bool(false))))
        } else {
            Err("badBlob".into())
        }
    }?;
    rpn.popPush(1, ret)
}

fn lookup (rpn: &mut RPN) -> Bresult<()> {
    let key = rpn.peek(0)?;
    let blob = rpn.peek(1)?;

    let ret =
    if key.as_str()
       .map(|s| Some('/') == s.chars().next())
       .unwrap_or(false)
    {
        blob.pointer(key.as_str().unwrap()).map(|v|v.clone()).ok_or("badPath".into())
    } else {
        if blob.is_array() {
            blob.as_array()
            .ok_or("impossible".into())
            .and_then( |ary|
                asNum::<usize>(&key)
                .and_then( |k|
                    ary.get(k)
                    .map( |v| v.clone() )
                    .ok_or("arrayBadIndex".into()) ) )
        } else if blob.is_string() {
            blob.as_str()
            .ok_or("impossible".into())
            .and_then( |s|
                asNum::<usize>(&key)
                .and_then( |k|
                    s.chars()
                    .nth(k)
                    .map(|c| Value::from(c.to_string()) )
                    .ok_or("stringBadIndex".into()) ) )
        } else if blob.is_object() {
            blob.as_object()
            .ok_or("impossible".into())
            .and_then( |o|
                o.get(&key.to_str())
                .map( |v| v.clone())
                .ok_or("badKey".into()) )
        } else {
            Err("badBlob".into())
        }
    }?;
    rpn.popPush(2, ret)
}

fn insertDictionary (rpn: &mut RPN) -> Bresult<()> {
    rpn.peek(2).map_err( |_|"underflow" )?;
    let key = rpn.pop()?;
    rpn.peekMut(0)?[key.as_str().ok_or("keyBad")?] = rpn.pop()?;
    Ok(())
}

fn arrayPush (rpn: &mut RPN) -> Bresult<()> {
    rpn.peek(1).map_err( |_|"underflow" )?;
    let val = rpn.pop()?;
    rpn.peekMut(0)?.as_array_mut().ok_or("notArray")?.push(val);
    Ok(())
}

fn arrayPop (rpn: &mut RPN) -> Bresult<()> {
    let a = rpn.peekMut(0).map_err( |_|"underflow" )?;
    let v = a.as_array_mut().ok_or("not array")?.pop().ok_or("empty array")?;
    rpn.push(v)?;
    Ok(())
}

fn concat (rpn: &mut RPN) -> Bresult<()> {
    rpn.peek(1).map_err( |_|"underflow" )?;
    let b = rpn.pop()?;
    let a = rpn.pop()?;
    rpn.push( (a.to_str() + &b.to_str()).into() )
}

fn length (rpn: &mut RPN) -> Bresult<()> {
    let a = rpn.peek(0).map_err( |_|"underflow" )?;
    let l = a.as_array().ok_or("not array")?.len();
    rpn.push( Value::from(l) )
}

fn format (rpn: &mut RPN) -> Bresult<()> {
    rpn.pop()?
    .as_str().ok_or("notFormString".into())
    .map(|s| s.split("{}"))
    .and_then( |mut fmts| {
        let first = format!("{}", fmts.next().unwrap_or("{noFirst}"));
        let res = fmts.fold(
            first,
            |r, a|
                r + &rpn.pop()
                    .map(|v|v.to_str())
                    .unwrap_or_else( |e| e.to_string())
                + a
        );
        rpn.push( res.into() )
    })
}

async fn web (rpn: &mut RPN<'_>) -> Bresult<()> {
    let j = rpn.peek(0)?;
    let url = rpn.peek(1)?;
    let res = httpsjson(&url, &j).await;
    rpn.popPush(2, res?.into())
}

fn run (rpn: &mut RPN<'_>) -> Bresult<()>
{
    let newProg = Prog::new( rpn.pop()?.as_str().ok_or("notString")? );
    rpn.prog.push(newProg);
    Ok(())
}

fn trinary (rpn: &mut RPN<'_>) -> Bresult<()>
{
    rpn.peek(2)?;
    let f = rpn.pop()?;
    let t = rpn.pop()?;
    let boolVal = rpn.pop()?;

    let code = if 0.0 == asNum::<f64>(&boolVal)? { f } else { t };

    rpn.prog.push( Prog::new( code.as_str().ok_or("notString")? ) );
    Ok(())
}

fn lookupRun (rpn: &mut RPN<'_>, sym: &str) -> Bresult<()>
{
    let env = rpn.env.lock().unwrap();
    let db = env.jsondb.get(rpn.key).unwrap();

    if Some(':') == sym.chars().next() {
        let code =
            db.get(&sym[1..]).ok_or("{lookupFail}")?
            .as_str().ok_or("notString")?;
        let prog = Prog::new(code);
        Ok(rpn.prog.push(prog))
    } else {
        rpn.push( db[sym].clone() )
    }
}

async fn opOrLookup (rpn: &mut RPN<'_>, sym :&str) -> Bresult<()>
{
    match sym {
        "&" => rpn.apply( |a:u64, b:u64| b & a ),
        "^" => rpn.apply( |a:u64, b:u64| b ^ a ),
        "|" => rpn.apply( |a:u64, b:u64| b | a ),
        "=="=> rpn.apply( |a:f64, b:f64| if b==a{1.0}else{0.0} ),
        "+" => rpn.apply( |a:f64, b:f64| b+a ),
        "-" => rpn.apply( |a:f64, b:f64| b-a ),
        "*" => rpn.apply( |a:f64, b:f64| b*a ),
        "/" => rpn.apply( |a:f64, b:f64| b/a ),
        "=" => rpn.assign(),           // val key =        =>  DB[key]=val
        "/=" => rpn.pathAssign(),      // val /a/2 /=      =>  DB[a][2] = val
        "/." => rpn.pathLookup(),      // /a/2 /.          =>  DB[a][2]
        "."  => lookup(rpn),           // a i .            =>  a[i] on array, obj, or string
        ":has" => has(rpn),            // {a:1} 'b :has    =>  {a:1} false
        ":psh" => arrayPush(rpn),      // [] 1             =>  [1]
        ":pop" => arrayPop(rpn),       // [1 2]            =>  [1] 2
        ":ary" => makeArray(rpn),      // 10 12 14 3 :ary     =>  [14 12 10]
        ":dic" => makeDictionary(rpn), // 'x 'y 2 :dic     =>  {"x":1,"y"2} values from DB or null
        ":ins" => insertDictionary(rpn),// {} val key :ins =>  {key:val}
        ":con" => concat(rpn),         // 'a 'b :con       =>  "ab"
        ":len" => length(rpn),         // [10 11] :len     =>  [10 11] 2
        ":fmt" => format(rpn),         // 1 2 "{}a{}" :fmt =>  "2a1"
        ":web" => web(rpn).await,      // a.com {} :web    =>  POST {} to a.com
        ":run" => run(rpn),            // "1 2 +" :run     =>  3
        "?"    => trinary(rpn),        // b t f ?          =>  :run's t if b is 1, otherwise :run f
        ":now" => rpn.push( Value::from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) ), // epoch seconds
        _      => lookupRun(rpn, sym)
    }
}

////////////////////////////////////////////////////////////////////////////////

async fn do_eval<'a> (env: &'a Env, key: &'a str, prog: &str) -> Bresult<RPN<'a>> {
    let mut rpn = RPN::new(env, key, prog);
    loop {
        let atom = rpn.cap();
        match atom {
          None => break Ok(rpn),
          Some(Atom::Val(v)) => rpn.push(v),
          Some(Atom::Sym(v)) =>
            opOrLookup(&mut rpn, &v.as_str().unwrap()).await
            .map_err( |e| {
                // Push token, error, and rest of program tokens
                rpn.push(v).ok();
                rpn.push(format!("{{{}}}", e.to_string()).into()).ok();

                while let Some(atom) = rpn.cap() {
                    rpn.push( match atom { Atom::Val(v) => v, Atom::Sym(v) => v } ).ok();
                }

                Box::<dyn Error>::from( // Format stack into simple string error
                    rpn.stk()
                    .into_iter()
                    .fold(String::new(), |r,a| r + " " + &a.to_str()) )
            })
        }?;

        if 100 < rpn.prog.len() {
            while let Some(atom) = rpn.cap() {
                rpn.push( match atom { Atom::Val(v) => v, Atom::Sym(v) => v } ).ok();
            }

            return Err(Box::<dyn Error>::from( // Format stack into simple string error
                rpn.stk()
                .into_iter()
                .fold(String::new(), |r,a| r + " " + &a.to_str()) ))
        }
    }
}

async fn handler_rpn (env: &Env, key: &str, body: &str) -> HttpResponse {
    match do_eval(env, key, body).await {
        Ok(rpn) => {
            let val = match rpn.stk.len() {
                 1 =>  rpn.stk[0].clone(),
                 _ =>  Value::from(rpn.stk)
            };
            httpResponseOkBody(val.to_str())
        },
        Err(err) => {
            let resv = json!({
                "body": body,
                "error":err.to_string()
            });
            httpResponseNotAcceptableJson(resv)
        }
    }
}

async fn loghackers (req: HttpRequest, body: web::Bytes) -> HttpResponse {
    dbReq(&req, &body);
    let env = req.app_data::<web::Data<Env>>().unwrap();

    // Maybe log this request
    if let Some(loggingEndpointUrl) = env.lock().unwrap().jsondb["public"]["logging"].as_str() {
       lgReq(&req, &body, &loggingEndpointUrl).await.ok();
    } else {
        warn!("no remote logging endpoint /public/logging\n");
    }
    httpResponseNotFound()
}

async fn handler (path: &str, req: &HttpRequest, body: web::Bytes) -> HttpResponse {
    dbReq(&req, &body);
    let env = req.app_data::<web::Data<Env>>().unwrap();

    let (key, pointer) = path.split_at(path.find('/').unwrap_or(path.len()));

    // Maybe log this request
    if let Some(remoteLogUrl) = env.lock().unwrap().jsondb[key]["logging"].as_str() {
       lgReq(&req, &body, &remoteLogUrl).await.ok();
    }

    let body = from_utf8(&body);

    // RESTful JSON pointer lookup
    if pointer != "" {
        let contentType = env.lock().unwrap().jsondb[key]["Content-Type"].as_str().map(|s|s.to_string());
        return match env.lock().unwrap().jsondb.pointer(&("/".to_string()+path)) {
            Some(v) => httpResponseOkJsonContentType(&v, contentType),
            None => httpResponseNotAcceptableJson(Value::Null)
       }
    }

    // Consider HTTP request body as JSON, or treat as plaintext to evaluate in RPN
    let value = if req.content_type().find("json").is_some() {
        match body.map_err(|e|e.to_string()).and_then(|b|serde_json::from_str(&b).map_err(|e|e.to_string())) {
            Err(e) => {
                let resv = json!({
                    "body": body.unwrap(),
                    "error":e.to_string()
                });
                return httpResponseBadRequestJson(resv);
            },
            Ok(value) => value
        }
    } else {
        return handler_rpn(env, key, &body.unwrap()).await
    };

    match &value {
      Value::Object(js) => {
        let gdb = &mut env.lock().unwrap().jsondb;
        let db = &mut gdb[key];
        js.keys().for_each( |k| db[k] = js[k].clone() );
        if db.is_null() { gdb[key] = json!({}) } // Prevent null DB
        let len :Value = js.len().into();
        httpResponseOkJsonContentType(&len, None)
      },
      Value::Array(js) => {
        let db = &env.lock().unwrap().jsondb[key];
        let mut resv = json!({});
        let res = resv.as_object_mut().unwrap();

        for k in js {
            let k = k.to_str();
            let v = db[&k].clone();
            res.insert(k.into(), v);
        }
        if res.len() == 0 {
            resv = db.clone();
        }
        httpResponseOkJsonContentType(&resv, None)
      },
      Value::String(js) => handler_rpn(env, key, &js.as_str()).await,
      _ => {
        let resv = json!({
            "body": value.to_string(),
            "error":"Unaccepted JSON form."
        });
        httpResponseNotAcceptableJson(resv)
      }
    }
}

async fn jsonDbV1Public (req: HttpRequest, body: web::Bytes) -> HttpResponse {
    let key = "public";
     handler(key, &req, body).await
}

async fn jsonDbV1 (req: HttpRequest, body: web::Bytes) -> HttpResponse {

    let key = {
        let path = req.path();
        match
            Regex::new(r#"^/jsondb/v1/(.+)$"#)
            .map_err(|e| e.to_string())
            .and_then(|re| re.captures(path).ok_or("Bad Key".into()))
            .and_then(|cap| cap.get(1).ok_or(String::new()))
        {
            Ok(key) => key.as_str(),
            Err(s) => { return HttpResponse::BadRequest().body(s) }
        }
    };

    handler(key, &req, body).await
}


////////////////////////////////////////////////////////////////////////////////

async fn launch () -> Bresult<()> {
    println!("::launch");

    let mut ssl_acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    ssl_acceptor_builder.set_private_key_file(
        env::var_os("KEYPEM").as_ref().ok_or("Bad KEYPEM path")?,
        SslFiletype::PEM
    )?;
    ssl_acceptor_builder.set_certificate_chain_file(
        env::var_os("CRTPEM").as_ref().ok_or("Bad CRTPEM path")?
    )?;
    let env = EnvStruct::new(
        env::var_os("JSONDB")
            .as_ref()
            .and_then(|s|s.to_str())
            .unwrap_or("db.json")
            .to_string())?;

    env.lock().map(|e| info!("{} {}", e.dbfile, e.jsondb.to_string())).map_err(|e|e.to_string())?;

    let envc = env.clone();
    HttpServer::new(move ||
        App::new()
        .app_data(web::Data::new(envc.clone()))
        .service(web::resource("/jsondb/v1/{tail:.*}").route(Route::new().to(jsonDbV1)))
        .service(web::resource("/"                   ).route(Route::new().to(jsonDbV1Public)))
        .service(web::resource("{tail:.*}"           ).route(Route::new().to(loghackers)))
    ).bind_openssl( //.bind("0.0.0.0:4441")?
        format!("0.0.0.0:{}", env::var( "DBPORT" ).as_deref().unwrap_or("4441")),
        ssl_acceptor_builder)?
    .shutdown_timeout(60)
    .run()
    .await?;

    // Save DB
    let envl = env.lock().map_err(|e|e.to_string())?;
    let db = envl.jsondb.to_string();
    std::fs::write(&envl.dbfile, &db)?;
    info!("{} {}\n--launch", envl.dbfile, db);
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////

#[actix_web::main]
async fn main() {
    logger_init();
    println!("::main");
    println!("--main {:?}", launch().await);
}
