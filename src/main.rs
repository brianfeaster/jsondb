#![allow(non_snake_case)]

use std::{
    env,
    io::{Write},
    error::Error,
    str::{from_utf8},
    time::{Duration, SystemTime, UNIX_EPOCH}, sync::{RwLockReadGuard, RwLockWriteGuard, RwLock}};

use log::{
  //error,
    error, warn, info, Record,
    Level::{self, Warn, Info, Debug, Trace}};

use env_logger::fmt::{Formatter, style::{Color, AnsiColor::*}};

use ::openssl::ssl::{
    SslAcceptor, SslFiletype, SslMethod, SslRef, SslAlert, SniError, NameType};

use actix_web::{
    web::{to, Bytes, Data}, App, HttpRequest, HttpMessage, HttpServer, HttpResponse,
    http::header::HeaderMap};

use awc::{Client, ClientResponse};

use serde_json::{json, Value};
use regex::{Regex};


////////////////////////////////////////////////////////////////////////////////

pub type Res<T> = Result<T, Box<dyn Error>>;

#[macro_export] 
macro_rules! IF {
    ($p:expr, $t:expr, $f:expr) => (if $p { $t } else { $f })
} 

fn dbport () -> String {
    env::var("DBPORT").as_deref().unwrap_or("4442").into()
}

////////////////////////////////////////////////////////////////////////////////

trait IntoString<T, E> {
    fn okstring(self) -> Result<String, E>;
    fn errstring(self) -> Result<T, String>;
}

impl<T, E> IntoString<T, E> for Result<T, E>
where T: ToString, E: ToString
{
    fn errstring(self) -> Result<T, String> {
        self.map_err(|e| e.to_string())
    }
    fn okstring(self) -> Result<String, E> {
        self.map(|r| r.to_string())
    }
}

fn logger_formatter (buf: &mut Formatter, rec: &Record) -> std::io::Result<()> {
    let level = rec.level();
    let style = buf
        .default_level_style(level)
        .fg_color( match level {
            Level::Error => Some(Color::Ansi(Red)),
            Warn  => Some(Color::Ansi(Yellow)),
            Info  => Some(Color::Ansi(Green)),
            Debug => Some(Color::Ansi(Cyan)),
            Trace => Some(Color::Ansi(Magenta))
        });
    writeln!(buf, "{style}{}{} {:?}", /*rec.level()*/ rec.target(), rec.line().unwrap_or(0), rec.args())
}

fn logger_init () {
    env_logger::builder()
    .format(logger_formatter)
    .init();
}

pub fn bytes2json (body: &[u8]) -> Res<Value> {
    Ok( serde_json::from_str( from_utf8(&body)? )? )
}

fn headersPretty (hm: &HeaderMap) -> String {
    hm.iter()
    .map(|(k,v)| format!("\x1b[0m {}:\x1b[1;30m{}", k, v.to_str().unwrap_or("?")))
    .collect::<Vec<String>>()
    .join("")
}

fn reqPretty (req: &HttpRequest, body: &Bytes) -> String {
    format!("\x1b[1;35m{} {:?} {} \x1b[22m{:?} \x1b[33;100m{}{}",
        req.peer_addr().map(|sa|sa.ip().to_string()).as_deref().unwrap_or("?"),
        req.version(),
        req.method(),
        req.uri(),
        from_utf8(body).okstring().unwrap_or_else(|_|format!("{:?}", body)),
        headersPretty(req.headers()))
}

fn resPretty (res: &HttpResponse, body: &str) -> String {
    let prettyBody = {
        let bdy = body.replace("\n"," \x1b7\x08\x1b[43m \x1b8");
        let len = bdy.chars().count();
        if 1024 < len {
            bdy.chars().take(512).collect::<String>() + &" ... " + &bdy.chars().skip(len-512).collect::<String>()
        } else {
            bdy
        }
    };
    format!("\x1b[1;35m{} \x1b[0;33;100m{}{}",
        res.status(),
        prettyBody,
        headersPretty(res.headers()))
}

fn outPretty (url: &str, body: &str) -> String {
    format!("<= \x1b[34m{} \x1b[33;100m{}", url, body.replace("\n"," \x1b7\x08\x1b[43m \x1b8"))
}

fn inPretty<T> (resp: &ClientResponse<T>,  body: &str) -> String {
    format!("=> \x1b[34m{:?} {} \x1b[33;100m{}{}",
        resp.version(),
        resp.status(),
        body.replace("\n"," \x1b7\x08\x1b[43m \x1b8"),
        headersPretty(resp.headers()))
}

////////////////////////////////////////////////////////////////////////////////

async fn webhttps (url: &Value, val: &Value) -> Res<Value> {
    let url = url.as_str().ok_or(format!("{{notStringy {:?}}}", url))?;
    info!("{}", outPretty(url, &val.to_string()));
    let mut res = if val.is_null() {
        Client::default()
        .get(url)
        .timeout(Duration::new(90,0))
        .send()
        .await?
    } else {
        Client::default()
        .post(url)
        .insert_header(("User-Agent", "JsonDb"))
        .timeout(Duration::new(90,0))
        .send_json(&val) // ClientRequest
        .await? // ClientResponse
    };
    let body = from_utf8(&res.body().await?)?.to_string();
    info!("{}", inPretty(&res, &body));
    Ok(if body.is_empty() { Value::Null } else { serde_json::from_str(&body)? })
}

async fn httpsbody (url: &str, body: &str) -> Res<String> {
    info!("  {}", outPretty(url, body));
    let mut res =
        Client::default()
        .post(url)
        .insert_header(("User-Agent", "JsonDb"))
        .timeout(Duration::new(90,0))
        .send_body(body.to_string()).await?;
    let body = from_utf8(&res.body().await?)?.to_string();
    info!("  {}", inPretty(&res, &body));
    Ok(body)
}

// Log remotely incoming request details
async fn logRemote (req: &HttpRequest, body: &Bytes, url: &str) -> Res<String> {
    httpsbody(
        &url,
        &format!("{} {}:{} {}\n{}",
            req.headers().get(actix_web::http::header::USER_AGENT).and_then(|hv|hv.to_str().ok()).unwrap_or("?"),
            req.peer_addr().map(|sa|sa.ip().to_string()).unwrap_or("?".into()),
            dbport(),
            req.path(),
            from_utf8(body).unwrap_or("?")))
    .await
}

async fn logErrorRemote (req: &HttpRequest, body: &Bytes, val: &Value, url: &str) -> Res<String> {
    httpsbody(
        &url,
        &format!("!!! ERROR DETECTED !!!\n{} {} {}\n{}\n{:?}",
            req.headers().get(actix_web::http::header::USER_AGENT).and_then(|hv|hv.to_str().ok()).unwrap_or("?"),
            req.peer_addr().map(|sa|sa.ip().to_string()).unwrap_or("?".into()),
            req.path(),
            from_utf8(body).unwrap_or("?"),
            val))
    .await
}

////////////////////////////////////////////////////////////////////////////////
// https://docs.rs/http/0.2.8/src/http/status.rs.html

pub fn httpResponseOkBody (body: String) -> HttpResponse {
    let mut resp = HttpResponse::Ok().body(body.clone());
    info!("{}", resPretty(&mut resp, &body));
    resp
}
pub fn httpResponseOkBodyHeaders (body: String, headers: &[(&str, &str)]) -> HttpResponse {
    let mut respbuilder = HttpResponse::Ok();
    for header in headers { respbuilder.insert_header(*header); }
    let resp = respbuilder.body(body.clone());
    info!("{}", resPretty(&resp, &body));
    resp
}

fn httpResponseOkJsonContentType (val: &Value, headers: &Value) -> HttpResponse {
    let mut resp = HttpResponse::Ok();
    let mut isJson = false;

    headers.as_object().map(|headers| headers.iter().for_each(|(k,v)| {
        v.as_str().map(|s| {
           if s.find("json").is_some() { isJson = true }
           resp.insert_header((&k[..], s));
        });
    }));

    let resp = if headers.is_object() && isJson {
        resp.json(val.clone())
    } else {
        resp.body(val.to_str_alt())
    };

    info!("{}", resPretty(&resp, &val.to_str_alt()));
    resp
}

fn httpResponseNotFound () -> HttpResponse {
    let resp = HttpResponse::NotFound().finish();
    error!("{}", resPretty(&resp, &""));
    resp
}

fn httpResponseNotAcceptableJson (val: Value) -> HttpResponse {
    let s = val.to_str_alt();
    let resp = HttpResponse::NotAcceptable().json(val);
    error!("{}", resPretty(&resp, &s));
    resp
}

fn httpResponseNotAcceptable (msg: String) -> HttpResponse {
    let resp = HttpResponse::NotAcceptable().body(msg.to_string());
    error!("{}", resPretty(&resp, &msg));
    resp
}

fn httpResponseBadRequestJson (val: Value) -> HttpResponse {
    let s = val.to_str_alt();
    let resp = HttpResponse::BadRequest().json(val);
    error!("{}", resPretty(&resp, &s));
    resp
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct Env {
    db_filename: String,
    db: RwLock<Value> // The base JSON dictionary (holds every user database)
}

impl Env {
    fn new(db_filename: &str) -> Res<Env> {
        Ok(Env{
            db_filename: db_filename.to_string(),
            db: RwLock::new(serde_json::from_str(
                std::fs::read_to_string(db_filename)
                    .as_deref()
                    .map_err(|e| warn!("{:?}", e))
                    .unwrap_or(r#"{}"#))?)})
    }
    fn db_rlock(&self) -> Result<RwLockReadGuard<'_, Value>, String> {
        Ok(self.db.read().errstring()?)
    }
    fn db_wlock(&self) -> Result<RwLockWriteGuard<'_, Value>, String> {
        Ok(self.db.write().errstring()?)
    }
    // Generate list of database names and size
    fn db_names (&self) -> Res<Vec<String>> {
        Ok(self.db_rlock()?
        .as_object()
        .ok_or("DB not json object")?
        .iter()
        .map(|(k,v)| format!("{}:{}",
            k.to_string(),
            v.as_object()
                .map(|o| o.len().to_string())
                .unwrap_or("?".into())))
        .collect::<Vec<String>>())
    }
}

////////////////////////////////////////////////////////////////////////////////

trait ToNum<T> { fn toNum (&self) -> Res<T>; }

impl ToNum<usize> for Value {
    fn toNum (&self) -> Res<usize> {
        self.as_u64()
        .or_else(
            || self.as_f64()
            .map(|n|n as u64) )
        .map(|n| n as usize)
        .ok_or("{notUsizeable}".into())
    }
}

impl ToNum<isize> for Value {
    fn toNum (&self) -> Res<isize> {
        self.as_i64()
        .or_else(
            || self.as_f64()
            .map(|n|n as i64) )
        .map(|n| n as isize)
        .ok_or("{notIsizeable}".into())
    }
}

impl ToNum<u64> for Value {
    fn toNum (&self) -> Res<u64> {
        self.as_u64()
        .or_else(
            || self.as_f64()
            .map(|n|n as u64) )
        .ok_or("{notU64able}".into())
    }
}

impl ToNum<f64> for Value {
    fn toNum (&self) -> Res<f64> {
        self.as_f64()
        .ok_or("{notF64able}".into())
    }
}

////////////////////////////////////////////////////////////////////////////////

trait ToStr {
  fn to_str_alt (&self) -> String;
}

impl ToStr for Value {
  fn to_str_alt (&self) -> String {
    self.as_str()
    .map(<str>::to_string)
    .unwrap_or_else(||self.to_string())
  }
}

////////////////////////////////////////////////////////////////////////////////

fn asNum<T> (value: &Value) -> Res<T>
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
            ( \s | ;[^\n]*(\n|$) )*       # comment
            (                             # any 3
                (-?\d*[.]\d+ | -?\d+[.]?)\s # number 4
                | ("( \\" | [^"] )*")       # string 5
                | ([^\s;]+) )               # symbol 7
            ( \s | ;[^\n]*(\n|$) )*       # comment
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
    fn lookup (&self, sym: &str) -> Result<Value, String>;
    fn stkLen (&self) -> usize;
    fn stk (&mut self) -> &mut Vec<Value>;
    fn pop (&mut self) -> Res<Value>;
    fn push (&mut self, v: Value) -> Res<()>;
    fn popPush (&mut self, count: usize, v: Value) -> Res<()>;
    fn peek (&self, i: usize) -> Res<& Value>;
    fn peekMut (&mut self, i: usize) -> Res<&mut Value>;
    fn peekAsNum<U> (&self, i: usize) -> Res<U>
    where
        U: From<u8>,
        Value: ToNum<U>;
    fn popArgCount (&mut self) -> Res<usize>;
    fn apply<F,U> (&mut self, f: F) -> Res<()>
    where
        Value: From<U> + ToNum<U>,
        U: From<u8>,
        F: Fn(U,U)->U;
    fn assign(&mut self) -> Res<()>;
    fn pathAssign (&mut self) -> Res<()>;
    fn pathLookup (&mut self) -> Res<()>;
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
    fn lookup (&self, sym: &str) -> Result<Value, String> {
        self.env
            .db_rlock()
            .map(|db| db[self.key][sym].clone())
    }
    fn stkLen (&self) -> usize { self.stk.len() }
    fn stk (&mut self) -> &mut Vec<Value> { &mut self.stk }
    fn pop (&mut self) -> Res<Value> {
        self.stk()
        .pop()
        .ok_or("popUnderflow".into())
    }
    fn push (&mut self, v: Value) -> Res<()> {
        Ok(self.stk().push(v))
    }
    fn popPush (&mut self, count: usize, v: Value) -> Res<()> {
        let len = self.stkLen();
        if len < count { Err("popPushUnderflow".into()) }
        else {
            self.stk().truncate(len - count);
            self.push(v)
        }
    }
    fn peek (&self, i: usize) -> Res<&Value> {
        let len = self.stkLen();
        if len <= i { Err("peekUnderflow")? }
        Ok(&self.stk[len-i-1])
    }
    fn peekMut (&mut self, i: usize) -> Res<&mut Value> {
        let len = self.stkLen();
        if len <= i { Err("peekMutUnderflow")? }
        Ok(&mut self.stk()[len-i-1])
    }
    fn peekAsNum<U> (&self, i: usize) -> Res<U>
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
    fn popArgCount (&mut self) -> Res<usize> {
        let n = self.peekAsNum::<usize>(0)?;
        self.peek(n)?;
        self.pop()?;
        Ok(n)
    }
    fn apply<F,U>(&mut self, f:F) -> Res<()>
    where
        Value: From<U> + ToNum<U>,
        U: From<u8>,
        F: Fn(U,U)->U,
    {
        let a = self.peekAsNum(0)?;
        let b = self.peekAsNum(1)?;
        self.popPush(2, f(a,b).into())
    }
    fn assign(&mut self) -> Res<()>
    {
        self.peek(1)?;
        let key = self.pop()?;
        let val = self.pop()?;
        self.env.db_wlock()?[self.key][key.as_str().ok_or("assignKeyBad")?] = val;
        Ok(())
    }
    fn pathAssign(&mut self) -> Res<()>
    {
        let path = self.peek(0)?.as_str().ok_or("pathNotStr")?;
        let val  = self.peek(1)?.clone();

        self.env.db_wlock()?[self.key]
        .pointer_mut(path)
        .map(|v| *v = val)
        .ok_or("badPath")?;

        self.pop()?;
        self.pop()?;
        Ok(())
    }
    fn pathLookup(&mut self) -> Res<()>
    {
        let path = self.peek(0)?.as_str().ok_or("pathNotStr")?;
        let ret =
            self.env.db_rlock()?[self.key]
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


fn makeArray (rpn: &mut RPN) -> Res<()> {
    let n = rpn.popArgCount()?;
    let mut v = Vec::new();
    for _ in 0..n { v.push( rpn.pop()? ) }
    rpn.push(Value::from(v))
}

fn makeDictionary (rpn: &mut RPN) -> Res<()> {
    let n = rpn.popArgCount()?;
    let mut j = json!({});
    let db = &rpn.env.db_rlock()?[rpn.key];
    for _ in 0..n {
       let key = rpn.pop()?;
       let keys = key.as_str().ok_or("keyNotStr")?;
       j[keys] = db[keys].clone();
    }
    rpn.push(j)
}

fn swp (rpn: &mut RPN) -> Res<()> {
    let a = rpn.pop()?;
    let b = rpn.pop()?;
    rpn.push(a)?;
    rpn.push(b)
}

fn has (rpn: &mut RPN) -> Res<()> {
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
                Ok(o.get(&key.to_str_alt())
                .map(|_c| Value::Bool(true) )
                .unwrap_or_else(||Value::Bool(false))))
        } else {
            Err("badBlob".into())
        }
    }?;
    rpn.popPush(1, ret)
}

fn subAss (rpn: &mut RPN) -> Res<()> {
    let val = rpn.peekAsNum::<f64>(1)?;
    let sym = rpn.peek(0)?.as_str().ok_or("assignKeyBad")?;

    let db = &mut rpn.env.db_wlock()?[rpn.key];

    let o = if Some('/') == sym.chars().next() {
        db.pointer_mut(sym).ok_or("pathBad")?
    } else {
        &mut db[sym]
    };
    *o = Value::from(ToNum::<f64>::toNum(o)? - val);
    rpn.popPush(2, o.clone())
}

fn addAss (rpn: &mut RPN) -> Res<()> {
    let val = rpn.peekAsNum::<f64>(1)?;
    let sym = rpn.peek(0)?.as_str().ok_or("assignKeyBad")?;

    let db = &mut rpn.env.db_wlock()?[rpn.key];

    let o = if Some('/') == sym.chars().next() {
        db.pointer_mut(sym).ok_or("pathBad")?
    } else {
        &mut db[sym]
    };
    *o = Value::from(ToNum::<f64>::toNum(o)? + val);
    rpn.popPush(2, o.clone())
}

fn lookup (rpn: &mut RPN) -> Res<()> {
    let key = rpn.peek(0)?;
    let blob = rpn.peek(1)?;

    let ret = if key.as_str()
       .map(|s| Some('/') == s.chars().next())
       .unwrap_or(false)
    {
        blob.pointer(key.as_str().unwrap()).map(|v|v.clone()).ok_or("badPath".into())
    } else {
        if blob.is_array() {
            blob.as_array()
            .ok_or("impossible".into())
            .and_then( |ary|
                asNum::<isize>(&key)
                .and_then( |k|
                    ary.get(IF!(k<0, blob.as_array().unwrap().len() as isize+k, k) as usize)
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
                o.get(&key.to_str_alt())
                .map( |v| v.clone())
                .ok_or("badKey".into()) )
        } else {
            Err("badBlob".into())
        }
    }?;
    rpn.popPush(2, ret)
}

fn insertDictionary (rpn: &mut RPN) -> Res<()> {
    rpn.peek(2).map_err( |_|"underflow" )?;
    let key = rpn.pop()?;
    rpn.peekMut(0)?[key.as_str().ok_or("keyBad")?] = rpn.pop()?;
    Ok(())
}

fn arrayPush (rpn: &mut RPN) -> Res<()> {
    rpn.peek(1).map_err( |_|"underflow" )?;
    let val = rpn.pop()?;
    rpn.peekMut(0)?.as_array_mut().ok_or("notArray")?.push(val);
    Ok(())
}

fn dup (rpn: &mut RPN) -> Res<()> {
    let v = rpn.peek(0).map_err( |_|"underflow" )?;
    rpn.push(v.clone())?;
    Ok(())
}

fn popAny (rpn: &mut RPN) -> Res<()> {
    let v = match rpn.peekMut(0).map_err( |_|"underflow" )? {
      Value::Array(a) => a.pop().ok_or("EMPTY ARRAY")?,
      Value::Object(h) => {
        let k = h.keys().next().ok_or("EMPTY DICT")?.clone();
        let (k,v) = h.remove_entry(&k).ok_or("impossible")?;
        json!([k,v])
      }
      _ => Err("NOT POPABLE")?
    };
    rpn.push(v).ok();
    Ok(())
}

fn concat (rpn: &mut RPN) -> Res<()> {
    rpn.peek(1).map_err( |_|"underflow" )?;
    let b = rpn.pop()?;
    let a = rpn.pop()?;
    rpn.push( (a.to_str_alt() + &b.to_str_alt()).into() )
}

fn length (rpn: &mut RPN) -> Res<()> {
    let a = rpn.peek(0).map_err( |_|"underflow" )?;
    let l = match a {
            Value::Array(a) => a.len(),
            Value::String(a) => a.len(),
            Value::Object(a) => a.len(),
                            _ => Err("not lengthable")?
    };
    rpn.push( Value::from(l) )
}

fn format (rpn: &mut RPN) -> Res<()> {
    rpn.pop()?
    .as_str().ok_or("notFormString".into())
    .map(|s| s.split("{}"))
    .and_then( |mut fmts| {
        let first = format!("{}", fmts.next().unwrap_or("{noFirst}"));
        let res = fmts.fold(
            first,
            |r, a|
                r + &rpn.pop()
                    .map(|v|v.to_str_alt())
                    .unwrap_or_else( |e| e.to_string())
                + a
        );
        rpn.push( res.into() )
    })
}

async fn web (rpn: &mut RPN<'_>) -> Res<()> {
    let j = rpn.peek(0)?;
    let url = rpn.peek(1)?;
    let res = webhttps(&url, &j).await;
    warn!("{:?}", res);
    rpn.popPush(2, res?.into())
}

async fn get (rpn: &mut RPN<'_>) -> Res<()> {
    let j = rpn.peek(0)?.as_str().ok_or("notStr")?;
    let url = rpn.peek(1)?.as_str().ok_or("notAStr")?;
    let res = httpsbody(url, j).await;
    warn!("{:?}", res);
    rpn.popPush(2, res?.into())
}

fn run (rpn: &mut RPN<'_>) -> Res<()>
{
    let newProg = Prog::new( rpn.pop()?.as_str().ok_or("notString")? );
    rpn.prog.push(newProg);
    Ok(())
}

fn trinary (rpn: &mut RPN<'_>) -> Res<()>
{
    rpn.peek(2)?;
    let f = rpn.pop()?;
    let t = rpn.pop()?;
    let boolVal = rpn.pop()?;

    let code = if 0.0 == asNum::<f64>(&boolVal)? { f } else { t };

    rpn.prog.push( Prog::new( code.as_str().ok_or("notString")? ) );
    Ok(())
}

fn lookupRun (rpn: &mut RPN<'_>, sym: &str) -> Res<()>
{

    if Some(':') == sym.chars().next() {
        match sym[1..].parse::<usize>() {
            Ok(u) => rpn.push(rpn.peek(u)?.clone()),
            Err(_) => Ok(rpn.prog.push(
                Prog::new(
                    rpn.lookup(&sym[1..])?
                    .as_str()
                    .ok_or("notString")?)))
        }
    } else {
        rpn.push( rpn.lookup(sym)? )
    }
}

async fn opOrLookup (rpn: &mut RPN<'_>, sym :&str) -> Res<()>
{
    match sym {
        "&" => rpn.apply( |a:u64, b:u64| b & a ),
        "^" => rpn.apply( |a:u64, b:u64| b ^ a ),
        "|" => rpn.apply( |a:u64, b:u64| b | a ),
        "=="=> rpn.apply( |a:f64, b:f64| if b==a{1.0}else{0.0} ),
        "<" => rpn.apply( |a:f64, b:f64| if b<a{1.0}else{0.0} ),
        ">" => rpn.apply( |a:f64, b:f64| if b>a{1.0}else{0.0} ),
        "+" => rpn.apply( |a:f64, b:f64| b+a ),
        "-" => rpn.apply( |a:f64, b:f64| b-a ),
        "*" => rpn.apply( |a:f64, b:f64| b*a ),
        "/" => rpn.apply( |a:f64, b:f64| b/a ),
        "=" => rpn.assign(),           // val key =        =>  DB[key]=val
        "/=" => rpn.pathAssign(),      // val /a/2 /=      =>  DB[a][2] = val
        "/." => rpn.pathLookup(),      // /a/2 /.          =>  DB[a][2]
        "-=" => subAss(rpn),           // val key -=       =>  DB[key]-=val
        "+=" => addAss(rpn),           // val key +=       =>  DB[key]_=val
        "."  => lookup(rpn),           // a i .            =>  a[i] on array, obj, or string
        ":!" => rpn.pop().map(|_|()),  // 1 2 :!           =>  1
        ":swp" => swp(rpn),            // 1 2              =>  2 1
        ":has" => has(rpn),            // {a:1} 'b :has    =>  {a:1} false
        ":dup" => dup(rpn),            // 42               =>  42 42
        ":psh" => arrayPush(rpn),      // [] 1             =>  [1]
        ":pop" => popAny(rpn),       // [1 2]            =>  [1] 2
        ":ary" => makeArray(rpn),      // 10 12 14 3 :ary  =>  [14 12 10]
        ":dic" => makeDictionary(rpn), // 'x 'y 2 :dic     =>  {"x":1,"y"2} values from DB or null
        ":ins" => insertDictionary(rpn),// {} val key :ins =>  {key:val}
        ":con" => concat(rpn),         // 'a 'b :con       =>  "ab"
        ":len" => length(rpn),         // [10 11] :len     =>  [10 11] 2
        ":fmt" => format(rpn),         // 1 2 "{}a{}" :fmt =>  "2a1"
        ":web" => web(rpn).await,      // a.com {} :web    =>  POST {} to a.com
        ":get" => get(rpn).await,      // a.com "..." :get =>  GET "..." to a.com
        ":run" => run(rpn),            // "1 2 +" :run     =>  3
        "?"    => trinary(rpn),        // b t f ?          =>  :run's t if b is 1, otherwise :run f
        ":now" => rpn.push( Value::from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) ), // epoch seconds
        _      => lookupRun(rpn, sym)
    }
}

////////////////////////////////////////////////////////////////////////////////

async fn do_eval_rpn<'a> (env: &'a Env, key: &'a str, prog: &str) -> Res<RPN<'a>> {
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
                    .fold(String::new(), |r,a| r + " " + &a.to_str_alt()) )
            })
        }?;

        if 65535 < rpn.prog.len() {
            while let Some(atom) = rpn.cap() {
                rpn.push( match atom { Atom::Val(v) => v, Atom::Sym(v) => v } ).ok();
            }

            return Err(Box::<dyn Error>::from( // Format stack into simple string error
                rpn.stk()
                .into_iter()
                .fold(String::new(), |r,a| r + " " + &a.to_str_alt()) ))
        }
    }
}

async fn handler_rpn (env: &Env, key: &str, body: &str) -> Res<HttpResponse> {
    Ok(match do_eval_rpn(env, key, body).await {
        Ok(rpn) => {
            httpResponseOkJsonContentType(
                &IF!(1==rpn.stk.len(), rpn.stk[0].clone(), Value::from(rpn.stk)),
                &env.db_rlock()?[key]["Headers"])
        },
        Err(err) =>
            httpResponseNotAcceptableJson(json!({"body":body, "error":err.to_string()}))
    })
}

async fn do_loghackers (req: HttpRequest, body: Bytes) -> Res<HttpResponse> {
    info!("{}", reqPretty(&req, &body));
    let env = req.app_data::<Data<Env>>().ok_or("web data")?;

    // Maybe log this request
    let logging =  env.db_rlock()?["public"]["logging"].clone();
    if let Some(url) = logging.as_str() {
       logRemote(&req, &body, &url).await.ok();
    } else {
        warn!("no remote logging endpoint /public/logging\n");
    }

    Ok(httpResponseNotFound())
}

async fn handler_json (env: &Env, key: &str, value: Value) -> Res<HttpResponse> {
    match &value {
      Value::Object(js) => {
        let len = {
            let jdb = &mut env.db_wlock()?;
            let db = &mut jdb[key];
            js.keys().for_each( |k| db[k] = js[k].clone() );
            if db.is_null() { jdb[key] = json!({}) } // Prevent null DB
            js.len().into()
        };
        Ok(httpResponseOkJsonContentType(&len, &Value::Null))
      },
      Value::Array(js) => {
        let resv =  {
            let db = &env.db_rlock()?[key];
            let mut resv = json!({});
            let res = resv.as_object_mut().unwrap();

            for k in js {
                let k = k.to_str_alt();
                let v = db[&k].clone();
                res.insert(k.into(), v);
            }
            if res.len() == 0 {
                resv = db.clone();
            }
            resv
        };
        Ok(httpResponseOkJsonContentType(&resv, &Value::Null))
      },
      Value::String(js) => handler_rpn(env, key, &js.as_str()).await,
      _ => {
        let resv = json!({
            "body": value.to_string(),
            "error":"Unaccepted JSON form."
        });
        Ok(httpResponseNotAcceptableJson(resv))
      }
    }
}

async fn handler_rest (env: &Env, key: &str, path: &str) -> Res<HttpResponse> {
    Ok(match env.db_rlock()?.pointer(&format!("/{path}")) {
        Some(val) =>
            httpResponseOkJsonContentType(&val, &env.db_rlock()?[key]["Headers"]),
        None =>
            httpResponseNotAcceptableJson(Value::Null)
   })
}

async fn handler (path: &str, req: HttpRequest, bytes: Bytes) -> Res<HttpResponse> {
    println!();
    info!("{}", reqPretty(&req, &bytes));
    let env = req.app_data::<Data<Env>>().ok_or("webdata")?;

    let (key, pointer) = path.split_at(path.find('/').unwrap_or(path.len()));

    // Maybe log this request
    let logUrl = env.db_rlock()?[key]["logging"].as_str().map(<str>::to_string);
    if let Some(ref url) = logUrl {
       logRemote(&req, &bytes, &url).await.ok();
    }

    // RESTful JSON pointer lookup
    if pointer != "" { return handler_rest(env, key, path).await }

    let body = match from_utf8(&bytes) {
        Ok(body) => body,
        Err(e) => return Ok(httpResponseNotAcceptable(format!("body:{}  error:{}", format!("{:?}", bytes), e)))
    };

    // Plaintext body evaluated as RPN
    if req.content_type().find("json").is_none() { return handler_rpn(env, key, &body).await }

    // Consider HTTP request body as JSON
    match serde_json::from_str(&body).map_err(|e|e.to_string()) {
        Err(e) => {
            let resv = json!({"body": body, "error":e.to_string()});
            let logErrUrl = env.db_rlock()?[key]["loggingerror"].as_str().map(<str>::to_string);
            if let Some(url) = logErrUrl {
                logErrorRemote(&req, &bytes, &resv, &url).await.ok();
            }
            Ok(httpResponseBadRequestJson(resv))
        },
        Ok(value) => handler_json(env, key, value).await
    }
}

async fn pre_handler (req: HttpRequest, body: Bytes) -> Res<HttpResponse> {
    let key = 
        Regex::new(r#"^/jsondb/v1/(.+)$"#)?
        .captures(req.path())
        .ok_or("Bad Key".into())
        .and_then(|cap| cap.get(1).ok_or(String::new()))
        .map(|key| key.as_str())?
        .to_string();
    handler(&key, req, body).await
}

////////////////////////////////////////////////////////////////////////////////

async fn jsonDbV1 (req: HttpRequest, body: Bytes) -> HttpResponse {
    match pre_handler(req, body).await {
        Err(err) => HttpResponse::BadRequest().body(err.to_string()),
        Ok(res) => res
    }
}

async fn jsonDbV1Public (req: HttpRequest, body: Bytes) -> HttpResponse {
     match handler("public", req, body).await {
        Err(err) => HttpResponse::BadRequest().body(err.to_string()),
        Ok(res) => res
     }
}

pub async fn sendBigThing (req: HttpRequest, body: Bytes) -> HttpResponse {
    info!("{}", reqPretty(&req, &body));
    let mut bdy = String::new();
    for _ in 0..65536*10 { bdy.push('[') }
    for _ in 0..65536*10 { bdy.push(']') }
    httpResponseOkBodyHeaders(bdy, &[("content-type","application/json")])
}

async fn loghackers (req: HttpRequest, body: Bytes) -> HttpResponse {
    match do_loghackers(req, body).await {
        Err(err) => HttpResponse::BadRequest().body(err.to_string()),
        Ok(res) => res
    }
}

////////////////////////////////////////////////////////////////////////////////

pub fn verifyServerName (crt_pem: &str) -> Res<impl Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError>>
{   
    let mut names = Vec::new();
    let mut ab = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    ab.set_certificate_chain_file(crt_pem)?;
    // Make list of domain names from certificate
    ab.build().context().certificate().map(|cert| {
        // SAN
        cert.subject_alt_names()
        .map( |sans|
            sans.iter()
            .for_each( |gn| {
                gn.dnsname()
                .map( |n|
                    names.push(n.to_string())); } ) );
        // CN
        cert.subject_name().entries()
        .for_each( |xne| {
            from_utf8(xne.data().as_slice())
            .map( |n| names.push(n.to_string()))
            .ok(); } );
    } );
    Ok(move |sr: &mut SslRef, _: &mut SslAlert| {
        let sni = sr.servername(NameType::HOST_NAME).unwrap_or("");
        if !names.iter().any(|n| sni==n) {
            warn!("Rejected SNI '{}'", sni);
            Err(SniError::ALERT_FATAL)
        } else {
            Ok(())
        }
    })
}

async fn main_web_server () -> Res<()> {
    info!("::main_web_server");

    let key_pem = env::var_os("KEYPEM").ok_or("Bad KEYPEM")?.into_string().unwrap();
    let crt_pem = env::var_os("CRTPEM").ok_or("Bad CRTPEM")?.into_string().unwrap();
    let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    acceptor_builder.set_private_key_file(&key_pem, SslFiletype::PEM)?;
    acceptor_builder.set_certificate_chain_file(&crt_pem)?;
    acceptor_builder.set_servername_callback(verifyServerName(&crt_pem)?);

    let env = Data::new(Env::new(
        env::var_os("JSONDB")
            .as_ref()
            .and_then(|s|s.to_str())
            .unwrap_or("db.json"))?);

    info!("{} {}", env.db_filename, env.db_names()?.join(" "));

    let env2 = env.clone();
    HttpServer::new(move ||
            App::new()
                .app_data(env2.clone())
                .route("/jsondb/v1/{tail:.*}", to(jsonDbV1))
                //.route("/",                    to(jsonDbV1Public))
                .route("{tail:.*}",            to(loghackers)))
        .workers(2)
        .bind_openssl(
            format!("0.0.0.0:{}", dbport()),
            acceptor_builder)?
        .shutdown_timeout(60)
        .run()
        .await?;

    // Save DB
    let db = env.db_rlock()?.to_string();
    std::fs::write(&env.db_filename, &db)?;
    info!("{} {}", env.db_filename, env.db_names()?.join(" "));
    info!("--main_web_server");
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////

#[actix_web::main]
async fn main() {
    logger_init();
    info!("::main");
    info!("--main {:?}", main_web_server().await);
}
