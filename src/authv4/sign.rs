extern crate crypto;
extern crate hyper;
extern crate rustc_serialize;
extern crate time;

use credentials::static_creds::Credentials;

use std::ascii::AsciiExt;
use std::io::Read;
use std::str;

use self::crypto::digest::Digest;
use self::crypto::hmac::Hmac;
use self::crypto::mac::Mac;
use self::crypto::sha2::Sha256;
use self::hyper::client::Request;
use self::hyper::net::Fresh;
use self::rustc_serialize::hex::ToHex;

trait Signable {
    fn sign<B: Read>(mut self, Option<B>, String, String, time::Tm, creds: Credentials) -> Self;
}

impl Signable for Request<Fresh> {
    fn sign<B: Read>(mut self,
                     body: Option<B>,
                     region: String,
                     service: String,
                     date: time::Tm,
                     creds: Credentials)
                     -> Request<Fresh> {
        let canonical_path = &self.url.serialize_path().unwrap_or("".to_string());
        let canonical_query = &(self.url.clone().query.unwrap_or("".to_string()));
        let (header_keys, canonical_headers) = canonicalize_headers(self.headers());

        let mut hasher = Sha256::new();
        if let Some(mut b) = body {
            loop {
                let mut buf: [u8; 4096] = [0; 4096];
                let size_read = b.read(&mut buf).unwrap_or(0);
                if size_read == 0 {
                    break;
                }
                hasher.input(&buf[0..size_read]);
            }
        }

        // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        let canonical_request = self.method().as_ref().to_string() + "\n" + canonical_path +
                                "\n" + &canonical_query + "\n" +
                                &canonical_headers.join("\n") +
                                "\n\n" + &header_keys.join(";") +
                                "\n" + &hasher.result_str();

        let mut canonical_request_hasher = Sha256::new();
        canonical_request_hasher.input(&canonical_request.as_ref());

        let ymd = date.to_utc().strftime("%Y%m%d").unwrap().to_string();
        let iso8601 = date.to_utc().strftime("%Y%m%dT%H%M%SZ").unwrap().to_string();

        let string_to_sign = "AWS4-HMAC-SHA256".to_string() + "\n" + iso8601.as_ref() + "\n" +
                             ymd.as_ref() + "/" +
                             region.as_ref() + "/" +
                             service.as_ref() + "/aws4_request" +
                             "\n" +
                             canonical_request_hasher.result_str().as_ref();

        let secret = "AWS4".to_string() + &creds.secret_key;
        let mut kdate = Hmac::new(Sha256::new(), secret.as_bytes());
        kdate.input(ymd.as_bytes());
        let mut kregion = Hmac::new(Sha256::new(), kdate.result().code());
        kregion.input(region.as_bytes());
        let mut kservice = Hmac::new(Sha256::new(), kregion.result().code());
        kservice.input(service.as_bytes());
        let mut ksigning = Hmac::new(Sha256::new(), kservice.result().code());
        ksigning.input("aws4_request".as_bytes());
        let ksigningkey = ksigning.result();

        let mut ksignature = Hmac::new(Sha256::new(), ksigningkey.code());
        ksignature.input(&string_to_sign.as_bytes());
        let ksigresult = ksignature.result();
        let signature = ksigresult.code();

        self.headers_mut()
            .set(Authorization("AWS4-HMAC-SHA256 Credential=".to_string() + &creds.access_key +
                               "/" +
                               &ymd.to_string() + "/" + &region +
                               "/" + &service +
                               "/aws4_request, " + "SignedHeaders=" +
                               &header_keys.join(";") + ", " +
                               "Signature=" + &signature.to_hex()));
        self
    }
}

fn canonicalize_headers(headers: &hyper::header::Headers) -> (Vec<String>, Vec<String>) {
    let mut header_keys: Vec<String> = headers.iter()
                                              .map(|h| h.name().to_string().to_ascii_lowercase())
                                              .collect();
    header_keys.sort();
    let canonical_headers = header_keys.iter()
                                       .map(|key| {
                                           let header_value = headers.get_raw(key)
                                                                     .unwrap();
                                           let strheaders: Vec<String> =
                                               header_value.iter()
                                                           .map(|el| {
                                                               str::from_utf8(el)
                                                                   .unwrap()
                                                                   .trim()
                                                                   .to_string()
                                                           })
                                                           .collect();
                                           key.to_string() + ":" + &strheaders.join(",")
                                       })
                                       .collect();

    (header_keys, canonical_headers)
}

header! { (AmzSecurityToken, "X-Amz-Security-Token") => [String] }
header! { (Authorization, "Authorization") => [String] }
header! { (XAmzTarget, "X-Amz-Target") => [String] }
header! { (XAmzDate, "x-amz-date") => [String] }


#[test]
fn it_signs_an_example_request() {
    use self::hyper::Url;
    use self::hyper::header::{ContentType, UserAgent};
    use self::hyper::method::Method;
    use self::hyper::mime::Mime;
    use std::io::Cursor;

    let credentials = Credentials {
        access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        session_token: "".to_string(),
    };
    let date = time::at(time::Timespec {
        sec: 100,
        nsec: 0,
    });
    let mut req = Request::new(Method::Post,
                               Url::parse("https://ecs.us-east-1.amazonaws.com/").unwrap())
                      .unwrap();

    let xamzjsonmime: Mime = "application/x-amz-json-1.1".parse().unwrap();

    req.headers_mut()
       .set(XAmzTarget("AmazonEC2ContainerServiceV20141113.ListClusters".to_string()));
    req.headers_mut().set(XAmzDate(date.rfc3339().to_string()));
    req.headers_mut().set(ContentType(xamzjsonmime));
    req.headers_mut().set(UserAgent("useragent".to_string()));
    let body = "{}";
    let result = req.sign(Some(Cursor::new(body.as_bytes())),
                          "us-east-1".to_string(),
                          "ecs".to_string(),
                          date,
                          credentials);

    let resulting_sig = result.headers().get::<Authorization>();
    assert_eq!(resulting_sig,
               Some(&Authorization("AWS4-HMAC-SHA256 \
                                    Credential=AKIAIOSFODNN7EXAMPLE/19700101/us-east-1/ecs/aws4\
                                    _request, \
                                    SignedHeaders=content-type;host;user-agent;x-amz-date;\
                                    x-amz-target, \
                                    Signature=dba059855bfec128396fc743b942fb8438e95e8af80497544\
                                    cf5b4c612d423bd"
                                       .to_string())));
}
