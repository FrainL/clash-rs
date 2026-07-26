use std::{collections::HashMap, io, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use tokio::sync::RwLock;

use crate::{
    Error, Result,
    app::{
        dispatcher::BoxedChainedStream,
        dns::{SystemResolver, ThreadSafeDNSResolver},
        outbound::manager::OutboundManager,
    },
    common::http::client::{ClashHTTPClientExt, HttpClient},
    config::internal::proxy::OutboundProxyProtocol,
    proxy::{AnyOutboundHandler, utils::OutboundHandlerRegistry},
    session::{Network, Session, SocksAddr, Type},
};

#[derive(Clone)]
pub struct EmbeddedOutbound {
    handler: AnyOutboundHandler,
    resolver: ThreadSafeDNSResolver,
    registry: OutboundHandlerRegistry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedHttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedHttpRequest {
    pub method: EmbeddedHttpMethod,
    pub url: String,
    pub headers: Vec<EmbeddedHttpHeader>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
}

pub struct EmbeddedHttpResponse {
    pub status: u16,
    pub content_length: Option<u64>,
    pub content_range: Option<String>,
    pub accept_ranges: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub body: EmbeddedHttpBody,
}

pub struct EmbeddedHttpBody {
    body: Incoming,
}

impl EmbeddedHttpBody {
    pub async fn next_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let Some(frame) = self
                .body
                .frame()
                .await
                .transpose()
                .map_err(io::Error::other)?
            else {
                return Ok(None);
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if !data.is_empty() {
                return Ok(Some(data.to_vec()));
            }
        }
    }
}

impl EmbeddedOutbound {
    pub fn from_clash_yaml_entry(entry: &str) -> Result<Self> {
        let proxy = parse_clash_yaml_entry(entry)?;
        let mut outbounds = OutboundManager::load_plain_outbounds(vec![proxy]);
        let handler = outbounds.pop().ok_or_else(|| {
            Error::InvalidConfig(
                "proxy entry uses a protocol that this clash-lib build does not \
                 support"
                    .to_owned(),
            )
        })?;
        Self::from_handler(handler)
    }

    pub fn name(&self) -> &str {
        self.handler.name()
    }

    pub async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<BoxedChainedStream> {
        let session = Session {
            network: Network::Tcp,
            typ: Type::Ignore,
            destination: SocksAddr::Domain(host.to_owned(), port),
            ..Default::default()
        };
        self.handler
            .connect_stream(&session, Arc::clone(&self.resolver))
            .await
    }

    pub async fn http_request(
        &self,
        request: EmbeddedHttpRequest,
    ) -> io::Result<EmbeddedHttpResponse> {
        let timeout = request.timeout.unwrap_or(Duration::from_secs(30));
        let client = HttpClient::new(
            Arc::clone(&self.resolver),
            Some(Arc::clone(&self.registry)),
            Some(timeout),
        )?;
        let mut builder = http::Request::builder()
            .method(match request.method {
                EmbeddedHttpMethod::Get => http::Method::GET,
                EmbeddedHttpMethod::Post => http::Method::POST,
            })
            .uri(&request.url);
        for header in request.headers {
            builder = builder.header(header.name, header.value);
        }
        let body =
            Full::<Bytes>::from(Bytes::from(request.body.unwrap_or_default()));
        let mut http_request = builder.body(body).map_err(io::Error::other)?;
        http_request.extensions_mut().insert(ClashHTTPClientExt {
            outbound: Some(self.handler.name().to_owned()),
        });

        let response = client.request(http_request).await?;
        let status = response.status().as_u16();
        let content_length = response_content_length(
            response.headers().get(http::header::CONTENT_LENGTH),
        );
        let content_range = response_header_value(
            response.headers().get(http::header::CONTENT_RANGE),
        );
        let accept_ranges = response_header_value(
            response.headers().get(http::header::ACCEPT_RANGES),
        );
        let etag = response_header_value(response.headers().get(http::header::ETAG));
        let last_modified = response_header_value(
            response.headers().get(http::header::LAST_MODIFIED),
        );
        Ok(EmbeddedHttpResponse {
            status,
            content_length,
            content_range,
            accept_ranges,
            etag,
            last_modified,
            body: EmbeddedHttpBody {
                body: response.into_body(),
            },
        })
    }

    fn from_handler(handler: AnyOutboundHandler) -> Result<Self> {
        crate::setup_default_crypto_provider();
        let resolver: ThreadSafeDNSResolver = Arc::new(SystemResolver::new(true)?);
        let mut registry = HashMap::new();
        registry.insert(handler.name().to_owned(), Arc::clone(&handler));
        Ok(Self {
            handler,
            resolver,
            registry: Arc::new(RwLock::new(registry)),
        })
    }
}

fn parse_clash_yaml_entry(entry: &str) -> Result<OutboundProxyProtocol> {
    let value =
        serde_yaml::from_str::<serde_yaml::Value>(entry).map_err(|source| {
            Error::InvalidConfig(format!("invalid proxy YAML: {source}"))
        })?;
    let mapping = value.as_mapping().ok_or_else(|| {
        Error::InvalidConfig("proxy YAML entry must be a mapping".to_owned())
    })?;
    let mut object = HashMap::new();
    for (key, value) in mapping {
        let key = key
            .as_str()
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "proxy YAML entry keys must be strings".to_owned(),
                )
            })?
            .to_owned();
        object.insert(key, value.clone());
    }
    OutboundProxyProtocol::try_from(object)
}

fn response_content_length(value: Option<&http::HeaderValue>) -> Option<u64> {
    value?.to_str().ok()?.parse().ok()
}

fn response_header_value(value: Option<&http::HeaderValue>) -> Option<String> {
    value?.to_str().ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_outbound_rejects_non_mapping_yaml() {
        let error = match EmbeddedOutbound::from_clash_yaml_entry("- not-a-proxy") {
            Ok(_) => panic!("non-mapping YAML should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must be a mapping"));
    }

    #[tokio::test]
    async fn embedded_outbound_connects_direct_to_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await.expect("accept");
        });
        let outbound = EmbeddedOutbound::from_clash_yaml_entry(
            r#"
name: direct-fixture
type: direct
"#,
        )
        .expect("outbound");

        let _stream = outbound
            .connect_tcp(&address.ip().to_string(), address.port())
            .await
            .expect("connect");
        accept.await.expect("accept task");
    }

    #[tokio::test]
    async fn embedded_outbound_exposes_only_resume_response_metadata() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.expect("read request");
            stream
                .write_all(
                    b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 4-7/8\r\nAccept-Ranges: bytes\r\nETag: \"fixture-v1\"\r\nLast-Modified: Sun, 26 Jul 2026 12:00:00 GMT\r\nX-Secret: must-not-cross-boundary\r\nConnection: close\r\n\r\npart",
                )
                .await
                .expect("write response");
        });
        let outbound = EmbeddedOutbound::from_clash_yaml_entry(
            r#"
name: direct-fixture
type: direct
"#,
        )
        .expect("outbound");

        let response = outbound
            .http_request(EmbeddedHttpRequest {
                method: EmbeddedHttpMethod::Get,
                url: format!("http://{address}/file?token=secret"),
                headers: vec![EmbeddedHttpHeader {
                    name: "Range".to_owned(),
                    value: "bytes=4-".to_owned(),
                }],
                body: None,
                timeout: Some(Duration::from_secs(5)),
            })
            .await
            .expect("response");
        accept.await.expect("accept task");

        assert_eq!(response.status, 206);
        assert_eq!(response.content_length, Some(4));
        assert_eq!(response.content_range.as_deref(), Some("bytes 4-7/8"));
        assert_eq!(response.accept_ranges.as_deref(), Some("bytes"));
        assert_eq!(response.etag.as_deref(), Some("\"fixture-v1\""));
        assert_eq!(
            response.last_modified.as_deref(),
            Some("Sun, 26 Jul 2026 12:00:00 GMT")
        );
    }
}
