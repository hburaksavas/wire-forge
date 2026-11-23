use crate::proxy::Store;
use bytes::Bytes;
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    HeaderMap,
};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

pub const PREVIEW_LIMIT: usize = 16 * 1024;

pub fn headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    let mut remaining = PREVIEW_LIMIT;
    for (name, value) in headers {
        if name.as_str() == "proxy-authorization" {
            continue;
        }
        let size = name.as_str().len() + value.as_bytes().len();
        if size > remaining {
            rows.push((
                "preview".into(),
                "Additional headers omitted (16 KiB limit).".into(),
            ));
            break;
        }
        remaining -= size;
        rows.push((
            name.to_string(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        ));
    }
    rows
}

pub struct BodyPreview {
    pub text: String,
    pub truncated: bool,
    pub available: bool,
}

fn decode(reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    reader
        .take((PREVIEW_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn body_preview(bytes: &[u8], headers: &HeaderMap, wire_truncated: bool) -> BodyPreview {
    if bytes.is_empty() {
        return BodyPreview {
            text: String::new(),
            truncated: wire_truncated,
            available: true,
        };
    }
    let mut truncated = wire_truncated || bytes.len() > PREVIEW_LIMIT;
    let mut decoded = bytes[..bytes.len().min(PREVIEW_LIMIT)].to_vec();
    let encodings = headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let encodings: Vec<_> = encodings
        .split(',')
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    let unavailable = |message: &str| BodyPreview {
        text: message.into(),
        truncated,
        available: false,
    };
    if encodings.len() > 3 {
        return unavailable("Content encoding chain exceeds the preview limit.");
    }
    for encoding in encodings.iter().rev() {
        let result = match encoding.as_str() {
            "identity" => continue,
            "gzip" | "x-gzip" => decode(flate2::read::MultiGzDecoder::new(decoded.as_slice())),
            "deflate" => decode(flate2::read::ZlibDecoder::new(decoded.as_slice()))
                .or_else(|_| decode(flate2::read::DeflateDecoder::new(decoded.as_slice()))),
            "br" => decode(brotli::Decompressor::new(decoded.as_slice(), 4096)),
            _ => {
                return BodyPreview {
                    text: format!("Unsupported content encoding: {encoding}"),
                    truncated,
                    available: false,
                }
            }
        };
        match result {
            Ok(bytes) => {
                truncated |= bytes.len() > PREVIEW_LIMIT;
                decoded = bytes[..bytes.len().min(PREVIEW_LIMIT)].to_vec();
            }
            Err(_) => {
                return BodyPreview {
                    text: "Compressed preview is unavailable: incomplete or invalid encoded data."
                        .into(),
                    truncated,
                    available: false,
                }
            }
        }
    }
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if (!content_type.is_empty()
        && !(content_type.starts_with("text/")
            || ["json", "xml", "javascript", "x-www-form-urlencoded"]
                .iter()
                .any(|kind| content_type.contains(kind))))
        || decoded.contains(&0)
    {
        return BodyPreview {
            text: "Binary body. Text preview is unavailable.".into(),
            truncated,
            available: false,
        };
    }
    let text = match std::str::from_utf8(&decoded) {
        Ok(text) => text.to_owned(),
        Err(error) if truncated && error.error_len().is_none() => {
            String::from_utf8_lossy(&decoded[..error.valid_up_to()]).into_owned()
        }
        Err(_) => {
            return BodyPreview {
                text: "Body uses a non-UTF-8 encoding. Text preview is unavailable.".into(),
                truncated,
                available: false,
            }
        }
    };
    BodyPreview {
        text,
        truncated,
        available: true,
    }
}

pub fn preview(bytes: &[u8], headers: &HeaderMap) -> String {
    body_preview(bytes, headers, false).text
}

pub struct CapturedBody {
    inner: Pin<Box<Incoming>>,
    store: Arc<Store>,
    id: u64,
    bytes: Vec<u8>,
    total: u64,
    headers: HeaderMap,
    finished: bool,
}

impl CapturedBody {
    pub fn new(inner: Incoming, store: Arc<Store>, id: u64, headers: HeaderMap) -> Self {
        let mut body = Self {
            inner: Box::pin(inner),
            store,
            id,
            bytes: Vec::new(),
            total: 0,
            headers,
            finished: false,
        };
        if body.inner.is_end_stream() {
            body.finish("complete");
        }
        body
    }

    fn finish(&mut self, state: &str) {
        if self.finished {
            return;
        }
        self.finished = true;
        let bytes = std::mem::take(&mut self.bytes);
        let headers = self.headers.clone();
        let total = self.total;
        let id = self.id;
        let store = self.store.clone();
        let state = state.to_owned();
        let encoded = headers
            .get("content-encoding")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.eq_ignore_ascii_case("identity"));
        if encoded {
            store.finish_response(
                id,
                BodyPreview {
                    text: String::new(),
                    truncated: total > PREVIEW_LIMIT as u64,
                    available: false,
                },
                total,
                "decoding",
            );
            tokio::task::spawn_blocking(move || {
                store.finish_response(
                    id,
                    body_preview(&bytes, &headers, total > PREVIEW_LIMIT as u64),
                    total,
                    &state,
                );
            });
        } else {
            store.finish_response(
                id,
                body_preview(&bytes, &headers, total > PREVIEW_LIMIT as u64),
                total,
                &state,
            );
        }
    }
}

impl Body for CapturedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let result = self.inner.as_mut().poll_frame(context);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.total = self.total.saturating_add(data.len() as u64);
                    let count = data.len().min(PREVIEW_LIMIT - self.bytes.len());
                    self.bytes.extend_from_slice(&data[..count]);
                }
                if self.inner.is_end_stream() {
                    self.finish("complete");
                }
            }
            Poll::Ready(None) => self.finish("complete"),
            Poll::Ready(Some(Err(_))) => self.finish("failed"),
            Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CapturedBody {
    fn drop(&mut self) {
        self.finish("aborted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_headers_and_omits_proxy_credentials() {
        let mut source = HeaderMap::new();
        source.insert(
            "proxy-authorization",
            "Basic private-token".parse().unwrap(),
        );
        source.insert("large", "x".repeat(PREVIEW_LIMIT + 1).parse().unwrap());
        let captured = headers(&source);
        assert!(!captured
            .iter()
            .any(|(_, value)| value.contains("private-token")));
        assert!(captured.iter().any(|(name, _)| name == "preview"));
        assert!(
            captured
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>()
                < 256
        );
    }

    #[test]
    fn distinguishes_encoded_binary_and_text_bodies() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "Application/JSON".parse().unwrap());
        assert_eq!(preview(b"{}", &headers), "{}");
        assert_eq!(
            preview(&vec![b'x'; PREVIEW_LIMIT * 2], &headers).len(),
            PREVIEW_LIMIT
        );
        headers.insert("content-encoding", "gzip".parse().unwrap());
        assert!(preview(b"compressed", &headers).contains("Compressed preview"));
        headers.remove("content-encoding");
        headers.insert("content-type", "application/octet-stream".parse().unwrap());
        assert!(preview(b"binary", &headers).contains("Binary body"));
        assert_eq!(preview(b"", &headers), "");
    }

    fn encode(bytes: &[u8], encoding: &str) -> Vec<u8> {
        use std::io::Write;
        match encoding {
            "gzip" => {
                let mut writer =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                writer.write_all(bytes).unwrap();
                writer.finish().unwrap()
            }
            "deflate" => {
                let mut writer =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
                writer.write_all(bytes).unwrap();
                writer.finish().unwrap()
            }
            "raw-deflate" => {
                let mut writer =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
                writer.write_all(bytes).unwrap();
                writer.finish().unwrap()
            }
            "br" => {
                let mut result = Vec::new();
                {
                    let mut writer = brotli::CompressorWriter::new(&mut result, 4096, 4, 20);
                    writer.write_all(bytes).unwrap();
                }
                result
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn decodes_supported_encodings_and_stacked_layers() {
        for encoding in ["gzip", "deflate", "raw-deflate", "br"] {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "application/json".parse().unwrap());
            headers.insert(
                "content-encoding",
                (if encoding == "raw-deflate" {
                    "deflate"
                } else {
                    encoding
                })
                .parse()
                .unwrap(),
            );
            let encoded = encode(b"{\"decoded\":true}", encoding);
            let result = body_preview(&encoded, &headers, false);
            assert_eq!(result.text, "{\"decoded\":true}", "{encoding}");
            assert!(result.available && !result.truncated);
        }
        let compressed = encode(&encode(b"stacked", "gzip"), "br");
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip, br".parse().unwrap());
        let result = body_preview(&compressed, &headers, false);
        assert_eq!(result.text, "stacked");
        assert!(result.available);
    }

    #[test]
    fn decompression_expansion_and_invalid_streams_remain_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        let compressed = encode(&vec![b'x'; 2 * 1024 * 1024], "gzip");
        assert!(compressed.len() < PREVIEW_LIMIT);
        let result = body_preview(&compressed, &headers, false);
        assert_eq!(result.text.len(), PREVIEW_LIMIT);
        assert!(result.available && result.truncated);
        let broken = body_preview(b"not gzip", &headers, false);
        assert!(!broken.available);
        headers.insert("content-encoding", "unknown".parse().unwrap());
        assert!(!body_preview(b"data", &headers, false).available);
    }
}
