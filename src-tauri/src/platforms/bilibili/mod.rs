use std::path::PathBuf;

use omniget_core::models::progress::ProgressUpdate;

use anyhow::anyhow;
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::models::media::{DownloadOptions, DownloadResult, MediaInfo, MediaType, VideoQuality};
use crate::platforms::traits::PlatformDownloader;

pub mod api;
pub mod auth;
pub mod cdn;
pub mod cookie;
pub mod cover;
pub mod danmaku;
pub mod engine;
pub mod legacy;
pub mod naming;
pub mod nfo;
pub mod notify;
pub mod parser;
pub mod preview;
pub mod url_kind;
pub mod wbi;

pub struct BilibiliDownloader;

impl Default for BilibiliDownloader {
    fn default() -> Self {
        Self::new()
    }
}

impl BilibiliDownloader {
    pub fn new() -> Self {
        Self
    }
}

pub fn has_active_account() -> bool {
    active_account_slug().is_some()
}

pub fn active_account_slug() -> Option<String> {
    let registry = crate::cookies::load_registry();
    let bucket = registry.buckets.get("bilibili.com")?;

    if let Some(selected) = omniget_core::core::log_hook::current_cookie_slug() {
        if bucket
            .accounts
            .iter()
            .any(|a| a.slug == selected && a.slug != "_anonymous" && a.cookie_count > 0)
        {
            return Some(selected);
        }
    }

    let native = bucket
        .accounts
        .iter()
        .filter(|a| a.slug != "_anonymous" && a.slug != "_default" && a.cookie_count > 0)
        .max_by_key(|a| a.last_used_at_ms.unwrap_or(a.captured_at_ms))
        .map(|a| a.slug.clone());
    if native.is_some() {
        return native;
    }
    bucket
        .accounts
        .iter()
        .filter(|a| a.slug == "_default" && a.cookie_count > 0)
        .find(|a| slug_has_session_cookie(&a.slug))
        .map(|a| a.slug.clone())
}

fn slug_has_session_cookie(slug: &str) -> bool {
    let path = match crate::cookies::account_path_for_consumer("bilibili.com", Some(slug)) {
        Some(p) => p,
        None => return false,
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    content.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        line.split('\t').nth(5) == Some("SESSDATA")
    })
}

async fn api_engine_download(
    info: &MediaInfo,
    opts: &DownloadOptions,
    progress: mpsc::Sender<ProgressUpdate>,
) -> anyhow::Result<DownloadResult> {
    let _ = cookie::ensure_fresh().await;

    let url = info
        .available_qualities
        .first()
        .map(|q| q.url.as_str())
        .unwrap_or("");
    if url.is_empty() {
        return Err(anyhow!("No URL available"));
    }

    let slug = active_account_slug();
    let client = build_api_client(slug.as_deref(), opts.user_agent.as_deref())?;

    let mut effective_url = url.to_string();
    if url_kind::is_b23_short(&effective_url) {
        if let Ok(resolved) = url_kind::resolve_b23(&client, &effective_url).await {
            effective_url = resolved;
        }
    }

    let kind = url_kind::detect(&effective_url)
        .map_err(|e| anyhow!("Failed to detect URL kind: {}", e.i18n_key()))?;
    let parsed = parser::parse(&client, &kind)
        .await
        .map_err(|e| anyhow!("Failed to parse content: {}", e.i18n_key()))?;

    let settings = crate::storage::config::load_settings_standalone();
    let container = mux::container_from_setting(&settings.download.bilibili_container);
    let danmaku_format = danmaku_format_from_setting(&settings.download.bilibili_danmaku_format);
    let cover_format = cover::CoverFormat::from_str(&settings.download.bilibili_cover_format);
    let template_set = naming::TemplateSet {
        video: settings.download.bilibili_naming_video.clone(),
        multi_part: settings.download.bilibili_naming_multi_part.clone(),
        bangumi: settings.download.bilibili_naming_bangumi.clone(),
        cheese: settings.download.bilibili_naming_cheese.clone(),
        collection: settings.download.bilibili_naming_collection.clone(),
    };
    let first_item_owned = parsed.items.first().cloned().unwrap_or_default();
    let naming_kind = naming::classify(&kind, &first_item_owned);
    let naming_inputs = naming::NamingInputs {
        item: &first_item_owned,
        metadata: &parsed.metadata,
        parsed_title: &parsed.title,
    };
    let rendered_name = naming::render_for_kind(naming_kind, &naming_inputs, &template_set);
    let filename = if rendered_name.is_empty() {
        sanitize(&first_item_owned.title)
    } else {
        rendered_name
    };
    let cdn_alt_hosts = cdn::parse_hosts(&settings.download.bilibili_cdn_hosts);
    let engine_opts = engine::EngineOptions {
        output_dir: PathBuf::from(opts.output_dir.clone()),
        container,
        video_qn_pref: if settings.download.bilibili_preferred_qn != 0 {
            settings.download.bilibili_preferred_qn
        } else {
            preview::QN_AUTO
        },
        video_codec_pref: if settings.download.bilibili_preferred_codec != 0 {
            settings.download.bilibili_preferred_codec
        } else {
            preview::CODEC_AUTO
        },
        audio_qn_pref: if settings.download.bilibili_preferred_audio_qn != 0 {
            settings.download.bilibili_preferred_audio_qn
        } else {
            preview::AUDIO_AUTO
        },
        embed_cover: settings.download.embed_thumbnail,
        keep_streams: false,
        filename,
        cancel: opts.cancel_token.clone(),
        danmaku_enabled: settings.download.bilibili_danmaku_enabled,
        danmaku_format: Some(danmaku_format),
        nfo_enabled: settings.download.bilibili_nfo_enabled,
        cover_sidecar_enabled: settings.download.bilibili_cover_sidecar,
        cover_format,
        cdn_alt_hosts,
        cdn_prefer_alternatives: settings.download.bilibili_cdn_prefer_alternatives,
    };

    let result = engine::run_parsed_content(&client, &parsed, &kind, &engine_opts, progress)
        .await
        .map_err(|e| anyhow!("Engine failed: {}", e.i18n_key()))?;

    Ok(DownloadResult {
        file_path: result.final_path,
        file_size_bytes: result.bytes,
        duration_seconds: parsed
            .items
            .first()
            .and_then(|i| i.duration_seconds)
            .unwrap_or(0.0),
        torrent_id: None,
    })
}

fn build_api_client(
    slug: Option<&str>,
    user_agent: Option<&str>,
) -> anyhow::Result<api::ApiClient> {
    let mut client =
        api::ApiClient::new().map_err(|e| anyhow!("api client init failed: {}", e.i18n_key()))?;
    if let Some(ua) = user_agent.filter(|s| !s.is_empty()) {
        client = client.with_user_agent(ua);
    }
    match slug {
        Some(s) => client = client.with_account(s),
        None => client = client.with_anonymous_cookies(),
    }
    Ok(client)
}

fn sanitize(s: &str) -> String {
    let cleaned = sanitize_filename::sanitize(s);
    if cleaned.is_empty() {
        "video".to_string()
    } else {
        cleaned
    }
}

/// Fetch bilibili media info via the in-house API engine instead of yt-dlp.
///
/// The API path is much faster and more reliable than yt-dlp for bilibili
/// (no slow metadata extraction, no 412 without cookies). It reuses the same
/// parser/preview pipeline that `bilibili_preview_info` uses. If it fails we
/// fall back to the yt-dlp-based `legacy::get_media_info` so the user is never
/// left without metadata.
async fn get_media_info_via_api(url: &str) -> anyhow::Result<MediaInfo> {
    let _ = cookie::ensure_fresh().await;

    let slug = active_account_slug();
    let client = build_api_client(slug.as_deref(), None)
        .map_err(|e| anyhow!("bilibili api client init failed: {}", e))?;

    let mut effective_url = url.to_string();
    if url_kind::is_b23_short(&effective_url) {
        if let Ok(resolved) = url_kind::resolve_b23(&client, &effective_url).await {
            effective_url = resolved;
        }
    }

    let kind = url_kind::detect(&effective_url)
        .map_err(|e| anyhow!("Failed to detect URL kind: {}", e.i18n_key()))?;
    let parsed = parser::parse(&client, &kind)
        .await
        .map_err(|e| anyhow!("Failed to parse bilibili content: {}", e.i18n_key()))?;

    let item = parsed
        .items
        .first()
        .ok_or_else(|| anyhow!("No items found for this bilibili URL"))?;

    // Build the quality list from the in-house preview pipeline.
    let mut qualities: Vec<VideoQuality> = Vec::new();
    if let Some(info) = preview::fetch(&client, item, &kind).await.ok() {
        for qn in info.available_qns() {
            qualities.push(VideoQuality {
                label: preview::qn_label(qn).to_string(),
                width: 0,
                height: qn_to_height(qn),
                url: effective_url.clone(),
                format: "mp4".to_string(),
            });
        }
        for qn in info.available_audio_qns() {
            qualities.push(VideoQuality {
                label: format!("audio/{}", preview::audio_qn_label(qn)),
                width: 0,
                height: 0,
                url: effective_url.clone(),
                format: "m4a".to_string(),
            });
        }
    }
    // Guarantee at least one entry so the download engine always has an entry URL.
    if qualities.is_empty() {
        qualities.push(VideoQuality {
            label: "auto".to_string(),
            width: 0,
            height: 0,
            url: effective_url.clone(),
            format: "mp4".to_string(),
        });
    }

    let media_type = if parsed.items.len() > 1 {
        MediaType::Playlist
    } else {
        MediaType::Video
    };
    let thumbnail_url = item
        .cover_url
        .clone()
        .or_else(|| parsed.metadata.poster.clone())
        .or_else(|| parsed.metadata.cover.clone());

    Ok(MediaInfo {
        title: parsed.title.clone(),
        author: parsed.metadata.uploader.clone().unwrap_or_default(),
        platform: "bilibili".to_string(),
        duration_seconds: item.duration_seconds,
        thumbnail_url,
        available_qualities: qualities,
        media_type,
        file_size_bytes: None,
    })
}

/// Map a bilibili quality number to an approximate vertical resolution for
/// display purposes. Exact heights are returned by the API at download time.
fn qn_to_height(qn: u32) -> u32 {
    match qn {
        125 | 127 | 128 => 1080,
        116 | 120 => 1080,
        112 | 108 | 100 => 1080,
        80 => 1080,
        74 => 720,
        64 => 720,
        32 => 480,
        16 => 360,
        _ => 0,
    }
}

mod mux {
    pub use super::engine::mux::Container;

    pub fn container_from_setting(value: &str) -> Container {
        match value {
            "mkv" => Container::Mkv,
            _ => Container::Mp4,
        }
    }
}

fn danmaku_format_from_setting(value: &str) -> danmaku::DanmakuFormat {
    match value {
        "ass" => danmaku::DanmakuFormat::Ass,
        "json" => danmaku::DanmakuFormat::Json,
        _ => danmaku::DanmakuFormat::Xml,
    }
}

#[async_trait]
impl PlatformDownloader for BilibiliDownloader {
    fn name(&self) -> &str {
        "bilibili"
    }

    fn can_handle(&self, url: &str) -> bool {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                let host = host.to_lowercase();
                return host.contains("bilibili.com")
                    || host.contains("bilibili.tv")
                    || host == "b23.tv";
            }
        }
        false
    }

    async fn get_media_info(&self, url: &str) -> anyhow::Result<MediaInfo> {
        // Prefer the fast in-house API engine over yt-dlp for metadata. Fall
        // back to yt-dlp if the API path fails (e.g. unexpected URL shape).
        match get_media_info_via_api(url).await {
            Ok(info) => Ok(info),
            Err(e) => {
                tracing::warn!(
                    "[bilibili] api media-info failed ({}), falling back to yt-dlp",
                    e
                );
                legacy::get_media_info(url).await
            }
        }
    }

    async fn download(
        &self,
        info: &MediaInfo,
        opts: &DownloadOptions,
        progress: mpsc::Sender<ProgressUpdate>,
    ) -> anyhow::Result<DownloadResult> {
        if has_active_account() && info.media_type != MediaType::Playlist {
            tracing::info!("[bilibili] using api-direct engine (account active)");
            match api_engine_download(info, opts, progress.clone()).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("errors.bilibili.not_logged_in") {
                        notify::session_expired(active_account_slug().as_deref());
                    }
                    tracing::warn!(
                        "[bilibili] api engine failed, falling back to legacy yt-dlp: {}",
                        e
                    );
                    return legacy::download(info, opts, progress).await;
                }
            }
        }
        legacy::download(info, opts, progress).await
    }
}
