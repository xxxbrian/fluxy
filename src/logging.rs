use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::Subscriber;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

static CONN_ID: AtomicU64 = AtomicU64::new(1);

pub fn new_conn_id() -> String {
    let id = CONN_ID.fetch_add(1, Ordering::Relaxed);
    base36_encode(id)
}

fn base36_encode(mut num: u64) -> String {
    if num == 0 {
        return "0".to_string();
    }

    const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut result = Vec::new();

    while num > 0 {
        result.push(CHARSET[(num % 36) as usize]);
        num /= 36;
    }

    result.reverse();
    String::from_utf8(result).unwrap()
}

struct CustomFormatter;

impl<S, N> FormatEvent<S, N> for CustomFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        use nu_ansi_term::Color;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let datetime = chrono::DateTime::from_timestamp(now.as_secs() as i64, now.subsec_nanos())
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S%.6fZ");
        write!(writer, "{} ", datetime)?;

        let level = event.metadata().level();
        let level_str = match *level {
            tracing::Level::TRACE => Color::Purple.paint("TRACE"),
            tracing::Level::DEBUG => Color::Blue.paint("DEBUG"),
            tracing::Level::INFO => Color::Green.paint(" INFO"),
            tracing::Level::WARN => Color::Yellow.paint(" WARN"),
            tracing::Level::ERROR => Color::Red.paint("ERROR"),
        };
        write!(writer, "{} ", level_str)?;

        let mut found_conn_id = false;
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let extensions = span.extensions();
                if let Some(fields) =
                    extensions.get::<tracing_subscriber::fmt::FormattedFields<N>>()
                {
                    let fields_str = fields.as_str();
                    if let Some(conn_id) = extract_conn_id(fields_str) {
                        write!(writer, "{:>3} ", conn_id)?;
                        found_conn_id = true;
                        break;
                    }
                }
            }
        }
        if !found_conn_id {
            write!(writer, "    ")?;
        }

        write!(writer, "{}: ", event.metadata().target())?;

        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next_ch) = chars.peek() {
                    chars.next();
                    if next_ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn extract_conn_id(fields: &str) -> Option<String> {
    let clean_fields = strip_ansi(fields);
    for field in clean_fields.split_whitespace() {
        if let Some(value) = field.strip_prefix("conn_id=") {
            return Some(value.to_string());
        }
    }
    None
}

pub fn init(log_level: Option<&str>) {
    let user_level = log_level.unwrap_or("info");

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("fluxy={}", user_level)));

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_ansi(true)
        .event_format(CustomFormatter);

    let subscriber = Registry::default().with(filter).with(fmt_layer);

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base36_encode() {
        assert_eq!(base36_encode(0), "0");
        assert_eq!(base36_encode(1), "1");
        assert_eq!(base36_encode(35), "z");
        assert_eq!(base36_encode(36), "10");
        assert_eq!(base36_encode(1000), "rs");
    }

    #[test]
    fn test_conn_id_increments() {
        let id1 = new_conn_id();
        let id2 = new_conn_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_strip_ansi() {
        assert_eq!(strip_ansi("hello"), "hello");
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(
            strip_ansi("\x1b[3mconn_id\x1b[0m=\x1b[2m123"),
            "conn_id=123"
        );
    }

    #[test]
    fn test_extract_conn_id() {
        assert_eq!(extract_conn_id("conn_id=abc"), Some("abc".to_string()));
        assert_eq!(
            extract_conn_id("foo=bar conn_id=xyz"),
            Some("xyz".to_string())
        );
        assert_eq!(
            extract_conn_id("\x1b[3mconn_id\x1b[0m=\x1b[2m123"),
            Some("123".to_string())
        );
        assert_eq!(extract_conn_id("no_match=value"), None);
    }
}
