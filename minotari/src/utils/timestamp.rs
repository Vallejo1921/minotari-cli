use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

pub trait AsNaive {
    fn as_naive(&self) -> NaiveDateTime;
}

impl AsNaive for NaiveDateTime {
    fn as_naive(&self) -> NaiveDateTime {
        *self
    }
}

impl<T: TimeZone> AsNaive for DateTime<T> {
    fn as_naive(&self) -> NaiveDateTime {
        self.naive_utc()
    }
}

pub fn format_timestamp(date: impl AsNaive) -> String {
    date.as_naive().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn current_db_timestamp() -> String {
    format_timestamp(Utc::now())
}
