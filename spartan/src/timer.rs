#[cfg(feature = "profile")]
use colored::Colorize;
#[cfg(feature = "profile")]
use core::sync::atomic::AtomicUsize;
#[cfg(feature = "profile")]
use core::sync::atomic::Ordering;
#[cfg(feature = "profile")]
use std::time::Instant;

#[cfg(feature = "profile")]
pub static CALL_DEPTH: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "profile")]
pub struct Timer {
  label: String,
  timer: Instant,
}

#[cfg(feature = "profile")]
impl Timer {
  #[inline(always)]
  pub fn new(label: &str) -> Self {
    let timer = Instant::now();
    CALL_DEPTH.fetch_add(1, Ordering::Relaxed);
    let star = "* ";
    println!(
      "{:indent$}{}{}",
      "",
      star,
      label.yellow().bold(),
      indent = 2 * CALL_DEPTH.fetch_add(0, Ordering::Relaxed)
    );
    Self {
      label: label.to_string(),
      timer,
    }
  }

  #[inline(always)]
  pub fn stop(&self) {
    let duration = self.timer.elapsed();
    let star = "* ";
    println!(
      "{:indent$}{}{} {:?}",
      "",
      star,
      self.label.blue().bold(),
      duration,
      indent = 2 * CALL_DEPTH.fetch_add(0, Ordering::Relaxed)
    );
    CALL_DEPTH.fetch_sub(1, Ordering::Relaxed);
  }

  #[inline(always)]
  pub fn print(msg: &str) {
    CALL_DEPTH.fetch_add(1, Ordering::Relaxed);
    let star = "* ";
    println!(
      "{:indent$}{}{}",
      "",
      star,
      msg.to_string().green().bold(),
      indent = 2 * CALL_DEPTH.fetch_add(0, Ordering::Relaxed)
    );
    CALL_DEPTH.fetch_sub(1, Ordering::Relaxed);
  }
}

#[cfg(not(feature = "profile"))]
pub struct Timer {
  _label: String,
}

#[cfg(not(feature = "profile"))]
impl Timer {
  #[inline(always)]
  pub fn new(label: &str) -> Self {
    Self {
      _label: label.to_string(),
    }
  }

  #[inline(always)]
  pub fn stop(&self) {}

  #[inline(always)]
  pub fn print(_msg: &str) {}
}
