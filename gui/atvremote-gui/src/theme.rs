//! Styling and theme definitions for the Apple TV Remote GUI.

use gpui::Rgba;

/// Helper to construct `Rgba` at compile time from a hex literal (e.g. `0x18181b`).
#[allow(clippy::cast_precision_loss)]
pub const fn hex_rgb(hex: u32) -> Rgba {
    let r = (((hex >> 16) & 0xff) as u8) as f32 / 255.0;
    let g = (((hex >> 8) & 0xff) as u8) as f32 / 255.0;
    let b = ((hex & 0xff) as u8) as f32 / 255.0;
    Rgba { r, g, b, a: 1.0 }
}

/// Remote casing background color.
pub const BACKGROUND: Rgba = hex_rgb(0x0012_1214);

/// Remote inner surface / container background.
pub const SURFACE: Rgba = hex_rgb(0x001e_1e24);

/// Hover state for surfaces.
pub const SURFACE_HOVER: Rgba = hex_rgb(0x0028_2830);

/// Active/pressed state for surfaces.
pub const SURFACE_ACTIVE: Rgba = hex_rgb(0x0032_323c);

/// D-Pad outer ring background.
pub const DPAD_BG: Rgba = hex_rgb(0x0025_252d);

/// D-Pad button background on hover.
pub const DPAD_BTN_HOVER: Rgba = hex_rgb(0x0035_3540);

/// D-Pad center button background.
pub const DPAD_CENTER_BG: Rgba = hex_rgb(0x002b_2b35);

/// Primary text color.
pub const TEXT_PRIMARY: Rgba = hex_rgb(0x00f4_f4f6);

/// Secondary/muted text color.
pub const TEXT_MUTED: Rgba = hex_rgb(0x008e_8e99);

/// Subtle border color.
pub const BORDER: Rgba = hex_rgb(0x002e_2e38);

/// Accent highlight color (blue).
pub const ACCENT: Rgba = hex_rgb(0x003b_82f6);

/// Connected status color (emerald green).
pub const STATUS_CONNECTED: Rgba = hex_rgb(0x0010_b981);

/// Connecting/scanning status color (amber).
pub const STATUS_CONNECTING: Rgba = hex_rgb(0x00f5_9e0b);

/// Error/disconnected status color (rose red).
pub const STATUS_ERROR: Rgba = hex_rgb(0x00ef_4444);

/// Inactive/idle status color (slate).
pub const STATUS_IDLE: Rgba = hex_rgb(0x006b_7280);
