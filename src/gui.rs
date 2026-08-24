//! Desktop GUI for Pellitory-39 (`--gui` flag), built with `eframe` (egui).
//!
//! The GUI exposes only the **duress-compatible** generate flow and the
//! recovery flow for Bitcoin and Monero. Complex settings (multi-group,
//! raw hex, custom identifiers, `ext` flags) are left to the CLI.
//!
//! All UI `String` fields holding secrets (passwords, shares, seeds, keys)
//! are wrapped in `Zeroizing` so they are wiped from RAM on drop.
//!
//! This module is only compiled when the `gui` feature is enabled.

use std::sync::mpsc;

use eframe::egui;
use zeroize::Zeroizing;

use pellitory_39::export::BulkPackage;
use pellitory_39::gui_support::{
    self, analyse_shares, Coin, DecryptMethod, DeriveResult, DuressResult, EncryptMethod,
    MoneroRecovery, RecoveryResult, ShareCountInfo, SplitResult,
};
use pellitory_39::InputKind as DetectedKind;

// ─── Color palette ──────────────────────────────────────────────────────────
//
// Contrast ratios (WCAG):
//   TEXT       on BG       -> 12.4:1  (AAA)
//   TEXT       on CARD_BG  -> 10.7:1  (AAA)
//   TEXT_WEAK  on CARD_BG  ->  5.7:1  (AA)
//   TEXT_WEAK  on BG       ->  6.5:1  (AA)

const BG: egui::Color32 = egui::Color32::from_rgb(17, 18, 26);
const CARD_BG: egui::Color32 = egui::Color32::from_rgb(28, 30, 44);
const CARD_BG_LIGHT: egui::Color32 = egui::Color32::from_rgb(36, 38, 54);
const INPUT_BG: egui::Color32 = egui::Color32::from_rgb(21, 22, 34);
const CARD_STROKE: egui::Color32 = egui::Color32::from_rgb(52, 54, 76);

const TEXT: egui::Color32 = egui::Color32::from_rgb(218, 220, 232);
const TEXT_BRIGHT: egui::Color32 = egui::Color32::from_rgb(248, 248, 255);
const TEXT_WEAK: egui::Color32 = egui::Color32::from_rgb(165, 167, 190);

const ACCENT: egui::Color32 = egui::Color32::from_rgb(88, 140, 246);
const ACCENT_HOVER: egui::Color32 = egui::Color32::from_rgb(120, 165, 255);

const GREEN: egui::Color32 = egui::Color32::from_rgb(72, 192, 92);
const GREEN_BG: egui::Color32 = egui::Color32::from_rgb(26, 42, 32);
const ORANGE: egui::Color32 = egui::Color32::from_rgb(244, 146, 68);
const ORANGE_BG: egui::Color32 = egui::Color32::from_rgb(42, 34, 26);
const RED: egui::Color32 = egui::Color32::from_rgb(248, 85, 78);
const RED_BG: egui::Color32 = egui::Color32::from_rgb(44, 24, 28);
const AMBER: egui::Color32 = egui::Color32::from_rgb(218, 160, 44);
const AMBER_BG: egui::Color32 = egui::Color32::from_rgb(42, 36, 20);
/// Dark text that stays legible on the amber accent (used for the caution
/// button in the empty-password modal). ~9.2:1 contrast on AMBER.
const ON_AMBER: egui::Color32 = egui::Color32::from_rgb(38, 26, 6);

/// Maximum shares per SLIP-0039 group (the spec reserves 4 bits).
const MAX_SHARES: u8 = 16;

/// Horizontal margin around the central panel content.
const SIDE_MARGIN: i8 = 30;

/// Message shown when a background worker thread terminates without sending
/// a result (panic or premature tx drop). Lets the poll loop surface a clean
/// error instead of leaving the tab spinner stuck forever (audit L-5).
const WORKER_DISCONNECTED_MSG: &str =
    "The background worker terminated unexpectedly. Please try again.";

// ─── Public entry point ─────────────────────────────────────────────────────

pub fn run_gui() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Pellitory-39 — Secure Wallet Backup")
            .with_inner_size([1000.0, 820.0])
            .with_min_inner_size([720.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "pellitory-39-gui",
        options,
        Box::new(|cc| {
            configure_visuals(&cc.egui_ctx);
            Ok(Box::new(App::default()))
        }),
    )
}

fn configure_visuals(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();

    v.panel_fill = BG;
    v.window_fill = CARD_BG;
    v.faint_bg_color = CARD_BG_LIGHT;
    v.extreme_bg_color = INPUT_BG;

    v.widgets.noninteractive.bg_fill = CARD_BG;
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, CARD_STROKE);

    v.widgets.inactive.bg_fill = INPUT_BG;
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, CARD_STROKE);

    v.widgets.hovered.bg_fill = ACCENT_HOVER;
    v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT_BRIGHT);
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);

    v.widgets.active.bg_fill = ACCENT;
    v.widgets.active.fg_stroke = egui::Stroke::new(1.0, TEXT_BRIGHT);
    v.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);

    v.selection.bg_fill = ACCENT;
    v.selection.stroke = egui::Stroke::new(1.0, TEXT_BRIGHT);

    v.window_stroke = egui::Stroke::new(1.0, CARD_STROKE);
    v.clip_rect_margin = 4.0;

    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(9.0, 9.0);
    style.spacing.button_padding = egui::vec2(18.0, 9.0);
    style.spacing.window_margin = egui::Margin::same(16);
    // Slightly larger, more legible default text sizes.
    style
        .text_styles
        .insert(egui::TextStyle::Small, egui::FontId::proportional(12.0));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(20.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(14.0));
    ctx.set_style(style);
}

// ─── App state ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum CoinTab {
    Bitcoin,
    Monero,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModeTab {
    Generate,
    Split,
    Recover,
    Derive,
}

/// A tab switch requested by the user that may be intercepted by the
/// "results will be cleared" confirmation dialog before being applied.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingSwitch {
    Coin(CoinTab),
    Mode(ModeTab),
}

struct GenerateOutput {
    real_shares: Zeroizing<String>,
    decoy_shares: Zeroizing<String>,
    real_monero: Option<MoneroRecovery>,
    decoy_monero: Option<MoneroRecovery>,
}

impl From<DuressResult> for GenerateOutput {
    fn from(r: DuressResult) -> Self {
        Self {
            real_shares: r.real_shares,
            decoy_shares: r.decoy_shares,
            real_monero: r.real_monero,
            decoy_monero: r.decoy_monero,
        }
    }
}

struct RecoverOutput {
    bip39: Option<Zeroizing<String>>,
    monero: Option<MoneroRecovery>,
}

impl From<RecoveryResult> for RecoverOutput {
    fn from(r: RecoveryResult) -> Self {
        match r {
            RecoveryResult::Bip39(s) => Self {
                bip39: Some(s),
                monero: None,
            },
            RecoveryResult::Monero(m) => Self {
                bip39: None,
                monero: Some(m),
            },
        }
    }
}

struct GenerateState {
    threshold: u8,
    total_shares: u8,
    real_password: Zeroizing<String>,
    real_password_confirm: Zeroizing<String>,
    generate_decoy: bool,
    decoy_password: Zeroizing<String>,
    decoy_password_confirm: Zeroizing<String>,
    advanced_open: bool,
    iterations: usize,
    busy: bool,
    output: Option<GenerateOutput>,
    error: Option<Zeroizing<String>>,
    rx: Option<mpsc::Receiver<WorkerMsg>>,
    confirm_empty_pass: bool,
}

impl Default for GenerateState {
    fn default() -> Self {
        Self {
            threshold: 2,
            total_shares: 3,
            real_password: Zeroizing::new(String::new()),
            real_password_confirm: Zeroizing::new(String::new()),
            generate_decoy: true,
            decoy_password: Zeroizing::new(String::new()),
            decoy_password_confirm: Zeroizing::new(String::new()),
            advanced_open: false,
            iterations: 0,
            busy: false,
            output: None,
            error: None,
            rx: None,
            confirm_empty_pass: false,
        }
    }
}

struct RecoverState {
    shares_text: Zeroizing<String>,
    password: Zeroizing<String>,
    /// Confirmation field: must equal `password` before recovery starts.
    /// Guards against a mistyped password silently recovering (and then
    /// funding) the wrong wallet — see SECURITY.md.
    password_confirm: Zeroizing<String>,
    busy: bool,
    output: Option<RecoverOutput>,
    error: Option<Zeroizing<String>>,
    rx: Option<mpsc::Receiver<WorkerMsg>>,
    /// True if a decrypt popup is open.
    decrypt_popup_open: bool,
    /// True after at least one share has been decrypted in-place.
    /// Drives the "Decrypted with age" badge.
    decrypted: bool,
    /// Number of shares successfully decrypted so far.
    decrypted_count: usize,
    /// Cached share analysis (avoid re-running sharing::inspect on every
    /// frame — it does PBKDF2 + checksum validation).
    cached_analysis: Option<ShareCountInfo>,
    /// Queue of armoured lines intercepted from the text area, waiting
    /// for decryption. Processed one at a time through the decrypt popup.
    pending_armoured: Vec<String>,
}

/// Output of the Derive tab: a BIP-39 phrase (Bitcoin) or a Monero key
/// set. Structurally the same as `RecoverOutput` but kept separate so the
/// two tabs never share a result slot.
struct DeriveOutput {
    bip39: Option<Zeroizing<String>>,
    monero: Option<MoneroRecovery>,
}

impl From<DeriveResult> for DeriveOutput {
    fn from(r: DeriveResult) -> Self {
        match r {
            DeriveResult::Bip39(s) => Self {
                bip39: Some(s),
                monero: None,
            },
            DeriveResult::Monero(m) => Self {
                bip39: None,
                monero: Some(m),
            },
        }
    }
}

struct DeriveState {
    /// Raw material to derive from: hex entropy (Bitcoin) or a spend key /
    /// 25-word mnemonic (Monero).
    input: Zeroizing<String>,
    busy: bool,
    output: Option<DeriveOutput>,
    error: Option<Zeroizing<String>>,
    rx: Option<mpsc::Receiver<WorkerMsg>>,
}

impl Default for DeriveState {
    fn default() -> Self {
        Self {
            input: Zeroizing::new(String::new()),
            busy: false,
            output: None,
            error: None,
            rx: None,
        }
    }
}

impl Default for RecoverState {
    fn default() -> Self {
        Self {
            shares_text: Zeroizing::new(String::new()),
            password: Zeroizing::new(String::new()),
            password_confirm: Zeroizing::new(String::new()),
            busy: false,
            output: None,
            error: None,
            rx: None,
            decrypt_popup_open: false,
            decrypted: false,
            decrypted_count: 0,
            cached_analysis: None,
            pending_armoured: Vec::new(),
        }
    }
}

enum WorkerMsg {
    Generate(Result<DuressResult, String>),
    Split(Result<SplitResult, String>),
    Recover(Result<RecoveryResult, String>),
    Derive(Result<DeriveResult, String>),
}

/// What a save worker thread returns on success (for the status banner).
struct SaveOutcome {
    /// Plain-word method label, e.g. "passphrase" / "X25519 recipient 1ab2c3d4"
    /// / "SSH Ed25519 1ab2c3d4".
    method_label: String,
    /// Suggested file name that was saved (or "" if the user cancelled the
    /// file dialog).
    saved_name: String,
    /// True for the plaintext (no-encryption) save path. Kept separate from
    /// `method_label` so the success toast branches on a real bool instead
    /// of a stringly-typed sentinel.
    is_plaintext: bool,
    /// True when the saved shares are a decoy wallet (duress). For plaintext
    /// saves of a *real* wallet we surface an extra "no encryption" warning
    /// in the toast so the user is reminded the file is unencrypted.
    is_decoy: bool,
}

/// Which kind of save the popup is collecting a method for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SaveTarget {
    /// One share -> one `.age` file.
    PerShare,
    /// All shares -> a ZIP with per-share `.age` entries.
    BulkZip,
    /// All shares -> one concatenated armoured blob.
    BulkOneFile,
}

/// Editor state for one encryption credential row in the save popup.
enum MethodEditor {
    Passphrase {
        pass: Zeroizing<String>,
        confirm: Zeroizing<String>,
        /// Last validation error (mismatch / round-trip failure).
        error: Option<String>,
    },
    Recipient {
        /// Pasted or loaded recipient string (`age1...` / `ssh-...`).
        text: Zeroizing<String>,
        /// Parsed fingerprint, if the text is a valid recipient.
        fingerprint: Option<String>,
        /// "I have the matching private key" confirmation (required).
        confirmed: bool,
        error: Option<String>,
        /// Snapshot of `text` from the last parse. If `text` hasn't
        /// changed since this snapshot, we skip re-parsing (which calls
        /// age's Recipient::from_str — a base64 + curve point parse).
        last_parsed: Zeroizing<String>,
    },
}

/// Transient state for the age-encryption save popup. Held in
/// `App::save_popup` while open; dropped (zeroizing all secrets) on close.
/// This is UI state, not session state — there is no "remember" checkbox
/// anywhere
struct SavePopupState {
    target: SaveTarget,
    /// One method editor per share (PerShare / BulkZip) or exactly one
    /// (BulkOneFile).
    methods: Vec<MethodEditor>,
    /// The shares to encrypt, owned so they survive the popup closing.
    shares: Vec<Zeroizing<String>>,
    threshold: u8,
    /// Show the duress notice (decoy bulk save).
    is_decoy: bool,
    /// Short label for the popup title / status (e.g. "Real share 2 of 3").
    title: String,
    /// Carousel index for BulkZip mode (which share is currently shown).
    carousel_idx: usize,
    /// Slide animation offset (px). Set to a non-zero value when the
    /// carousel changes; decays to 0 each frame. Positive = slide from
    /// right (Next), negative = slide from left (Back).
    slide_offset: f32,
}

/// Transient state for the expert-mode save choice popup. Asks the
/// user whether to encrypt (opening the full method-popup) or save as
/// plaintext, before proceeding with the respective workflow.
struct SaveChoiceState {
    target: SaveTarget,
    shares: Vec<Zeroizing<String>>,
    threshold: u8,
    is_decoy: bool,
    title: String,
}

/// Transient state for the age-decryption popup on the Recover tab.
/// Collects a single decrypt credential (passphrase / age identity /
/// SSH key) applied to all armoured lines in the shares text.
struct DecryptPopupState {
    /// Which decrypt method the user selected.
    method: DecryptPopupMethod,
    /// Slide animation offset (px). Decays to 0 each frame.
    slide_offset: f32,
}

/// Receiver type for async file-load results: (file contents, filename).
type FileLoadResult = mpsc::Receiver<Result<(Zeroizing<Vec<u8>>, String), String>>;

/// Where an async file-load result should be routed.
#[derive(Clone, Copy)]
enum FileLoadTarget {
    /// Save popup: recipient public key (paste or load).
    /// The index identifies which method editor in the popup's `methods`
    /// vec the result should go to (carousel position in BulkZip mode).
    SaveRecipient(usize),
    /// Decrypt popup: age identity or SSH private key (auto-detected).
    DecryptKeyFile,
    /// Recover tab: share file (armoured or plain).
    RecoverShareFile,
}

/// Decrypt method editor for the Recover tab popup.
enum DecryptPopupMethod {
    Passphrase {
        pass: Zeroizing<String>,
        error: Option<String>,
    },
    /// age identity *or* SSH private key — the format is auto-detected
    /// when decrypting. Replaces the former separate AgeIdentity / SshKey
    /// variants so the user picks a single "age / SSH key" option.
    KeyFile {
        /// File contents loaded via "Load file..." or pasted.
        contents: Zeroizing<Vec<u8>>,
        loaded_name: String,
        /// Pasted text (alternative to loading a file).
        pasted: Zeroizing<String>,
        error: Option<String>,
    },
}

impl Default for DecryptPopupMethod {
    fn default() -> Self {
        DecryptPopupMethod::Passphrase {
            pass: Zeroizing::new(String::new()),
            error: None,
        }
    }
}

struct SplitState {
    secret_input: Zeroizing<String>,
    threshold: u8,
    total_shares: u8,
    password: Zeroizing<String>,
    password_confirm: Zeroizing<String>,
    /// Generate a decoy wallet alongside the real split (duress).
    generate_decoy: bool,
    decoy_password: Zeroizing<String>,
    decoy_password_confirm: Zeroizing<String>,
    advanced_open: bool,
    iterations: usize,
    busy: bool,
    output: Option<SplitResult>,
    error: Option<Zeroizing<String>>,
    rx: Option<mpsc::Receiver<WorkerMsg>>,
}

impl Default for SplitState {
    fn default() -> Self {
        Self {
            secret_input: Zeroizing::new(String::new()),
            threshold: 2,
            total_shares: 3,
            password: Zeroizing::new(String::new()),
            password_confirm: Zeroizing::new(String::new()),
            generate_decoy: false,
            decoy_password: Zeroizing::new(String::new()),
            decoy_password_confirm: Zeroizing::new(String::new()),
            advanced_open: false,
            iterations: 0,
            busy: false,
            output: None,
            error: None,
            rx: None,
        }
    }
}

struct App {
    coin_tab: CoinTab,
    mode_tab: ModeTab,
    btc_gen: GenerateState,
    xmr_gen: GenerateState,
    btc_split: SplitState,
    xmr_split: SplitState,
    btc_rec: RecoverState,
    xmr_rec: RecoverState,
    btc_derive: DeriveState,
    xmr_derive: DeriveState,
    /// When true, generated / split / recovered results are kept when the
    /// user switches tabs (instead of being wiped on navigation). All
    /// secrets are still wiped on app exit. Defaults to `false` so the
    /// safer behavior is the default.
    persist_outputs: bool,
    /// Expert mode: when true, the Generate/Split save buttons open the
    /// encryption-method popup (passphrase / age recipient / SSH key) before
    /// saving. When false (default), saves write plaintext `.txt` / `.zip`
    /// files directly with no popup. The Recover tab is unaffected — armour
    /// auto-detect and decrypt-in-place are always active.
    expert_mode: bool,
    /// Whether we have already shown the one-time "results won't persist"
    /// warning this session. Once acknowledged it is not shown again.
    warned_no_persist: bool,
    /// A tab switch awaiting confirmation in the warning dialog. While this
    /// is `Some`, the actual tab change is held until the user picks an
    /// action in the dialog.
    pending_switch: Option<PendingSwitch>,
    /// Stashed copy of the egui context so `on_exit` (which is not passed
    /// the context) can clear egui's widget-state caches and overwrite the
    /// clipboard. Set on the first `update` call.
    ctx: Option<egui::Context>,
    /// Active age-encryption save popup (per-share or bulk), if open.
    save_popup: Option<SavePopupState>,
    /// Expert-mode save choice popup (encrypt vs plaintext), if open.
    save_choice: Option<SaveChoiceState>,
    /// Receiver for the save worker thread.
    save_rx: Option<mpsc::Receiver<Result<SaveOutcome, String>>>,
    /// Brief status banner shown after a save completes (success or error).
    /// The `bool` is `true` when the message is an error (red warning icon)
    /// and `false` for a success (green check).
    save_status: Option<(String, bool)>,
    /// Instant when the save status was first shown (for auto-dismiss).
    save_status_time: Option<std::time::Instant>,
    /// Active age-decryption popup on the Recover tab, if open.
    decrypt_popup: Option<DecryptPopupState>,
    /// Receiver for the decrypt worker thread.
    decrypt_rx: Option<mpsc::Receiver<Result<Zeroizing<String>, String>>>,
    /// Receiver for async file-load (pick_file + read) worker threads.
    /// Avoids blocking the UI thread with rfd's blocking dialog.
    file_load_rx: Option<FileLoadResult>,
    /// What the loaded file is for (routes the result to the right field).
    file_load_target: Option<FileLoadTarget>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            coin_tab: CoinTab::Bitcoin,
            mode_tab: ModeTab::Generate,
            btc_gen: GenerateState::default(),
            xmr_gen: GenerateState::default(),
            btc_split: SplitState::default(),
            xmr_split: SplitState::default(),
            btc_rec: RecoverState::default(),
            xmr_rec: RecoverState::default(),
            btc_derive: DeriveState::default(),
            xmr_derive: DeriveState::default(),
            persist_outputs: false,
            expert_mode: true,
            warned_no_persist: false,
            pending_switch: None,
            ctx: None,
            save_popup: None,
            save_choice: None,
            save_rx: None,
            save_status: None,
            save_status_time: None,
            decrypt_popup: None,
            decrypt_rx: None,
            file_load_rx: None,
            file_load_target: None,
        }
    }
}

impl App {
    fn gen_mut(&mut self) -> &mut GenerateState {
        match self.coin_tab {
            CoinTab::Bitcoin => &mut self.btc_gen,
            CoinTab::Monero => &mut self.xmr_gen,
        }
    }
    fn rec_mut(&mut self) -> &mut RecoverState {
        match self.coin_tab {
            CoinTab::Bitcoin => &mut self.btc_rec,
            CoinTab::Monero => &mut self.xmr_rec,
        }
    }
    fn split_mut(&mut self) -> &mut SplitState {
        match self.coin_tab {
            CoinTab::Bitcoin => &mut self.btc_split,
            CoinTab::Monero => &mut self.xmr_split,
        }
    }
    fn derive_mut(&mut self) -> &mut DeriveState {
        match self.coin_tab {
            CoinTab::Bitcoin => &mut self.btc_derive,
            CoinTab::Monero => &mut self.xmr_derive,
        }
    }
    fn coin(&self) -> Coin {
        match self.coin_tab {
            CoinTab::Bitcoin => Coin::Bitcoin,
            CoinTab::Monero => Coin::Monero,
        }
    }
}

// ─── eframe::App impl ───────────────────────────────────────────────────────

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ctx = Some(ctx.clone());
        self.poll_workers();
        self.poll_save_worker();
        self.poll_decrypt_worker();
        self.poll_file_load_worker();

        // ── Top bar ──
        egui::TopBottomPanel::top("top_bar")
            .exact_height(100.0)
            .frame(
                egui::Frame::NONE
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0, CARD_STROKE))
                    .inner_margin(egui::Margin {
                        left: SIDE_MARGIN,
                        right: SIDE_MARGIN,
                        top: 14,
                        bottom: 10,
                    }),
            )
            .show(ctx, |ui| {
                // Title row
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Pellitory-39")
                            .size(21.0)
                            .strong()
                            .color(TEXT_BRIGHT),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new("Secure wallet backup · SLIP-0039")
                            .size(13.0)
                            .color(TEXT_WEAK),
                    );
                });

                ui.add_space(10.0);

                // Tab row
                ui.horizontal(|ui| {
                    tab_button(ui, "Bitcoin", self.coin_tab == CoinTab::Bitcoin, || {
                        self.request_switch(PendingSwitch::Coin(CoinTab::Bitcoin));
                    });
                    tab_button(ui, "Monero", self.coin_tab == CoinTab::Monero, || {
                        self.request_switch(PendingSwitch::Coin(CoinTab::Monero));
                    });

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(16.0);

                    tab_button(ui, "Generate", self.mode_tab == ModeTab::Generate, || {
                        self.request_switch(PendingSwitch::Mode(ModeTab::Generate));
                    });
                    tab_button(ui, "Split", self.mode_tab == ModeTab::Split, || {
                        self.request_switch(PendingSwitch::Mode(ModeTab::Split));
                    });
                    tab_button(ui, "Recover", self.mode_tab == ModeTab::Recover, || {
                        self.request_switch(PendingSwitch::Mode(ModeTab::Recover));
                    });
                    tab_button(ui, "Derive", self.mode_tab == ModeTab::Derive, || {
                        self.request_switch(PendingSwitch::Mode(ModeTab::Derive));
                    });

                    // Expert mode toggle (right-aligned). Only affects
                    // Generate/Split save buttons: simple = plaintext save,
                    // expert = encryption-method popup. Recover is always
                    // auto-detect.
                    //
                    // Currently hidden — `expert_mode` defaults to `true`
                    // (see Default impl) so the choice popup always shows.
                    // Un-comment the block below to re-expose the toggle.
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |_ui| {
                            /*
                            let label = if self.expert_mode {
                                "Expert mode: on (encrypted saves)"
                            } else {
                                "Expert mode: off (plaintext saves)"
                            };
                            let text = egui::RichText::new(label).size(12.0).color(TEXT_WEAK);
                            if ui
                                .add(egui::Checkbox::new(&mut self.expert_mode, text))
                                .changed()
                            {
                                // No state wipe needed — only affects future saves.
                            }
                            */
                        },
                    );
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(BG)
                    .inner_margin(egui::Margin {
                        left: SIDE_MARGIN,
                        right: SIDE_MARGIN,
                        top: 16,
                        bottom: 16,
                    }),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(4.0);
                        match self.mode_tab {
                            ModeTab::Generate => self.render_generate(ui, ctx),
                            ModeTab::Split => self.render_split(ui, ctx),
                            ModeTab::Recover => self.render_recover(ui, ctx),
                            ModeTab::Derive => self.render_derive(ui, ctx),
                        }
                        ui.add_space(24.0);
                    });
            });

        // ── Save status (auto-dismissing toast) ──
        // A centered floating window at the bottom that auto-dismisses after
        // 4 seconds or on any click. No dismiss button.
        if let Some((status, is_error)) = self.save_status.clone() {
            let mut dismiss = false;
            // Auto-dismiss after 4 seconds.
            if let Some(t) = self.save_status_time {
                if t.elapsed().as_secs() >= 4 {
                    dismiss = true;
                }
            }
            // Branch the icon / stroke colour on success vs error so a
            // green check never appears next to a failure message.
            let stroke_color = if is_error { RED } else { ACCENT };
            let (icon_kind, icon_color) = if is_error {
                (Icon::Warning, RED)
            } else {
                (Icon::Check, GREEN)
            };
            let response = egui::Window::new("save_status_toast")
                .title_bar(false)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_BOTTOM, egui::Vec2::new(0.0, -24.0))
                .frame(
                    egui::Frame::NONE
                        .fill(CARD_BG)
                        .stroke(egui::Stroke::new(1.0, stroke_color))
                        .corner_radius(10.0)
                        .inner_margin(egui::Margin::same(14)),
                )
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        icon(ui, 14.0, icon_kind, icon_color);
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new(status.as_str())
                                .size(13.0)
                                .color(TEXT),
                        );
                    });
                });
            // Dismiss only on a click that lands on the toast itself, not
            // on arbitrary clicks elsewhere in the window (which would
            // prevent the user from ever reading the banner).
            if let Some(resp) = response {
                if resp.response.clicked() {
                    dismiss = true;
                }
            }
            if dismiss {
                self.save_status = None;
                self.save_status_time = None;
            }
        }

        // ── Age save popup ──
        self.render_save_popup(ctx);

        // ── Expert-mode save choice popup (encrypt vs plaintext) ──
        self.render_save_choice_popup(ctx);

        // ── Age decrypt popup (Recover tab) ──
        if self.rec_mut().decrypt_popup_open && self.decrypt_popup.is_none() {
            self.decrypt_popup = Some(DecryptPopupState {
                method: DecryptPopupMethod::default(),
                slide_offset: 0.0,
            });
        }
        self.render_decrypt_popup(ctx);

        // ── One-time "results won't persist" warning ──
        // Shown the first time the user navigates away from a tab that holds
        // a result, unless they have already enabled result persistence.
        if let Some(switch) = self.pending_switch {
            let mut proceed = false;
            let mut cancel = false;
            egui::Window::new("Leaving this tab clears its contents")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .frame(
                    egui::Frame::window(&ctx.style())
                        .fill(CARD_BG)
                        .stroke(egui::Stroke::new(1.0, AMBER)),
                )
                .show(ctx, |ui| {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        icon(ui, 22.0, Icon::Warning, AMBER);
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new("Results don't persist between tabs")
                                .size(16.0)
                                .strong()
                                .color(TEXT_BRIGHT),
                        );
                    });
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(
                            "Switching tabs clears everything you entered and any\n\
                             result on the tab you're leaving, so it won't be here\n\
                             when you come back. This is a security measure: seeds,\n\
                             shares, and passwords shouldn't linger on screen after\n\
                             you move on.\n\
                             \n\
                             You can keep inputs and results when switching tabs\n\
                             instead. All data is still wiped when the app exits.",
                        )
                        .size(13.0)
                        .color(TEXT),
                    );
                    ui.add_space(12.0);
                    ui.checkbox(
                        &mut self.persist_outputs,
                        "Keep inputs and results when switching tabs (wiped on exit)",
                    );
                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                        ui.add_space(10.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("I understand")
                                        .strong()
                                        .color(ON_AMBER),
                                )
                                .fill(AMBER)
                                .corner_radius(8.0),
                            )
                            .clicked()
                        {
                            proceed = true;
                        }
                    });
                });
            if proceed {
                // Acknowledge once per session; never show again after this.
                self.warned_no_persist = true;
                self.pending_switch = None;
                self.apply_switch(switch);
            }
            if cancel {
                // Stay on the current tab; inputs and result are preserved.
                self.pending_switch = None;
            }
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.wipe_all();
        // Clear any open popups (they hold share text / passphrases).
        self.save_popup = None;
        self.save_choice = None;
        self.decrypt_popup = None;
        self.save_rx = None;
        self.decrypt_rx = None;
        self.file_load_rx = None;
        self.file_load_target = None;
        self.save_status = None;
        self.clear_egui_caches();
        if let Some(ctx) = self.ctx.take() {
            // Best-effort: overwrite the system clipboard so a previously
            // copied secret does not persist beyond the app. (OS clipboard
            // history managers may still retain a copy; this clears only the
            // live clipboard.)
            ctx.copy_text(String::new());
        }
    }
}

// ─── Worker polling ─────────────────────────────────────────────────────────

impl App {
    fn poll_workers(&mut self) {
        let tabs = [
            (CoinTab::Bitcoin, ModeTab::Generate),
            (CoinTab::Monero, ModeTab::Generate),
            (CoinTab::Bitcoin, ModeTab::Split),
            (CoinTab::Monero, ModeTab::Split),
            (CoinTab::Bitcoin, ModeTab::Recover),
            (CoinTab::Monero, ModeTab::Recover),
            (CoinTab::Bitcoin, ModeTab::Derive),
            (CoinTab::Monero, ModeTab::Derive),
        ];
        for (coin, mode) in tabs {
            let (saved_coin, saved_mode) = (self.coin_tab, self.mode_tab);
            self.coin_tab = coin;
            self.mode_tab = mode;
            match mode {
                ModeTab::Generate => {
                    if let Some(rx) = self.gen_mut().rx.take() {
                        match rx.try_recv() {
                            Ok(WorkerMsg::Generate(Ok(r))) => {
                                self.gen_mut().busy = false;
                                self.gen_mut().output = Some(r.into());
                                self.gen_mut().error = None;
                            }
                            Ok(WorkerMsg::Generate(Err(e))) => {
                                self.gen_mut().busy = false;
                                self.gen_mut().output = None;
                                self.gen_mut().error = Some(Zeroizing::new(e));
                            }
                            Ok(_) => {
                                // Unexpected variant for this tab; reset to idle.
                                self.gen_mut().busy = false;
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                // Worker still running; put the receiver back.
                                self.gen_mut().rx = Some(rx);
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                // Worker thread panicked or dropped tx without
                                // sending. Surface a clean error instead of
                                // leaving the tab spinning forever (audit L-5).
                                self.gen_mut().busy = false;
                                self.gen_mut().error = Some(Zeroizing::new(
                                    WORKER_DISCONNECTED_MSG.to_owned(),
                                ));
                            }
                        }
                    }
                }
                ModeTab::Split => {
                    if let Some(rx) = self.split_mut().rx.take() {
                        match rx.try_recv() {
                            Ok(WorkerMsg::Split(Ok(r))) => {
                                self.split_mut().busy = false;
                                self.split_mut().output = Some(r);
                                self.split_mut().error = None;
                            }
                            Ok(WorkerMsg::Split(Err(e))) => {
                                self.split_mut().busy = false;
                                self.split_mut().output = None;
                                self.split_mut().error = Some(Zeroizing::new(e));
                            }
                            Ok(_) => {
                                self.split_mut().busy = false;
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                self.split_mut().rx = Some(rx);
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                self.split_mut().busy = false;
                                self.split_mut().error = Some(Zeroizing::new(
                                    WORKER_DISCONNECTED_MSG.to_owned(),
                                ));
                            }
                        }
                    }
                }
                ModeTab::Recover => {
                    if let Some(rx) = self.rec_mut().rx.take() {
                        match rx.try_recv() {
                            Ok(WorkerMsg::Recover(Ok(r))) => {
                                self.rec_mut().busy = false;
                                self.rec_mut().output = Some(r.into());
                                self.rec_mut().error = None;
                            }
                            Ok(WorkerMsg::Recover(Err(e))) => {
                                self.rec_mut().busy = false;
                                self.rec_mut().output = None;
                                self.rec_mut().error = Some(Zeroizing::new(e));
                            }
                            Ok(_) => {
                                self.rec_mut().busy = false;
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                self.rec_mut().rx = Some(rx);
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                self.rec_mut().busy = false;
                                self.rec_mut().error = Some(Zeroizing::new(
                                    WORKER_DISCONNECTED_MSG.to_owned(),
                                ));
                            }
                        }
                    }
                }
                ModeTab::Derive => {
                    if let Some(rx) = self.derive_mut().rx.take() {
                        match rx.try_recv() {
                            Ok(WorkerMsg::Derive(Ok(r))) => {
                                self.derive_mut().busy = false;
                                self.derive_mut().output = Some(r.into());
                                self.derive_mut().error = None;
                            }
                            Ok(WorkerMsg::Derive(Err(e))) => {
                                self.derive_mut().busy = false;
                                self.derive_mut().output = None;
                                self.derive_mut().error = Some(Zeroizing::new(e));
                            }
                            Ok(_) => {
                                self.derive_mut().busy = false;
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                self.derive_mut().rx = Some(rx);
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                self.derive_mut().busy = false;
                                self.derive_mut().error = Some(Zeroizing::new(
                                    WORKER_DISCONNECTED_MSG.to_owned(),
                                ));
                            }
                        }
                    }
                }
            }
            self.coin_tab = saved_coin;
            self.mode_tab = saved_mode;
        }
    }

    fn wipe_all(&mut self) {
        for gen in [&mut self.btc_gen, &mut self.xmr_gen] {
            gen.real_password = Zeroizing::new(String::new());
            gen.real_password_confirm = Zeroizing::new(String::new());
            gen.decoy_password = Zeroizing::new(String::new());
            gen.decoy_password_confirm = Zeroizing::new(String::new());
            gen.output = None;
        }
        for split in [&mut self.btc_split, &mut self.xmr_split] {
            split.secret_input = Zeroizing::new(String::new());
            split.password = Zeroizing::new(String::new());
            split.password_confirm = Zeroizing::new(String::new());
            split.decoy_password = Zeroizing::new(String::new());
            split.decoy_password_confirm = Zeroizing::new(String::new());
            split.output = None;
        }
        for rec in [&mut self.btc_rec, &mut self.xmr_rec] {
            rec.shares_text = Zeroizing::new(String::new());
            rec.password = Zeroizing::new(String::new());
            rec.password_confirm = Zeroizing::new(String::new());
            rec.output = None;
            rec.decrypt_popup_open = false;
            rec.decrypted = false;
            rec.decrypted_count = 0;
            rec.cached_analysis = None;
            rec.pending_armoured.clear();
        }
        for d in [&mut self.btc_derive, &mut self.xmr_derive] {
            d.input = Zeroizing::new(String::new());
            d.output = None;
        }
        // Cancel any pending file-load dialog — its result would have
        // nowhere to go after the popups are wiped below.
        self.file_load_rx = None;
        self.file_load_target = None;
    }

    /// Drop egui's per-widget state store and galley cache.
    ///
    /// egui caches per-widget state (including TextEdit undo stacks, which
    /// hold copies of the password / share text entered into the input
    /// fields) in `Memory::data`. Wiping the underlying `Zeroizing` buffers
    /// does NOT touch that stack, so the secrets could otherwise be recovered
    /// by pressing Ctrl+Z. The galley cache (`Memory::caches`) holds
    /// `LayoutJob`s whose `text: String` is the full source of every laid-out
    /// label — including the selectable share / key labels — so it is cleared
    /// too. Called on every non-persistent tab switch and on app exit.
    fn clear_egui_caches(&mut self) {
        if let Some(ctx) = &self.ctx {
            ctx.memory_mut(|m| m.data.clear());
            ctx.memory_mut(|m| m.caches = egui::cache::CacheStorage::default());
        }
    }

    /// Switch the active coin tab, wiping the secrets (inputs and results)
    /// of the tab being left so they don't linger after navigation —
    /// *unless* the user has enabled result persistence, in which case they
    /// are retained (everything is still wiped on app exit).
    fn switch_coin_tab(&mut self, new: CoinTab) {
        if self.coin_tab == new {
            return;
        }
        if !self.persist_outputs {
            self.wipe_current_secrets();
            // egui keeps a per-widget undo stack (Ctrl+Z history) for every
            // TextEdit in `Memory::data`, holding copies of the text that was
            // typed into the input fields. Wiping the underlying `Zeroizing`
            // buffers above does NOT touch that stack, so the secrets could
            // otherwise be recovered by pressing Ctrl+Z on the new tab. Drop
            // the whole per-widget store (and the galley cache, whose
            // LayoutJobs hold the laid-out result-label strings) on every
            // non-persistent navigation.
            self.clear_egui_caches();
        }
        self.coin_tab = new;
    }

    /// Switch the active mode tab, wiping the secrets (inputs and results)
    /// of the tab being left so they don't linger after navigation —
    /// *unless* the user has enabled result persistence, in which case they
    /// are retained (everything is still wiped on app exit).
    fn switch_mode_tab(&mut self, new: ModeTab) {
        if self.mode_tab == new {
            return;
        }
        if !self.persist_outputs {
            self.wipe_current_secrets();
            self.clear_egui_caches();
        }
        self.mode_tab = new;
    }

    /// Wipe the sensitive inputs, `output`, and `error` of the currently-
    /// active coin+mode tab. Only the currently-visible tab is allowed to
    /// hold secret material. Non-secret configuration (share counts,
    /// iteration counts, the decoy toggle, advanced-panel state) is left
    /// intact so the user's preferences survive navigation.
    fn wipe_current_secrets(&mut self) {
        match (self.coin_tab, self.mode_tab) {
            (CoinTab::Bitcoin, ModeTab::Generate) => {
                self.btc_gen.real_password = Zeroizing::new(String::new());
                self.btc_gen.real_password_confirm = Zeroizing::new(String::new());
                self.btc_gen.decoy_password = Zeroizing::new(String::new());
                self.btc_gen.decoy_password_confirm = Zeroizing::new(String::new());
                self.btc_gen.output = None;
                self.btc_gen.error = None;
            }
            (CoinTab::Monero, ModeTab::Generate) => {
                self.xmr_gen.real_password = Zeroizing::new(String::new());
                self.xmr_gen.real_password_confirm = Zeroizing::new(String::new());
                self.xmr_gen.decoy_password = Zeroizing::new(String::new());
                self.xmr_gen.decoy_password_confirm = Zeroizing::new(String::new());
                self.xmr_gen.output = None;
                self.xmr_gen.error = None;
            }
            (CoinTab::Bitcoin, ModeTab::Split) => {
                self.btc_split.secret_input = Zeroizing::new(String::new());
                self.btc_split.password = Zeroizing::new(String::new());
                self.btc_split.password_confirm = Zeroizing::new(String::new());
                self.btc_split.decoy_password = Zeroizing::new(String::new());
                self.btc_split.decoy_password_confirm = Zeroizing::new(String::new());
                self.btc_split.output = None;
                self.btc_split.error = None;
            }
            (CoinTab::Monero, ModeTab::Split) => {
                self.xmr_split.secret_input = Zeroizing::new(String::new());
                self.xmr_split.password = Zeroizing::new(String::new());
                self.xmr_split.password_confirm = Zeroizing::new(String::new());
                self.xmr_split.decoy_password = Zeroizing::new(String::new());
                self.xmr_split.decoy_password_confirm = Zeroizing::new(String::new());
                self.xmr_split.output = None;
                self.xmr_split.error = None;
            }
            (CoinTab::Bitcoin, ModeTab::Recover) => {
                self.btc_rec.shares_text = Zeroizing::new(String::new());
                self.btc_rec.password = Zeroizing::new(String::new());
                self.btc_rec.password_confirm = Zeroizing::new(String::new());
                self.btc_rec.output = None;
                self.btc_rec.error = None;
                self.btc_rec.decrypt_popup_open = false;
                self.btc_rec.decrypted = false;
                self.btc_rec.decrypted_count = 0;
                self.btc_rec.cached_analysis = None;
                self.btc_rec.pending_armoured.clear();
                self.decrypt_popup = None;
                self.decrypt_rx = None;
                self.file_load_rx = None;
                self.file_load_target = None;
            }
            (CoinTab::Monero, ModeTab::Recover) => {
                self.xmr_rec.shares_text = Zeroizing::new(String::new());
                self.xmr_rec.password = Zeroizing::new(String::new());
                self.xmr_rec.password_confirm = Zeroizing::new(String::new());
                self.xmr_rec.output = None;
                self.xmr_rec.error = None;
                self.xmr_rec.decrypt_popup_open = false;
                self.xmr_rec.decrypted = false;
                self.xmr_rec.decrypted_count = 0;
                self.xmr_rec.cached_analysis = None;
                self.xmr_rec.pending_armoured.clear();
                self.decrypt_popup = None;
                self.decrypt_rx = None;
                self.file_load_rx = None;
                self.file_load_target = None;
            }
            (CoinTab::Bitcoin, ModeTab::Derive) => {
                self.btc_derive.input = Zeroizing::new(String::new());
                self.btc_derive.output = None;
                self.btc_derive.error = None;
            }
            (CoinTab::Monero, ModeTab::Derive) => {
                self.xmr_derive.input = Zeroizing::new(String::new());
                self.xmr_derive.output = None;
                self.xmr_derive.error = None;
            }
        }
    }

    /// Does the currently-active coin+mode tab hold any secret material
    /// (a result, or non-empty input fields)? Used to decide whether
    /// navigating away would discard anything the user might miss.
    fn current_tab_has_data(&self) -> bool {
        match (self.coin_tab, self.mode_tab) {
            (CoinTab::Bitcoin, ModeTab::Generate) => {
                self.btc_gen.output.is_some()
                    || !self.btc_gen.real_password.is_empty()
                    || !self.btc_gen.decoy_password.is_empty()
            }
            (CoinTab::Monero, ModeTab::Generate) => {
                self.xmr_gen.output.is_some()
                    || !self.xmr_gen.real_password.is_empty()
                    || !self.xmr_gen.decoy_password.is_empty()
            }
            (CoinTab::Bitcoin, ModeTab::Split) => {
                self.btc_split.output.is_some()
                    || !self.btc_split.secret_input.is_empty()
                    || !self.btc_split.password.is_empty()
                    || !self.btc_split.decoy_password.is_empty()
            }
            (CoinTab::Monero, ModeTab::Split) => {
                self.xmr_split.output.is_some()
                    || !self.xmr_split.secret_input.is_empty()
                    || !self.xmr_split.password.is_empty()
                    || !self.xmr_split.decoy_password.is_empty()
            }
            (CoinTab::Bitcoin, ModeTab::Recover) => {
                self.btc_rec.output.is_some()
                    || !self.btc_rec.shares_text.is_empty()
                    || !self.btc_rec.password.is_empty()
                    || !self.btc_rec.pending_armoured.is_empty()
            }
            (CoinTab::Monero, ModeTab::Recover) => {
                self.xmr_rec.output.is_some()
                    || !self.xmr_rec.shares_text.is_empty()
                    || !self.xmr_rec.password.is_empty()
                    || !self.xmr_rec.pending_armoured.is_empty()
            }
            (CoinTab::Bitcoin, ModeTab::Derive) => {
                self.btc_derive.output.is_some() || !self.btc_derive.input.is_empty()
            }
            (CoinTab::Monero, ModeTab::Derive) => {
                self.xmr_derive.output.is_some() || !self.xmr_derive.input.is_empty()
            }
        }
    }

    /// Entry point for a user-initiated tab switch. If result persistence is
    /// enabled, or the current tab has nothing to lose, or the one-time
    /// warning has already been acknowledged, the switch is applied
    /// immediately. Otherwise it is deferred to the confirmation dialog.
    fn request_switch(&mut self, switch: PendingSwitch) {
        let needs_dialog = !self.persist_outputs
            && self.current_tab_has_data()
            && !self.warned_no_persist;
        if needs_dialog {
            self.pending_switch = Some(switch);
        } else {
            self.apply_switch(switch);
        }
    }

    /// Apply a tab switch unconditionally (honoring `persist_outputs` via the
    /// wipe guard inside `switch_coin_tab` / `switch_mode_tab`).
    fn apply_switch(&mut self, switch: PendingSwitch) {
        match switch {
            PendingSwitch::Coin(c) => self.switch_coin_tab(c),
            PendingSwitch::Mode(m) => self.switch_mode_tab(m),
        }
    }
}

// ─── Generate tab ───────────────────────────────────────────────────────────

impl App {
    fn render_generate(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let coin = self.coin();
        let coin_label = match coin {
            Coin::Bitcoin => "Bitcoin",
            Coin::Monero => "Monero",
        };
        let mut start = false;
        let mut real_actions: Option<ShareCardActions> = None;
        let mut decoy_actions: Option<ShareCardActions> = None;

        {
            let gen = self.gen_mut();

            // ── Intro card ──
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    egui::RichText::new(format!(
                        "Generate a duress-compatible {coin_label} wallet pair"
                    ))
                    .size(16.0)
                    .strong()
                    .color(TEXT_BRIGHT),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "A Real wallet and an optional Decoy wallet will be created. The Decoy \
                         uses a different password and secret, but its shares are indistinguishable \
                         from the Real wallet's shares — so an attacker cannot tell which is which."
                    )
                    .size(13.0)
                    .color(TEXT_WEAK),
                );
            });

            ui.add_space(10.0);

            // ── Configuration card ──
            card(ui, |ui| {
                ui.set_width(ui.available_width());

                section_header(ui, "Share Configuration");

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        field_label(ui, "Shares needed to recover");
                        share_combo(ui, "threshold", &mut gen.threshold, 1, gen.total_shares);
                    });
                    ui.add_space(32.0);
                    ui.vertical(|ui| {
                        field_label(ui, "Total shares to create");
                        let prev_total = gen.total_shares;
                        share_combo(ui, "total", &mut gen.total_shares, 1, MAX_SHARES);
                        // Clamp threshold immediately if total dropped below it.
                        if gen.total_shares < prev_total && gen.threshold > gen.total_shares {
                            gen.threshold = gen.total_shares;
                        }
                    });
                });
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!(
                        "You need {} of {} shares to recover the wallet.",
                        gen.threshold.min(gen.total_shares),
                        gen.total_shares,
                    ))
                    .size(12.0)
                    .color(TEXT_WEAK),
                );

                ui.add_space(14.0);
                divider(ui);
                ui.add_space(14.0);

                // ── Passwords ──
                section_header(ui, "Passwords");

                field_label(ui, "Real wallet password");
                let r1 = ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut *gen.real_password)
                        .password(true)
                        .id_salt("real_pass"),
                );

                ui.add_space(8.0);

                field_label(ui, "Confirm Real wallet password");
                let r2 = ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut *gen.real_password_confirm)
                        .password(true)
                        .id_salt("real_pass_confirm"),
                );

                // Live mismatch hint for the real password.
                if !gen.real_password.is_empty()
                    || !gen.real_password_confirm.is_empty()
                {
                    let matches = gen.real_password.as_str() == gen.real_password_confirm.as_str();
                    if !matches {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            icon(ui, 13.0, Icon::Warning, RED);
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("Passwords do not match.")
                                    .size(12.0)
                                    .color(RED),
                            );
                        });
                    } else {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            icon(ui, 13.0, Icon::Check, GREEN);
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("Passwords match.")
                                    .size(12.0)
                                    .color(GREEN),
                            );
                        });
                    }
                }

                ui.add_space(10.0);

                ui.checkbox(&mut gen.generate_decoy, "Generate Decoy Wallet");

                if gen.generate_decoy {
                    ui.add_space(8.0);
                    field_label(ui, "Decoy wallet password");
                    let r3 = ui.add_sized(
                        [ui.available_width(), 36.0],
                        egui::TextEdit::singleline(&mut *gen.decoy_password)
                            .password(true)
                            .id_salt("decoy_pass"),
                    );

                    ui.add_space(8.0);

                    field_label(ui, "Confirm Decoy wallet password");
                    let r4 = ui.add_sized(
                        [ui.available_width(), 36.0],
                        egui::TextEdit::singleline(&mut *gen.decoy_password_confirm)
                            .password(true)
                            .id_salt("decoy_pass_confirm"),
                    );

                    if !gen.decoy_password.is_empty()
                        || !gen.decoy_password_confirm.is_empty()
                    {
                        let matches =
                            gen.decoy_password.as_str() == gen.decoy_password_confirm.as_str();
                        if !matches {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                icon(ui, 13.0, Icon::Warning, RED);
                                ui.add_space(4.0);
                                ui.label(
                                    egui::RichText::new("Decoy passwords do not match.")
                                        .size(12.0)
                                        .color(RED),
                                );
                            });
                        } else {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                icon(ui, 13.0, Icon::Check, GREEN);
                                ui.add_space(4.0);
                                ui.label(
                                    egui::RichText::new("Decoy passwords match.")
                                        .size(12.0)
                                        .color(GREEN),
                                );
                            });
                        }
                    }

                    if r3.changed() || r4.changed() {
                        gen.error = None;
                    }
                }

                if r1.changed() || r2.changed() {
                    gen.error = None;
                }

                ui.add_space(14.0);
                divider(ui);
                ui.add_space(10.0);

                // ── Advanced ──
                let avail_w = ui.available_width();
                let (hrect, hresp) =
                    ui.allocate_exact_size(egui::vec2(avail_w, 22.0), egui::Sense::click());
                let p = ui.painter();
                if hresp.hovered() {
                    p.rect_filled(hrect, 6.0, CARD_BG_LIGHT);
                }
                draw_icon_at(
                    p,
                    egui::pos2(hrect.left() + 7.0, hrect.center().y),
                    10.0,
                    if gen.advanced_open {
                        Icon::TriangleDown
                    } else {
                        Icon::TriangleRight
                    },
                    TEXT_WEAK,
                );
                p.text(
                    egui::pos2(hrect.left() + 22.0, hrect.center().y),
                    egui::Align2::LEFT_CENTER,
                    "Advanced Settings",
                    egui::FontId::proportional(13.0),
                    TEXT_WEAK,
                );
                if hresp.clicked() {
                    gen.advanced_open = !gen.advanced_open;
                }

                if gen.advanced_open {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        field_label(ui, "KDF iterations");
                        let labels = ["Default (1)", "High (2)"];
                        egui::ComboBox::from_id_salt("iter_combo")
                            .selected_text(labels[gen.iterations.min(1)])
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut gen.iterations, 0, "Default (1)");
                                ui.selectable_value(&mut gen.iterations, 1, "High (2)");
                            });
                    });
                    ui.label(
                        egui::RichText::new(
                            "Higher values make brute-force attacks harder but slow down generation."
                        )
                        .size(12.0)
                        .color(TEXT_WEAK),
                    );
                }

                ui.add_space(16.0);

                // ── Generate button ──
                let can_run = !gen.busy;
                let real_empty = gen.real_password.is_empty();
                let decoy_empty = gen.generate_decoy && gen.decoy_password.is_empty();

                let button_text = if gen.busy {
                    "Generating…"
                } else {
                    "Generate Wallets"
                };
                let btn = primary_button(ui, button_text, can_run);
                if btn.clicked() && can_run {
                    let real_match =
                        gen.real_password.as_str() == gen.real_password_confirm.as_str();
                    let decoy_match = !gen.generate_decoy
                        || gen.decoy_password.as_str() == gen.decoy_password_confirm.as_str();
                    if !real_match {
                        gen.error = Some(Zeroizing::new(
                            "The Real wallet passwords do not match. Please re-type them identically."
                                .to_owned(),
                        ));
                    } else if !decoy_match {
                        gen.error = Some(Zeroizing::new(
                            "The Decoy wallet passwords do not match. Please re-type them identically."
                                .to_owned(),
                        ));
                    } else if real_empty || decoy_empty {
                        gen.error = None;
                        gen.confirm_empty_pass = true;
                    } else {
                        gen.error = None;
                        start = true;
                    }
                }

                if gen.busy {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new("This may take a few seconds…")
                                .size(13.0)
                                .color(TEXT_WEAK),
                        );
                    });
                }
            });

            // ── Error ──
            if let Some(err) = &gen.error {
                ui.add_space(10.0);
                error_card(ui, err.as_str());
            }

            // ── Results ──
            // Collect save actions from share cards; react after the borrow ends.
            if let Some(out) = &gen.output {
                ui.add_space(14.0);
                warning_banner(ui);

                ui.add_space(10.0);
                real_actions = Some(share_card(
                    ui,
                    ctx,
                    "REAL WALLET SHARES",
                    GREEN,
                    GREEN_BG,
                    &out.real_shares,
                    "real_save",
                ));

                if gen.generate_decoy && !out.decoy_shares.is_empty() {
                    ui.add_space(10.0);
                    decoy_actions = Some(share_card(
                        ui,
                        ctx,
                        "DECOY WALLET SHARES",
                        ORANGE,
                        ORANGE_BG,
                        &out.decoy_shares,
                        "decoy_save",
                    ));
                }

                if let Some(m) = &out.real_monero {
                    ui.add_space(10.0);
                    monero_card(ui, "Real Monero Wallet (verify)", GREEN, GREEN_BG, m);
                }
                if let Some(m) = &out.decoy_monero {
                    ui.add_space(10.0);
                    monero_card(ui, "Decoy Monero Wallet (verify)", ORANGE, ORANGE_BG, m);
                }
            } // closes if let Some(out)
        } // gen borrow ends

        // ── Handle save-card actions (after gen borrow ends) ──
        if let Some(ra) = real_actions {
            let (shares_text, threshold) = {
                let gen = self.gen_mut();
                if let Some(out) = &gen.output {
                    (out.real_shares.clone(), gen.threshold)
                } else {
                    (Zeroizing::new(String::new()), 2)
                }
            };
            self.handle_share_card_actions(ctx, ra, false, "Real", shares_text, threshold);
        }
        if let Some(da) = decoy_actions {
            let (shares_text, threshold) = {
                let gen = self.gen_mut();
                if let Some(out) = &gen.output {
                    (out.decoy_shares.clone(), gen.threshold)
                } else {
                    (Zeroizing::new(String::new()), 2)
                }
            };
            self.handle_share_card_actions(ctx, da, true, "Decoy", shares_text, threshold);
        }

        // ── Empty-password confirmation dialog ──
        if self.gen_mut().confirm_empty_pass {
            let mut proceed = false;
            let mut cancel = false;
            egui::Window::new("No Password Set")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .frame(
                    egui::Frame::window(ui.style())
                        .fill(CARD_BG)
                        .stroke(egui::Stroke::new(1.0, AMBER)),
                )
                .show(ctx, |ui| {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        icon(ui, 22.0, Icon::Warning, AMBER);
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new("No Password Set")
                                .size(16.0)
                                .strong()
                                .color(TEXT_BRIGHT),
                        );
                    });
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(
                            "You are about to generate a wallet with an empty password.\n\
                             Without a password, anyone who obtains enough shares\n\
                             can recover the wallet — there is no second factor.\n\
                             This significantly reduces your security."
                        )
                        .size(13.0)
                        .color(TEXT),
                    );
                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                        ui.add_space(10.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("Continue Anyway")
                                        .strong()
                                        .color(ON_AMBER),
                                )
                                .fill(AMBER)
                                .corner_radius(8.0),
                            )
                            .clicked()
                        {
                            proceed = true;
                        }
                    });
                });
            if proceed {
                self.gen_mut().confirm_empty_pass = false;
                start = true;
            }
            if cancel {
                self.gen_mut().confirm_empty_pass = false;
            }
        }

        if start {
            self.start_generate(ctx);
        }
    }

    fn start_generate(&mut self, ctx: &egui::Context) {
        let coin = self.coin();
        let gen = self.gen_mut();
        let threshold = gen.threshold.min(gen.total_shares);
        let total = gen.total_shares;
        let iterations = gui_support::ITERATION_OPTIONS[gen.iterations.min(1)];
        // Wrap secrets in Zeroizing so the worker thread's owned copies are
        // wiped from RAM when the closure (and its String buffer) is dropped.
        let real_pass = Zeroizing::new(gen.real_password.as_str().to_owned());
        let generate_decoy = gen.generate_decoy;
        let decoy_pass = if generate_decoy {
            Zeroizing::new(gen.decoy_password.as_str().to_owned())
        } else {
            Zeroizing::new(String::new())
        };

        gen.busy = true;
        gen.output = None;
        gen.error = None;

        let (tx, rx) = mpsc::channel();
        gen.rx = Some(rx);

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = gui_support::generate_duress(
                coin,
                threshold,
                total,
                iterations,
                real_pass.as_str(),
                generate_decoy,
                decoy_pass.as_str(),
            );
            let mapped = result.map_err(|e| classify_generate_error(&e));
            let _ = tx.send(WorkerMsg::Generate(mapped));
            ctx.request_repaint();
            // real_pass / decoy_pass drop here -> zeroized.
        });
    }
}

// ─── Split tab ──────────────────────────────────────────────────────────────

impl App {
    fn render_split(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let coin = self.coin();
        let (coin_label, intro_text, field_text, unrecognized_hint) = match coin {
            Coin::Bitcoin => (
                "Bitcoin",
                "Paste an existing 12/15/18/21/24-word BIP-39 mnemonic (Bitcoin, Ethereum, etc.). \
                 The format is auto-detected and split into SLIP-0039 shares.",
                "Paste your BIP-39 seed phrase",
                "Expected a 12/15/18/21/24-word BIP-39 mnemonic.",
            ),
            Coin::Monero => (
                "Monero",
                "Paste an existing Monero spend key (64-char hex) or 25-word Monero mnemonic. \
                 The format is auto-detected and split into SLIP-0039 shares.",
                "Paste your Monero spend key (hex) or 25-word mnemonic",
                "Expected a 64-char hex spend key or a 25-word Monero mnemonic.",
            ),
        };
        let mut start = false;
        let mut split_actions: Option<ShareCardActions> = None;
        let mut decoy_actions: Option<ShareCardActions> = None;

        {
            let split = self.split_mut();

            // ── Intro card ──
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    egui::RichText::new(format!("Split an existing {coin_label} wallet into shares"))
                        .size(16.0)
                        .strong()
                        .color(TEXT_BRIGHT),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(intro_text)
                        .size(13.0)
                        .color(TEXT_WEAK),
                );
            });

            ui.add_space(10.0);

            // ── Secret input card ──
            card(ui, |ui| {
                ui.set_width(ui.available_width());

                section_header(ui, "Your Secret");
                field_label(ui, field_text);
                ui.add_sized(
                    [ui.available_width(), 120.0],
                    egui::TextEdit::multiline(&mut *split.secret_input)
                        .code_editor()
                        .id_salt("split_secret"),
                );

                // ── Live format detection ──
                let word_count = split
                    .secret_input
                    .split_whitespace()
                    .count();
                let detected = if !split.secret_input.trim().is_empty() {
                    match (coin, word_count) {
                        (Coin::Monero, 1) => Some("Hex spend key"),
                        (Coin::Monero, 25) => Some("25-word Monero mnemonic"),
                        (Coin::Bitcoin, 12 | 15 | 18 | 21 | 24) => Some("BIP-39 mnemonic"),
                        _ => None,
                    }
                } else {
                    None
                };
                if let Some(label) = detected {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        icon(ui, 13.0, Icon::Check, GREEN);
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!("Detected: {label}"))
                                .size(12.0)
                                .color(GREEN),
                        );
                    });
                } else if !split.secret_input.trim().is_empty() {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        icon(ui, 13.0, Icon::Warning, AMBER);
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                unrecognized_hint
                            )
                            .size(12.0)
                            .color(AMBER),
                        );
                    });
                }

                ui.add_space(14.0);
                divider(ui);
                ui.add_space(14.0);

                // ── Share Configuration ──
                section_header(ui, "Share Configuration");

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        field_label(ui, "Shares needed to recover");
                        share_combo(ui, "split_threshold", &mut split.threshold, 1, split.total_shares);
                    });
                    ui.add_space(32.0);
                    ui.vertical(|ui| {
                        field_label(ui, "Total shares to create");
                        let prev_total = split.total_shares;
                        share_combo(ui, "split_total", &mut split.total_shares, 1, MAX_SHARES);
                        if split.total_shares < prev_total && split.threshold > split.total_shares {
                            split.threshold = split.total_shares;
                        }
                    });
                });

                ui.add_space(14.0);
                divider(ui);
                ui.add_space(14.0);

                // ── Passwords ──
                section_header(ui, "Password");

                field_label(ui, "Password");
                let p1 = ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut *split.password)
                        .password(true)
                        .id_salt("split_pass"),
                );

                ui.add_space(8.0);

                field_label(ui, "Confirm password");
                let p2 = ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut *split.password_confirm)
                        .password(true)
                        .id_salt("split_pass_confirm"),
                );

                if !split.password.is_empty() || !split.password_confirm.is_empty() {
                    let matches = split.password.as_str() == split.password_confirm.as_str();
                    if !matches {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            icon(ui, 13.0, Icon::Warning, RED);
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("Passwords do not match.")
                                    .size(12.0)
                                    .color(RED),
                            );
                        });
                    } else {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            icon(ui, 13.0, Icon::Check, GREEN);
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("Passwords match.")
                                    .size(12.0)
                                    .color(GREEN),
                            );
                        });
                    }
                }

                if p1.changed() || p2.changed() {
                    split.error = None;
                }

                ui.add_space(14.0);
                divider(ui);
                ui.add_space(14.0);

                // ── Decoy Wallet (duress) ──
                section_header(ui, "Decoy Wallet");
                ui.checkbox(&mut split.generate_decoy, "Generate Decoy Wallet");
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "A Decoy wallet uses a different password and a different \
                         (random) secret, but its shares are indistinguishable \
                         from the Real wallet's shares — so an attacker cannot \
                         tell which is which. If coerced, reveal the Decoy \
                         password."
                    )
                    .size(12.0)
                    .color(TEXT_WEAK),
                );

                if split.generate_decoy {
                    ui.add_space(8.0);
                    field_label(ui, "Decoy wallet password");
                    let d1 = ui.add_sized(
                        [ui.available_width(), 36.0],
                        egui::TextEdit::singleline(&mut *split.decoy_password)
                            .password(true)
                            .id_salt("split_decoy_pass"),
                    );
                    ui.add_space(8.0);
                    field_label(ui, "Confirm Decoy wallet password");
                    let d2 = ui.add_sized(
                        [ui.available_width(), 36.0],
                        egui::TextEdit::singleline(&mut *split.decoy_password_confirm)
                            .password(true)
                            .id_salt("split_decoy_pass_confirm"),
                    );
                    if !split.decoy_password.is_empty()
                        || !split.decoy_password_confirm.is_empty()
                    {
                        let matches =
                            split.decoy_password.as_str()
                                == split.decoy_password_confirm.as_str();
                        if !matches {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                icon(ui, 13.0, Icon::Warning, RED);
                                ui.add_space(4.0);
                                ui.label(
                                    egui::RichText::new("Decoy passwords do not match.")
                                        .size(12.0)
                                        .color(RED),
                                );
                            });
                        } else {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                icon(ui, 13.0, Icon::Check, GREEN);
                                ui.add_space(4.0);
                                ui.label(
                                    egui::RichText::new("Decoy passwords match.")
                                        .size(12.0)
                                        .color(GREEN),
                                );
                            });
                        }
                    }
                    if d1.changed() || d2.changed() {
                        split.error = None;
                    }
                }

                ui.add_space(14.0);
                divider(ui);
                ui.add_space(10.0);

                // ── Advanced ──
                let avail_w = ui.available_width();
                let (hrect, hresp) =
                    ui.allocate_exact_size(egui::vec2(avail_w, 22.0), egui::Sense::click());
                let p = ui.painter();
                if hresp.hovered() {
                    p.rect_filled(hrect, 6.0, CARD_BG_LIGHT);
                }
                draw_icon_at(
                    p,
                    egui::pos2(hrect.left() + 7.0, hrect.center().y),
                    10.0,
                    if split.advanced_open {
                        Icon::TriangleDown
                    } else {
                        Icon::TriangleRight
                    },
                    TEXT_WEAK,
                );
                p.text(
                    egui::pos2(hrect.left() + 22.0, hrect.center().y),
                    egui::Align2::LEFT_CENTER,
                    "Advanced Settings",
                    egui::FontId::proportional(13.0),
                    TEXT_WEAK,
                );
                if hresp.clicked() {
                    split.advanced_open = !split.advanced_open;
                }

                if split.advanced_open {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        field_label(ui, "KDF iterations");
                        let labels = ["Default (1)", "High (2)"];
                        egui::ComboBox::from_id_salt("split_iter_combo")
                            .selected_text(labels[split.iterations.min(1)])
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut split.iterations, 0, "Default (1)");
                                ui.selectable_value(&mut split.iterations, 1, "High (2)");
                            });
                    });
                    ui.label(
                        egui::RichText::new(
                            "Higher values make brute-force attacks harder but slow down splitting."
                        )
                        .size(12.0)
                        .color(TEXT_WEAK),
                    );
                }

                ui.add_space(16.0);

                // ── Split button ──
                let can_run = !split.busy && !split.secret_input.trim().is_empty();
                let button_text = if split.busy { "Splitting…" } else { "Split Secret" };
                let btn = primary_button(ui, button_text, can_run);
                if btn.clicked() && can_run {
                    let real_match =
                        split.password.as_str() == split.password_confirm.as_str();
                    let decoy_match = !split.generate_decoy
                        || split.decoy_password.as_str()
                            == split.decoy_password_confirm.as_str();
                    if !real_match {
                        split.error = Some(Zeroizing::new(
                            "The Real wallet passwords do not match. Please re-type them identically."
                                .to_owned(),
                        ));
                    } else if !decoy_match {
                        split.error = Some(Zeroizing::new(
                            "The Decoy wallet passwords do not match. Please re-type them identically."
                                .to_owned(),
                        ));
                    } else {
                        split.error = None;
                        start = true;
                    }
                }

                if split.busy {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new("This may take a few seconds…")
                                .size(13.0)
                                .color(TEXT_WEAK),
                        );
                    });
                }
            });

            // ── Error ──
            if let Some(err) = &split.error {
                ui.add_space(10.0);
                error_card(ui, err.as_str());
            }

            // ── Results ──
            if let Some(out) = &split.output {
                ui.add_space(14.0);
                warning_banner(ui);

                // Detected kind label
                let kind_label = match out.detected_kind {
                    DetectedKind::Hex => "hex secret",
                    DetectedKind::MoneroMnemonic => "25-word Monero mnemonic",
                    DetectedKind::Bip39Mnemonic => "BIP-39 mnemonic",
                };
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new(format!("Split from: {kind_label}"))
                        .size(13.0)
                        .color(TEXT_WEAK),
                );

                ui.add_space(10.0);
                split_actions = Some(share_card(
                    ui,
                    ctx,
                    "REAL WALLET SHARES",
                    GREEN,
                    GREEN_BG,
                    &out.shares,
                    "split_save",
                ));

                if split.generate_decoy && !out.decoy_shares.is_empty() {
                    ui.add_space(10.0);
                    decoy_actions = Some(share_card(
                        ui,
                        ctx,
                        "DECOY WALLET SHARES",
                        ORANGE,
                        ORANGE_BG,
                        &out.decoy_shares,
                        "split_decoy_save",
                    ));
                }

                if let Some(m) = &out.monero {
                    ui.add_space(10.0);
                    monero_card(ui, "Real Monero Wallet (verify)", GREEN, GREEN_BG, m);
                }
                if let Some(m) = &out.decoy_monero {
                    ui.add_space(10.0);
                    monero_card(ui, "Decoy Monero Wallet (verify)", ORANGE, ORANGE_BG, m);
                }
            }
        } // split borrow ends

        // ── Handle save-card actions (after split borrow ends) ──
        if let Some(sa) = split_actions {
            let (shares_text, threshold) = {
                let split = self.split_mut();
                if let Some(out) = &split.output {
                    (out.shares.clone(), split.threshold)
                } else {
                    (Zeroizing::new(String::new()), 2)
                }
            };
            self.handle_share_card_actions(ctx, sa, false, "Real", shares_text, threshold);
        }
        if let Some(da) = decoy_actions {
            let (shares_text, threshold) = {
                let split = self.split_mut();
                if let Some(out) = &split.output {
                    (out.decoy_shares.clone(), split.threshold)
                } else {
                    (Zeroizing::new(String::new()), 2)
                }
            };
            self.handle_share_card_actions(ctx, da, true, "Decoy", shares_text, threshold);
        }

        if start {
            self.start_split(ctx);
        }
    }

    fn start_split(&mut self, ctx: &egui::Context) {
        let coin = self.coin();
        let split = self.split_mut();
        let secret = Zeroizing::new(split.secret_input.as_str().to_owned());
        let threshold = split.threshold.min(split.total_shares);
        let total = split.total_shares;
        let iterations = gui_support::ITERATION_OPTIONS[split.iterations.min(1)];
        let password = Zeroizing::new(split.password.as_str().to_owned());
        let generate_decoy = split.generate_decoy;
        let decoy_password = Zeroizing::new(split.decoy_password.as_str().to_owned());

        split.busy = true;
        split.output = None;
        split.error = None;

        let (tx, rx) = mpsc::channel();
        split.rx = Some(rx);

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = gui_support::split_existing(
                coin,
                secret.as_str(),
                threshold,
                total,
                iterations,
                password.as_str(),
                generate_decoy,
                decoy_password.as_str(),
            );
            let mapped = result.map_err(|e| classify_split_error(&e));
            let _ = tx.send(WorkerMsg::Split(mapped));
            ctx.request_repaint();
            // secret / password / decoy_password drop here -> zeroized.
        });
    }
}

// ─── Recover tab ────────────────────────────────────────────────────────────

impl App {
    fn render_recover(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let coin = self.coin();
        let coin_label = match coin {
            Coin::Bitcoin => "Bitcoin",
            Coin::Monero => "Monero",
        };
        let mut start = false;
        let mut load_share_file = false;

        {
            let rec = self.rec_mut();

            // ── Intro card ──
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    egui::RichText::new(format!("Recover your {coin_label} wallet"))
                        .size(16.0)
                        .strong()
                        .color(TEXT_BRIGHT),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Paste the required number of SLIP-0039 shares (one per line) \
                         and enter the password you used when generating."
                    )
                    .size(13.0)
                    .color(TEXT_WEAK),
                );
            });

            ui.add_space(10.0);

            // ── Input card ──
            card(ui, |ui| {
                ui.set_width(ui.available_width());

                field_label(ui, "Paste your shares here (one per line), or load a file:");
                let text_resp = ui.add_sized(
                    [ui.available_width(), 220.0],
                    egui::TextEdit::multiline(&mut *rec.shares_text)
                        .code_editor()
                        .id_salt("shares_input"),
                );
                ui.add_space(4.0);
                if ui.button("Load share file...").clicked() {
                    load_share_file = true;
                }
                // "Load file" button is handled after the rec borrow ends
                // (sets a flag the caller reads).

                // ── Age armour interception ──
                // When armoured text is pasted, extract the entire
                // multi-line armoured block (BEGIN...END) from the text
                // area and queue it for decryption. The armoured text never
                // stays in the shares field — a popup opens, the user
                // decrypts, and the plaintext is inserted as a new line.
                if text_resp.changed() {
                    let (new_text, new_armoured) =
                        extract_armoured_blocks(&rec.shares_text);
                    if !new_armoured.is_empty() {
                        // Remove armoured blocks from the text area.
                        rec.shares_text = Zeroizing::new(new_text);
                        // Queue them for decryption.
                        rec.pending_armoured.extend(new_armoured);
                        // Open the decrypt popup for the first one.
                        rec.decrypt_popup_open = true;
                    } else if rec.shares_text.trim().is_empty() {
                        // The user cleared the text area — start fresh:
                        // drop any pending armoured shares and reset the
                        // decrypt badge so the Recover button isn't
                        // blocked by stale state.
                        rec.pending_armoured.clear();
                        rec.decrypted = false;
                        rec.decrypted_count = 0;
                        rec.decrypt_popup_open = false;
                    }
                    rec.cached_analysis = Some(analyse_shares(&rec.shares_text));
                    if rec.error.is_some() {
                        rec.error = None;
                    }
                }

                // ── Armour / decrypt status ──
                if !rec.pending_armoured.is_empty() {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        icon(ui, 13.0, Icon::Warning, AMBER);
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!(
                                "{} encrypted share{} waiting to be decrypted.",
                                rec.pending_armoured.len(),
                                if rec.pending_armoured.len() == 1 { "" } else { "s" }
                            ))
                            .size(12.0)
                            .color(AMBER),
                        );
                    });
                    // Reopen button (e.g. after the user cancelled the
                    // popup to find their key).
                    if !rec.decrypt_popup_open {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.button("Decrypt encrypted shares").clicked() {
                                rec.decrypt_popup_open = true;
                                rec.error = None;
                            }
                            ui.add_space(6.0);
                            if ui.button("Discard encrypted shares").clicked() {
                                // Drop all pending armoured shares so the user
                                // can recover with the plaintext shares already
                                // in the text area.
                                rec.pending_armoured.clear();
                                rec.error = None;
                            }
                        });
                    }
                } else if rec.decrypted && rec.decrypted_count > 0 {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        icon(ui, 13.0, Icon::Check, GREEN);
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!(
                                "{} share{} decrypted with age",
                                rec.decrypted_count,
                                if rec.decrypted_count == 1 { "" } else { "s" }
                            ))
                            .size(12.0)
                            .color(GREEN),
                        );
                    });
                }

                // ── Live share counter (from cached analysis) ──
                let info = rec.cached_analysis.clone().unwrap_or_default();
                if info.count > 0 {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if let (Some(mt), Some(gc)) = (info.member_threshold, info.group_count) {
                            if gc == 1 {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{} of {} shares pasted",
                                        info.count, mt
                                    ))
                                    .size(12.0)
                                    .color(if info.count >= mt as usize {
                                        GREEN
                                    } else {
                                        TEXT_WEAK
                                    }),
                                );
                                if info.count >= mt as usize {
                                    ui.add_space(4.0);
                                    icon(ui, 13.0, Icon::Check, GREEN);
                                }
                            } else {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{} shares pasted ({}-of-{} groups, group {} needs {})",
                                        info.count,
                                        info.group_threshold.unwrap_or(0),
                                        gc,
                                        1,
                                        mt
                                    ))
                                    .size(12.0)
                                    .color(TEXT_WEAK),
                                );
                            }
                        } else {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} share{} pasted",
                                    info.count,
                                    if info.count == 1 { "" } else { "s" }
                                ))
                                .size(12.0)
                                .color(TEXT_WEAK),
                            );
                        }
                    });
                }

                ui.add_space(12.0);
                field_label(ui, "Password");
                ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut *rec.password)
                        .password(true)
                        .id_salt("rec_pass"),
                );

                ui.add_space(8.0);

                field_label(ui, "Confirm password");
                let p2 = ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut *rec.password_confirm)
                        .password(true)
                        .id_salt("rec_pass_confirm"),
                );

                // Live mismatch / match hint, mirroring the Generate / Split
                // tabs. Drives home that a wrong password here silently
                // recovers a wrong (but plausible) wallet.
                if !rec.password.is_empty() || !rec.password_confirm.is_empty() {
                    let matches = rec.password.as_str() == rec.password_confirm.as_str();
                    if !matches {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            icon(ui, 13.0, Icon::Warning, RED);
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("Passwords do not match.")
                                    .size(12.0)
                                    .color(RED),
                            );
                        });
                    } else {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            icon(ui, 13.0, Icon::Check, GREEN);
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("Passwords match.")
                                    .size(12.0)
                                    .color(GREEN),
                            );
                        });
                    }
                }

                if p2.changed() {
                    rec.error = None;
                }

                ui.add_space(16.0);

                let can_run = !rec.busy && !rec.shares_text.is_empty() && rec.pending_armoured.is_empty();
                let label = if rec.busy { "Recovering…" } else { "Recover Wallet" };
                let btn = primary_button(ui, label, can_run);
                if btn.clicked() && can_run {
                    let matches = rec.password.as_str() == rec.password_confirm.as_str();
                    if !matches {
                        rec.error = Some(Zeroizing::new(
                            "The passwords do not match. Please re-type them identically — \
                             a mistyped recovery password produces a valid-looking but WRONG wallet."
                                .to_owned(),
                        ));
                    } else {
                        start = true;
                    }
                }

                if rec.password.is_empty() && !rec.shares_text.is_empty() && rec.pending_armoured.is_empty() {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        icon(ui, 13.0, Icon::Warning, AMBER);
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "No password set. Only continue if you generated with an empty password."
                            )
                            .size(12.0)
                            .color(AMBER),
                        );
                    });
                }

                if !rec.pending_armoured.is_empty() {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        icon(ui, 13.0, Icon::Warning, AMBER);
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(
                                "Decrypt all encrypted shares before recovering."
                            )
                            .size(12.0)
                            .color(AMBER),
                        );
                    });
                }

                if rec.busy {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(egui::RichText::new("Recovering…").size(13.0).color(TEXT_WEAK));
                    });
                }
            });

            // ── Error ──
            if let Some(err) = &rec.error {
                ui.add_space(10.0);
                error_card(ui, err.as_str());
            }

            // ── Results ──
            if let Some(out) = &rec.output {
                ui.add_space(14.0);
                warning_banner(ui);
                ui.add_space(10.0);
                verify_banner(ui);
                ui.add_space(10.0);

                if let Some(bip) = &out.bip39 {
                    result_card(
                        ui,
                        ctx,
                        "Recovered BIP-39 Mnemonic (24 words)",
                        bip.as_str(),
                        "rec_bip39",
                        200.0,
                    );
                }
                if let Some(m) = &out.monero {
                    let mut text = String::new();
                    use std::fmt::Write;
                    let _ = writeln!(text, "Mnemonic:  {}", m.mnemonic.as_str());
                    let _ = writeln!(text, "Spend key: {}", m.spend_key.as_str());
                    let _ = writeln!(text, "View key:  {}", m.view_key.as_str());
                    let _ = writeln!(text, "Address:   {}", m.address);
                    let text = Zeroizing::new(text);
                    result_card(ui, ctx, "Recovered Monero Wallet", text.as_str(), "rec_xmr", 380.0);
                }
            }
        } // rec borrow ends

        if load_share_file {
            self.launch_file_load(ctx, FileLoadTarget::RecoverShareFile);
        }

        if start {
            self.start_recover(ctx);
        }
    }

    fn start_recover(&mut self, ctx: &egui::Context) {
        let coin = self.coin();
        let rec = self.rec_mut();
        let shares = Zeroizing::new(rec.shares_text.as_str().to_owned());
        let password = Zeroizing::new(rec.password.as_str().to_owned());

        rec.busy = true;
        rec.output = None;
        rec.error = None;

        let (tx, rx) = mpsc::channel();
        rec.rx = Some(rx);

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = gui_support::recover(coin, shares.as_str(), password.as_str());
            let mapped = result.map_err(|e| classify_recover_error(&e));
            let _ = tx.send(WorkerMsg::Recover(mapped));
            ctx.request_repaint();
            // shares / password drop here -> zeroized.
        });
    }
}

// ─── Derive tab ─────────────────────────────────────────────────────────────

impl App {
    fn render_derive(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let coin = self.coin();
        let (coin_label, intro_text, field_text, placeholder_hint) = match coin {
            Coin::Bitcoin => (
                "Bitcoin",
                "Paste raw hex entropy (16 / 20 / 24 / 28 / 32 bytes = 32 / 40 / 48 / 56 / 64 \
                 hex chars) and derive the matching BIP-39 seed phrase (12 / 15 / 18 / 21 / 24 \
                 words). Use this to turn a hex secret into a recoverable Bitcoin / Ethereum \
                 seed phrase.",
                "Paste hex entropy (e.g. 64 hex chars)",
                "Expected an even number of hex digits — 16/20/24/28/32 bytes.",
            ),
            Coin::Monero => (
                "Monero",
                "Paste a private spend key (64-char hex) or a 25-word Monero mnemonic and \
                 derive the full key set: public keys, view key, and the wallet address. Use \
                 this to verify a wallet or generate its keys from a spend key.",
                "Paste your Monero spend key (hex) or 25-word mnemonic",
                "Expected a 64-char hex spend key or a 25-word Monero mnemonic.",
            ),
        };
        let mut start = false;

        {
            let d = self.derive_mut();

            // ── Intro card ──
            card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    egui::RichText::new(format!("Derive a {coin_label} phrase / keys from raw material"))
                        .size(16.0)
                        .strong()
                        .color(TEXT_BRIGHT),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(intro_text)
                        .size(13.0)
                        .color(TEXT_WEAK),
                );
            });

            ui.add_space(10.0);

            // ── Input card ──
            card(ui, |ui| {
                ui.set_width(ui.available_width());

                section_header(ui, "Input");
                field_label(ui, field_text);
                ui.add_sized(
                    [ui.available_width(), 120.0],
                    egui::TextEdit::multiline(&mut *d.input)
                        .code_editor()
                        .id_salt("derive_input"),
                );

                // ── Live input hint ──
                let trimmed_len = d.input.trim().len();
                let word_count = d.input.split_whitespace().count();
                if !d.input.trim().is_empty() {
                    ui.add_space(4.0);
                    match (coin, word_count, trimmed_len) {
                        (Coin::Monero, 25, _) => {
                            derive_hint(ui, "Detected: 25-word Monero mnemonic", true);
                        }
                        (Coin::Monero, 1, 64) => {
                            derive_hint(ui, "Detected: 64-char hex spend key", true);
                        }
                        (Coin::Bitcoin, 1, n)
                            if n % 2 == 0 && matches!(n, 32 | 40 | 48 | 56 | 64) =>
                        {
                            let words = match n {
                                32 => 12,
                                40 => 15,
                                48 => 18,
                                56 => 21,
                                64 => 24,
                                _ => unreachable!(),
                            };
                            let bytes = n / 2;
                            derive_hint(
                                ui,
                                &format!("Detected: {bytes}-byte entropy -> {words}-word phrase"),
                                true,
                            );
                        }
                        _ => {
                            derive_hint(ui, placeholder_hint, false);
                        }
                    }
                }

                ui.add_space(16.0);

                let can_run = !d.busy && !d.input.trim().is_empty();
                let label = if d.busy { "Deriving…" } else { "Derive" };
                let btn = primary_button(ui, label, can_run);
                if btn.clicked() && can_run {
                    start = true;
                }

                if d.busy {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new("Deriving…").size(13.0).color(TEXT_WEAK),
                        );
                    });
                }
            });

            // ── Error ──
            if let Some(err) = &d.error {
                ui.add_space(10.0);
                error_card(ui, err.as_str());
            }

            // ── Results ──
            if let Some(out) = &d.output {
                ui.add_space(14.0);
                warning_banner(ui);
                ui.add_space(10.0);

                if let Some(bip) = &out.bip39 {
                    let nw = bip.split_whitespace().count();
                    result_card(
                        ui,
                        ctx,
                        &format!("Derived BIP-39 Mnemonic ({nw} words)"),
                        bip.as_str(),
                        "derive_bip39",
                        200.0,
                    );
                }
                if let Some(m) = &out.monero {
                    let mut text = String::new();
                    use std::fmt::Write;
                    let _ = writeln!(text, "Address:   {}", m.address);
                    let _ = writeln!(text, "Spend key: {}", m.spend_key.as_str());
                    let _ = writeln!(text, "View key:  {}", m.view_key.as_str());
                    let _ = writeln!(text, "Mnemonic:  {}", m.mnemonic.as_str());
                    let text = Zeroizing::new(text);
                    result_card(
                        ui,
                        ctx,
                        "Derived Monero Wallet",
                        text.as_str(),
                        "derive_xmr",
                        320.0,
                    );
                }
            }
        } // d borrow ends

        if start {
            self.start_derive(ctx);
        }
    }

    fn start_derive(&mut self, ctx: &egui::Context) {
        let coin = self.coin();
        let d = self.derive_mut();
        // Clone the input into a Zeroizing owned copy that the worker
        // thread drops (and zeroises) when it finishes.
        let input = Zeroizing::new(d.input.as_str().to_owned());

        d.busy = true;
        d.output = None;
        d.error = None;

        let (tx, rx) = mpsc::channel();
        d.rx = Some(rx);

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = gui_support::derive(coin, input.as_str());
            let mapped = result.map_err(|e| classify_derive_error(&e));
            let _ = tx.send(WorkerMsg::Derive(mapped));
            ctx.request_repaint();
            // input drops here -> zeroized.
        });
    }
}

// ─── UI helper widgets ──────────────────────────────────────────────────────

/// A tab-style button with a fixed size and a painted underline for the
/// active state. Both active and inactive tabs occupy the same space so
/// there is no visual jumping when switching.
fn tab_button(ui: &mut egui::Ui, label: &str, active: bool, on_click: impl FnOnce()) {
    let text_color = if active { TEXT_BRIGHT } else { TEXT_WEAK };

    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(90.0, 28.0),
        egui::Sense::click(),
    );

    // Draw the text centered in the allocated rect.
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::proportional(14.0),
        text_color,
    );

    // Underline for active tab.
    if active {
        let y = rect.bottom() + 1.0;
        ui.painter().line_segment(
            [
                egui::pos2(rect.left() + 6.0, y),
                egui::pos2(rect.right() - 6.0, y),
            ],
            egui::Stroke::new(2.5, ACCENT),
        );
    }

    // Hover highlight.
    if response.hovered() && !active {
        ui.painter().line_segment(
            [
                egui::pos2(rect.left() + 6.0, rect.bottom() + 1.0),
                egui::pos2(rect.right() - 6.0, rect.bottom() + 1.0),
            ],
            egui::Stroke::new(2.0, CARD_STROKE),
        );
    }

    if response.clicked() {
        on_click();
    }
}

/// A rounded card container with a subtle background.
fn card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::group(ui.style())
        .fill(CARD_BG)
        .stroke(egui::Stroke::new(1.0, CARD_STROKE))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::same(18))
        .show(ui, add_contents);
}

/// Extract the actual mnemonic share lines from a formatted shares blob,
/// dropping the `#` comment headers.
fn split_shares(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// Actions returned by [`share_card`] for the caller to react to. The
/// card is a free function (it cannot touch `App` directly), so it reports
/// what the user clicked and the caller opens the save popup.
struct ShareCardActions {
    /// `(share_index, share_text)` for each per-share "Save .age" click.
    per_share_saves: Vec<(usize, String)>,
    /// True if the "Save ZIP" bulk button was clicked.
    bulk_zip: bool,
    /// True if the "Save (one file)" bulk button was clicked.
    bulk_one_file: bool,
    /// `(share_number, total)` if a per-share "Copy this Share" click
    /// fired, for the clipboard toast.
    copied_share: Option<(usize, usize)>,
    /// True if the "Copy All to Clipboard" bulk button was clicked.
    copied_all: bool,
}

/// A colored share card. Each individual share is rendered in its own
/// numbered sub-card with dedicated Copy and Save buttons, so they are
/// easy to identify and transfer one at a time. The card also offers bulk
/// "Save ZIP" / "Save (one file)" buttons 
#[allow(clippy::too_many_arguments)]
fn share_card(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    title: &str,
    accent: egui::Color32,
    bg: egui::Color32,
    text: &Zeroizing<String>,
    id: &str,
) -> ShareCardActions {
    let mut actions = ShareCardActions {
        per_share_saves: Vec::new(),
        bulk_zip: false,
        bulk_one_file: false,
        copied_share: None,
        copied_all: false,
    };

    egui::Frame::group(ui.style())
        .fill(bg)
        .stroke(egui::Stroke::new(1.0, accent))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());

            // Title row with colored dot.
            ui.horizontal(|ui| {
                icon(ui, 13.0, Icon::Circle, accent);
                ui.add_space(5.0);
                ui.label(egui::RichText::new(title).size(14.0).strong().color(accent));
            });
            ui.add_space(10.0);

            let shares = split_shares(text.as_str());
            let total = shares.len();

            for (i, share) in shares.iter().enumerate() {
                let saved = share_row(
                    ui,
                    ctx,
                    i + 1,
                    total,
                    share,
                    accent,
                    &format!("{id}_{i}"),
                );
                let (saved, copied) = saved;
                if let Some(share_text) = saved {
                    actions.per_share_saves.push((i, share_text));
                }
                if copied {
                    actions.copied_share = Some((i + 1, total));
                }
                if i + 1 < total {
                    ui.add_space(6.0);
                }
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Save ZIP").clicked() {
                    actions.bulk_zip = true;
                }
                ui.add_space(6.0);
                if ui.button("Save (one file)").clicked() {
                    actions.bulk_one_file = true;
                }
                ui.add_space(6.0);
                if ui.button("Copy All to Clipboard").clicked() {
                    ctx.copy_text(text.as_str().to_owned());
                    actions.copied_all = true;
                }
            });
        });

    actions
}

/// One numbered share: a label, the selectable mnemonic, and Copy / Save
/// buttons. Returns `(save_text, was_copied)` — `save_text` is `Some` if
/// the "Save" button was clicked (so the caller opens the save popup),
/// and `was_copied` is true if "Copy this Share" was clicked (for the
/// clipboard toast).
fn share_row(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    n: usize,
    total: usize,
    share: &str,
    accent: egui::Color32,
    id: &str,
) -> (Option<String>, bool) {
    let mut saved = None;
    let mut copied = false;
    egui::Frame::group(ui.style())
        .fill(CARD_BG_LIGHT)
        .stroke(egui::Stroke::new(1.0, CARD_STROKE))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());

            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("Share {n} of {total}"))
                        .size(12.0)
                        .strong()
                        .color(accent),
                );
            });
            ui.add_space(6.0);

            egui::ScrollArea::vertical()
                .max_height(120.0)
                .id_salt(id)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(share)
                                .size(15.0)
                                .color(TEXT)
                                .family(egui::FontFamily::Monospace),
                        )
                        .selectable(true)
                        .wrap_mode(egui::TextWrapMode::Wrap),
                    );
                });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Copy this Share").clicked() {
                    ctx.copy_text(share.to_owned());
                    copied = true;
                }
                ui.add_space(6.0);
                if ui.button("Save").clicked() {
                    saved = Some(share.to_owned());
                }
            });
        });
    (saved, copied)
}

/// A Monero key verification card with selectable text.
fn monero_card(
    ui: &mut egui::Ui,
    title: &str,
    accent: egui::Color32,
    bg: egui::Color32,
    keys: &MoneroRecovery,
) {
    egui::Frame::group(ui.style())
        .fill(bg)
        .stroke(egui::Stroke::new(1.0, accent))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                icon(ui, 13.0, Icon::Circle, accent);
                ui.add_space(5.0);
                ui.label(egui::RichText::new(title).size(14.0).strong().color(accent));
            });
            ui.add_space(10.0);
            egui::Grid::new(format!("{title}_grid"))
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    key_row(ui, "Address", &keys.address);
                    key_row(ui, "View key", keys.view_key.as_str());
                    key_row(ui, "Spend key", keys.spend_key.as_str());
                    key_row(ui, "Mnemonic", keys.mnemonic.as_str());
                });
        });
}

/// A result card with selectable text and a copy button.
fn result_card(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    title: &str,
    text: &str,
    id: &str,
    max_height: f32,
) {
    egui::Frame::group(ui.style())
        .fill(CARD_BG_LIGHT)
        .stroke(egui::Stroke::new(1.0, ACCENT))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                egui::RichText::new(title)
                    .size(14.0)
                    .strong()
                    .color(ACCENT),
            );
            ui.add_space(8.0);

            egui::ScrollArea::vertical()
                .max_height(max_height)
                .id_salt(id)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(text)
                                .size(14.0)
                                .color(TEXT)
                                .family(egui::FontFamily::Monospace),
                        )
                        .selectable(true)
                        .wrap_mode(egui::TextWrapMode::Wrap),
                    );
                });

            ui.add_space(8.0);
            if ui.button("Copy to Clipboard").clicked() {
                ctx.copy_text(text.to_owned());
            }
        });
}

/// A small inline detection hint for the Derive tab input: a green check
/// when the input is recognised, an amber warning otherwise.
fn derive_hint(ui: &mut egui::Ui, msg: &str, ok: bool) {
    ui.horizontal(|ui| {
        if ok {
            icon(ui, 13.0, Icon::Check, GREEN);
        } else {
            icon(ui, 13.0, Icon::Warning, AMBER);
        }
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(msg)
                .size(12.0)
                .color(if ok { GREEN } else { AMBER }),
        );
    });
}

/// An error banner card.
fn error_card(ui: &mut egui::Ui, msg: &str) {
    egui::Frame::group(ui.style())
        .fill(RED_BG)
        .stroke(egui::Stroke::new(1.0, RED))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                icon(ui, 18.0, Icon::Warning, RED);
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(msg)
                        .size(13.0)
                        .color(egui::Color32::from_rgb(255, 180, 175)),
                );
            });
        });
}

/// A recovery reminder banner: SLIP-0039 cannot verify the password, so a
/// wrong password yields a plausible but wrong wallet. The user must compare
/// the recovered address against the one recorded at generation time. This
/// is the dual of the duress property — see SECURITY.md.
fn verify_banner(ui: &mut egui::Ui) {
    egui::Frame::group(ui.style())
        .fill(AMBER_BG)
        .stroke(egui::Stroke::new(1.0, AMBER))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                icon(ui, 18.0, Icon::Warning, AMBER);
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "SLIP-0039 cannot verify your password — a wrong one shows a valid-looking but WRONG wallet. Compare the address below against the one you recorded when generating."
                    )
                    .size(13.0)
                    .color(egui::Color32::from_rgb(255, 210, 120)),
                );
            });
        });
}

/// The amber "write these down" warning banner.
fn warning_banner(ui: &mut egui::Ui) {
    egui::Frame::group(ui.style())
        .fill(AMBER_BG)
        .stroke(egui::Stroke::new(1.0, AMBER))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                icon(ui, 18.0, Icon::Warning, AMBER);
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "WRITE THESE DOWN ON PAPER. They will be wiped from RAM when the app closes."
                    )
                    .size(13.0)
                    .strong()
                    .color(egui::Color32::from_rgb(255, 210, 120)),
                );
            });
        });
}

/// A full-width primary action button.
fn primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    ui.add_sized(
        [ui.available_width(), 44.0],
        egui::Button::new(
            egui::RichText::new(label)
                .size(15.0)
                .strong()
                .color(if enabled { TEXT_BRIGHT } else { TEXT_WEAK }),
        )
        .fill(if enabled { ACCENT } else { CARD_BG_LIGHT })
        .stroke(if enabled {
            egui::Stroke::NONE
        } else {
            egui::Stroke::new(1.0, CARD_STROKE)
        })
        .corner_radius(8.0),
    )
}

/// A small uppercase section header with a divider underneath.
fn section_header(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(12.0).color(TEXT_WEAK));
    ui.add_space(8.0);
}

/// A label that sits above a form field.
fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(13.0).color(TEXT_WEAK));
}

/// A grid row: bold label + selectable monospace value.
fn key_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(egui::RichText::new(label).size(12.0).color(TEXT_WEAK));
    ui.add(
        egui::Label::new(
            egui::RichText::new(value)
                .size(12.0)
                .color(TEXT)
                .family(egui::FontFamily::Monospace),
        )
        .selectable(true)
        .wrap_mode(egui::TextWrapMode::Wrap),
    );
    ui.end_row();
}

/// A subtle horizontal divider.
fn divider(ui: &mut egui::Ui) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 0.0), egui::Sense::hover());
    ui.painter().line_segment(
        [
            egui::pos2(rect.left(), rect.center().y),
            egui::pos2(rect.right(), rect.center().y),
        ],
        egui::Stroke::new(1.0, CARD_STROKE),
    );
}

/// A combo box for choosing a share count (1..=max).
fn share_combo(ui: &mut egui::Ui, id: &str, value: &mut u8, min: u8, max: u8) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(format!("{}", value))
        .width(90.0)
        .show_ui(ui, |ui| {
            for n in min..=max {
                ui.selectable_value(value, n, format!("{}", n));
            }
        });
}

// ─── Vector icons ───────────────────────────────────────────────────────────
//
// egui's bundled fonts do not cover the Unicode glyphs we used previously
// (diamond circle triangle-down triangle-right warning check), so they
// rendered as "tofu" boxes that looked like empty checkboxes. Instead we
// draw every icon with the painter — guaranteed to
// render on every platform with no font dependency.

#[derive(Clone, Copy)]
enum Icon {
    Circle,
    TriangleDown,
    TriangleRight,
    Warning,
    Check,
}

/// Allocate a square region and draw an icon into it.
fn icon(ui: &mut egui::Ui, size: f32, kind: Icon, color: egui::Color32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    draw_icon_at(ui.painter(), rect.center(), size, kind, color);
    response
}

/// Draw an icon centered at `center` with overall extent `size`.
fn draw_icon_at(
    p: &egui::Painter,
    center: egui::Pos2,
    size: f32,
    kind: Icon,
    color: egui::Color32,
) {
    let h = size * 0.5;
    match kind {
        Icon::Circle => {
            p.circle_filled(center, h * 0.9, color);
        }
        Icon::TriangleDown => {
            let pts = vec![
                egui::pos2(center.x - h, center.y - h * 0.55),
                egui::pos2(center.x + h, center.y - h * 0.55),
                egui::pos2(center.x, center.y + h * 0.6),
            ];
            p.add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
        }
        Icon::TriangleRight => {
            let pts = vec![
                egui::pos2(center.x - h * 0.55, center.y - h),
                egui::pos2(center.x + h * 0.6, center.y),
                egui::pos2(center.x - h * 0.55, center.y + h),
            ];
            p.add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
        }
        Icon::Warning => {
            let pts = vec![
                egui::pos2(center.x, center.y - h),
                egui::pos2(center.x + h, center.y + h * 0.75),
                egui::pos2(center.x - h, center.y + h * 0.75),
            ];
            p.add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
            p.text(
                egui::pos2(center.x, center.y + h * 0.14),
                egui::Align2::CENTER_CENTER,
                "!",
                egui::FontId::proportional(size * 0.85),
                ON_AMBER,
            );
        }
        Icon::Check => {
            p.add(egui::Shape::line(
                vec![
                    egui::pos2(center.x - h * 0.55, center.y + h * 0.05),
                    egui::pos2(center.x - h * 0.1, center.y + h * 0.5),
                    egui::pos2(center.x + h * 0.6, center.y - h * 0.45),
                ],
                egui::Stroke::new(size * 0.18, color),
            ));
        }
    }
}

// ─── Age save popup (per-share + bulk) ──────────────────────────────────────

impl App {
    /// React to share-card save button clicks by opening the appropriate
    /// save popup. `shares_text` is the formatted shares blob (with `#`
    /// comments); `label` is "Real" / "Decoy" / "Share" for the popup title.
    fn handle_share_card_actions(
        &mut self,
        ctx: &egui::Context,
        actions: ShareCardActions,
        is_decoy: bool,
        label: &str,
        shares_text: Zeroizing<String>,
        threshold: u8,
    ) {
        // Clipboard toast (checked before actions are consumed).
        if let Some((n, total)) = actions.copied_share {
            self.save_status = Some((
                format!("{label} share {n} of {total} copied to clipboard"),
                false,
            ));
            self.save_status_time = Some(std::time::Instant::now());
        } else if actions.copied_all {
            self.save_status = Some((
                format!("All {label} shares copied to clipboard"),
                false,
            ));
            self.save_status_time = Some(std::time::Instant::now());
        }

        let shares: Vec<Zeroizing<String>> = split_shares(shares_text.as_str())
            .into_iter()
            .map(Zeroizing::new)
            .collect();
        let total = shares.len();

        if self.expert_mode {
            // Expert mode: open the choice popup (encrypt vs plaintext).
            // Only one popup can be open at a time, so process just the
            // first per-share save request this frame (egui only fires one
            // button click per frame, but be defensive against silent
            // overwrites if that ever changes).
            if let Some((idx, share_text)) = actions.per_share_saves.into_iter().next() {
                let title = format!("{label} share {} of {}", idx + 1, total);
                self.save_choice = Some(SaveChoiceState {
                    target: SaveTarget::PerShare,
                    shares: vec![Zeroizing::new(share_text)],
                    threshold,
                    is_decoy,
                    title,
                });
            }
            if actions.bulk_zip {
                let title = format!("{label} shares - ZIP");
                self.save_choice = Some(SaveChoiceState {
                    target: SaveTarget::BulkZip,
                    shares: shares.clone(),
                    threshold,
                    is_decoy,
                    title,
                });
            }
            if actions.bulk_one_file {
                let title = format!("{label} shares - one file");
                self.save_choice = Some(SaveChoiceState {
                    target: SaveTarget::BulkOneFile,
                    shares: shares.clone(),
                    threshold,
                    is_decoy,
                    title,
                });
            }
        } else {
            // Simple mode: plaintext save, no popup. Only one save worker
            // can be in-flight at a time (they share `save_rx`), so handle
            // just the first per-share request this frame.
            if let Some((idx, share_text)) = actions.per_share_saves.into_iter().next() {
                let title = format!("{label} share {} of {}", idx + 1, total);
                self.launch_plain_save_worker(
                    ctx,
                    vec![Zeroizing::new(share_text)],
                    SaveTarget::PerShare,
                    title,
                    threshold,
                    is_decoy,
                );
            }
            if actions.bulk_zip {
                let title = format!("{label} shares - ZIP");
                self.launch_plain_save_worker(
                    ctx,
                    shares.clone(),
                    SaveTarget::BulkZip,
                    title,
                    threshold,
                    is_decoy,
                );
            }
            if actions.bulk_one_file {
                let title = format!("{label} shares - one file");
                self.launch_plain_save_worker(
                    ctx,
                    shares.clone(),
                    SaveTarget::BulkOneFile,
                    title,
                    threshold,
                    is_decoy,
                );
            }
        }
    }

    /// Render the expert-mode save choice popup (encrypt vs plaintext).
    /// When the user picks "Encrypt", opens the full encryption-method
    /// popup ([`save_popup`]). When they pick "Save as plaintext", launches
    /// the plaintext save worker directly. "Cancel" discards.
    fn render_save_choice_popup(&mut self, ctx: &egui::Context) {
        let choice = match self.save_choice.take() {
            Some(c) => c,
            None => return,
        };
        let mut open = true;
        let mut encrypt = false;
        let mut plaintext = false;
        let mut cancel = false;
        let title = choice.title.clone();

        egui::Window::new("Save shares")
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new(&title).strong().color(TEXT_BRIGHT));
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(
                        "How would you like to save these shares?\n\
                         \n\
                         Encrypt with age (.age) — passphrase, age\n\
                         recipient, or SSH key. Recommended for\n\
                         sensitive wallet backups.\n\
                         \n\
                         Save as plaintext — no encryption. Faster,\n\
                         but anyone with the file can read it.",
                    )
                    .size(13.0)
                    .color(TEXT),
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let encrypt_btn = ui.add(
                        egui::Button::new(
                            egui::RichText::new("Encrypt with age").strong().color(TEXT_BRIGHT),
                        )
                        .fill(ACCENT)
                        .corner_radius(8.0),
                    );
                    if encrypt_btn.clicked() {
                        encrypt = true;
                    }
                    ui.add_space(8.0);
                    if ui.button("Save as plaintext").clicked() {
                        plaintext = true;
                    }
                    ui.add_space(8.0);
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if encrypt {
            // Open the full encryption-method popup.
            let methods: Vec<MethodEditor> = match choice.target {
                SaveTarget::BulkZip => (0..choice.shares.len())
                    .map(|_| MethodEditor::default())
                    .collect(),
                _ => vec![MethodEditor::default()],
            };
            self.save_popup = Some(SavePopupState {
                target: choice.target,
                methods,
                shares: choice.shares,
                threshold: choice.threshold,
                is_decoy: choice.is_decoy,
                title: choice.title,
                carousel_idx: 0,
                slide_offset: 0.0,
            });
        } else if plaintext {
            self.launch_plain_save_worker(
                ctx,
                choice.shares,
                choice.target,
                choice.title,
                choice.threshold,
                choice.is_decoy,
            );
        } else if open && !cancel {
            // Keep the popup open for next frame.
            self.save_choice = Some(choice);
        }
    }

    /// Render the save popup if open. Returns true if still open.
    fn render_save_popup(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let mut do_save = false;

        if self.save_popup.is_none() {
            return;
        }

        let popup_title = self
            .save_popup
            .as_ref()
            .map(|p| format!("Save — {}", p.title))
            .unwrap_or_default();
        let is_decoy = self.save_popup.as_ref().map(|p| p.is_decoy).unwrap_or(false);
        let mut save_load_requests: Vec<FileLoadTarget> = Vec::new();

        egui::Window::new(popup_title)
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .frame(
                egui::Frame::window(&ctx.style())
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0, ACCENT)),
            )
            .show(ctx, |ui| {
                ui.set_width(480.0);

                let popup = self.save_popup.as_mut().unwrap();
                let is_bulk_zip = popup.target == SaveTarget::BulkZip;
                let method_count = popup.methods.len();
                let share_count = popup.shares.len();

                // Clamp carousel index.
                if popup.carousel_idx >= method_count {
                    popup.carousel_idx = method_count - 1;
                }

                if is_bulk_zip {
                    // ── Carousel header ──
                    ui.label(
                        egui::RichText::new(format!(
                            "Share {} of {}",
                            popup.carousel_idx + 1,
                            share_count
                        ))
                        .size(14.0)
                        .strong()
                        .color(TEXT_BRIGHT),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new("Choose an encryption method for this share.")
                            .size(12.0)
                            .color(TEXT_WEAK),
                    );
                } else {
                    ui.label(
                        egui::RichText::new("This share will be encrypted with age.")
                            .size(13.0)
                            .color(TEXT_WEAK),
                    );
                }
                ui.add_space(10.0);

                // Duress notice (decoy bulk saves only).
                if is_decoy {
                    ui.add_space(6.0);
                    duress_notice_card(ui);
                    ui.add_space(10.0);
                }

                // ── Method editor(s) ──
                // Collect file-load requests from the editor so the caller
                // can launch async workers after the borrow ends.
                let mut load_requests: Vec<FileLoadTarget> = Vec::new();
                if is_bulk_zip {
                    let idx = popup.carousel_idx;
                    let offset = popup.slide_offset;
                    if offset.abs() > 0.5 {
                        ui.horizontal(|ui| {
                            ui.add_space(offset);
                            ui.vertical(|ui| {
                                load_requests = method_editor_ui(ui, &mut popup.methods[idx], idx);
                            });
                        });
                    } else {
                        load_requests = method_editor_ui(ui, &mut popup.methods[idx], idx);
                    }
                } else {
                    load_requests = method_editor_ui(ui, &mut popup.methods[0], 0);
                }
                save_load_requests.extend(load_requests);

                ui.add_space(16.0);

                // ── Carousel navigation (BulkZip only) ──
                if is_bulk_zip && method_count > 1 {
                    // Apply slide animation offset to the content above.
                    // Decay each frame toward 0.
                    if popup.slide_offset.abs() > 0.5 {
                        popup.slide_offset *= 0.78;
                        ui.ctx().request_repaint();
                    } else {
                        popup.slide_offset = 0.0;
                    }

                    ui.horizontal(|ui| {
                        let can_go_back = popup.carousel_idx > 0;
                        if ui.add_enabled(can_go_back, egui::Button::new("Back")).clicked() {
                            popup.carousel_idx -= 1;
                            popup.slide_offset = -24.0; // slide from left
                        }

                        ui.add_space(8.0);

                        // Carousel dots (clickable).
                        let clicked_dot = carousel_dots(
                            ui,
                            method_count,
                            popup.carousel_idx,
                        );
                        if let Some(dot) = clicked_dot {
                            if dot > popup.carousel_idx {
                                popup.slide_offset = 24.0; // slide from right
                            } else if dot < popup.carousel_idx {
                                popup.slide_offset = -24.0; // slide from left
                            }
                            popup.carousel_idx = dot;
                        }

                        ui.add_space(8.0);

                        let can_go_next = popup.carousel_idx < method_count - 1;
                        if ui.add_enabled(can_go_next, egui::Button::new("Next")).clicked() {
                            popup.carousel_idx += 1;
                            popup.slide_offset = 24.0; // slide from right
                        }
                    });
                    ui.add_space(12.0);
                }

                // ── Save / Cancel buttons ──
                let save_busy = self.save_rx.is_some();
                ui.horizontal(|ui| {
                    if save_busy {
                        let dots = (ui.ctx().input(|i| i.time) * 2.0) as usize % 4;
                        let label = format!("Saving{}", ".".repeat(dots));
                        ui.add_enabled(false, egui::Button::new(label));
                        ui.add_space(8.0);
                        ui.spinner();
                        ui.ctx().request_repaint();
                    } else {
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                        ui.add_space(10.0);
                        let can_save = popup.methods.iter().all(method_is_valid);
                        let btn = ui.add_enabled(
                            can_save,
                            egui::Button::new(
                                egui::RichText::new("Save .age").strong().color(TEXT_BRIGHT),
                            )
                            .fill(ACCENT)
                            .corner_radius(8.0),
                        );
                        if btn.clicked() && can_save {
                            do_save = true;
                        }
                        // Enter key triggers save.
                        if can_save
                            && ui.ctx().input(|i| i.key_pressed(egui::Key::Enter))
                        {
                            do_save = true;
                        }
                    }
                });
            });

        for target in save_load_requests {
            self.launch_file_load(ctx, target);
        }

        if do_save {
            self.launch_save_worker(ctx);
        }
        if close {
            self.save_popup = None;
            // Don't leave a pending file-load orphaned — the result would
            // have nowhere to go if the popup is reopened for a different
            // share.
            self.file_load_rx = None;
            self.file_load_target = None;
        }
    }

    /// Launch a plaintext save (simple mode): no encryption, no popup.
    /// Builds the file content (per-share `.txt`, bulk `.zip`, or one
    /// `.txt`) on a background thread, opens the OS file-save dialog, and
    /// writes the result. Shares the `save_rx` channel with the encrypted
    /// save path so `poll_save_worker` handles the toast.
    fn launch_plain_save_worker(
        &mut self,
        ctx: &egui::Context,
        shares: Vec<Zeroizing<String>>,
        target: SaveTarget,
        title: String,
        threshold: u8,
        is_decoy: bool,
    ) {
        let (default_name, filter_ext): (String, Vec<&'static str>) = match target {
            SaveTarget::PerShare => {
                (format!("{}.txt", sanitize_title(&title)), vec!["txt"])
            }
            SaveTarget::BulkZip => {
                (format!("{}.zip", sanitize_title(&title)), vec!["zip"])
            }
            SaveTarget::BulkOneFile => {
                (format!("{}.txt", sanitize_title(&title)), vec!["txt"])
            }
        };

        let (tx, rx) = mpsc::channel();
        self.save_rx = Some(rx);

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // Build plaintext content.
            let bytes: Zeroizing<Vec<u8>> = match target {
                SaveTarget::PerShare => {
                    // Single share as-is.
                    Zeroizing::new(shares[0].as_bytes().to_vec())
                }
                SaveTarget::BulkOneFile => {
                    // All shares joined with blank lines.
                    let joined = shares
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("\n\n");
                    Zeroizing::new(joined.into_bytes())
                }
                SaveTarget::BulkZip => {
                    // Build a ZIP of individual shareN.txt files.
                    use std::io::{Cursor, Write};
                    use zip::write::SimpleFileOptions;
                    use zip::{CompressionMethod, ZipWriter};
                    let cursor = Cursor::new(Vec::new());
                    let mut zip = ZipWriter::new(cursor);
                    let options =
                        SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
                    for (i, share) in shares.iter().enumerate() {
                        let name = format!("share{}.txt", i + 1);
                        if zip.start_file(&name, options).is_err() {
                            let _ = tx.send(Err("Failed to build ZIP".to_string()));
                            return;
                        }
                        if zip.write_all(share.as_bytes()).is_err() {
                            let _ = tx.send(Err("Failed to build ZIP".to_string()));
                            return;
                        }
                    }
                    // README with threshold info (no secrets).
                    let readme = format!(
                        "Pellitory-39 shares\n{} share(s), threshold {}\n\
                         Each shareN.txt file contains one SLIP-0039 share.\
                         Collect enough shares (at least the threshold) and\n\
                         paste them into the Recover tab.\n",
                        shares.len(),
                        threshold,
                    );
                    if zip.start_file("README.txt", options).is_err()
                        || zip.write_all(readme.as_bytes()).is_err()
                    {
                        let _ = tx.send(Err("Failed to build ZIP".to_string()));
                        return;
                    }
                    match zip.finish() {
                        Ok(writer) => Zeroizing::new(writer.into_inner()),
                        Err(_) => {
                            let _ = tx.send(Err("Failed to finalize ZIP".to_string()));
                            return;
                        }
                    }
                }
            };

            let filter_label = filter_ext.join("/");
            let path = rfd::FileDialog::new()
                .set_file_name(&default_name)
                .add_filter(&filter_label, &filter_ext)
                .save_file();
            let saved_name = path
                .as_ref()
                .map(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            if let Some(path) = path {
                if let Err(e) = std::fs::write(&path, bytes.as_slice()) {
                    let _ = tx.send(Err(format!("Failed to save file: {e}")));
                } else {
                    let _ = tx.send(Ok(SaveOutcome {
                        method_label: "plaintext".to_string(),
                        saved_name,
                        is_plaintext: true,
                        is_decoy,
                    }));
                }
            } else {
                // User cancelled.
                let _ = tx.send(Ok(SaveOutcome {
                    method_label: String::new(),
                    saved_name: String::new(),
                    is_plaintext: true,
                    is_decoy,
                }));
            }
            ctx.request_repaint();
        });
    }

    /// Collect validated methods from the popup, build the export on a
    /// worker thread, and write via a file-save dialog.
    fn launch_save_worker(&mut self, ctx: &egui::Context) {
        let popup = match self.save_popup.take() {
            Some(p) => p,
            None => return,
        };

        // Build EncryptMethod values from the editors.
        let methods: Vec<EncryptMethod> = popup
            .methods
            .iter()
            .filter_map(build_encrypt_method)
            .collect();
        if methods.len() != popup.methods.len() {
            // Should not happen if method_is_valid passed.
            self.save_status = Some(("Error: could not build encryption method.".to_owned(), true));
            self.save_status_time = Some(std::time::Instant::now());
            self.save_popup = Some(popup);
            return;
        }

        // Run the passphrase round-trip self-test for any passphrase
        // methods. This is a pipeline sanity check (age encrypt + decrypt
        // of a known test vector) — deferred from the live editor to avoid
        // running scrypt on every UI frame.
        for (i, m) in methods.iter().enumerate() {
            if let EncryptMethod::Passphrase(p) = m {
                if let Err(e) = gui_support::passphrase_roundtrip_check(p.as_str()) {
                    let share_label = if methods.len() > 1 {
                        format!("share {}: ", i + 1)
                    } else {
                        String::new()
                    };
                    self.save_status = Some((format!("{share_label}round-trip check failed: {e}"), true));
                    self.save_status_time = Some(std::time::Instant::now());
                    self.save_popup = Some(popup);
                    return;
                }
            }
        }

        let shares = popup.shares.clone();
        let threshold = popup.threshold;
        let target = popup.target;
        let title = popup.title.clone();

        // Determine package + default filename.
        let (package, default_name) = match target {
            SaveTarget::PerShare => (BulkPackage::OneFile, format!("{}.txt.age", sanitize_title(&title))),
            SaveTarget::BulkZip => (BulkPackage::Zip, format!("{}.zip", sanitize_title(&title))),
            SaveTarget::BulkOneFile => (BulkPackage::OneFile, format!("{}.txt.age", sanitize_title(&title))),
        };
        let filter_ext: Vec<&str> = match package {
            BulkPackage::Zip => vec!["zip"],
            BulkPackage::OneFile => vec!["age"],
        };

        // For per-share, only encrypt the one share.
        let (shares_to_encrypt, methods_to_use) = match target {
            SaveTarget::PerShare => (shares[..1].to_vec(), methods[..1].to_vec()),
            _ => (shares.clone(), methods.clone()),
        };

        let (tx, rx) = mpsc::channel();
        self.save_rx = Some(rx);

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = gui_support::build_bulk_export(
                &shares_to_encrypt,
                &methods_to_use,
                package,
                threshold,
            );
            match result {
                Ok(bytes) => {
                    let filter_label = filter_ext.join("/");
                    let path = rfd::FileDialog::new()
                        .set_file_name(&default_name)
                        .add_filter(&filter_label, &filter_ext)
                        .save_file();
                    let saved_name = path
                        .as_ref()
                        .map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())
                        .unwrap_or_default();
                    if let Some(path) = path {
                        if let Err(e) = std::fs::write(&path, bytes.as_slice()) {
                            let _ = tx.send(Err(format!("Failed to save file: {e}")));
                        } else {
                            let label = method_label(&methods_to_use);
                            let _ = tx.send(Ok(SaveOutcome {
                                method_label: label,
                                saved_name,
                                is_plaintext: false,
                                is_decoy: false,
                            }));
                        }
                    } else {
                        // User cancelled the file dialog.
                        let _ = tx.send(Ok(SaveOutcome {
                            method_label: String::new(),
                            saved_name: String::new(),
                            is_plaintext: false,
                            is_decoy: false,
                        }));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(format!("{e}")));
                }
            }
            ctx.request_repaint();
            // bytes / methods / shares drop here -> zeroized.
        });
    }

    /// Poll the save worker thread for results.
    fn poll_save_worker(&mut self) {
        if let Some(rx) = self.save_rx.take() {
            match rx.try_recv() {
                Ok(Ok(outcome)) => {
                    if outcome.saved_name.is_empty() && outcome.method_label.is_empty() {
                        // User cancelled the file dialog; no status.
                    } else if outcome.is_plaintext {
                        // For a *real* (non-decoy) wallet saved without
                        // encryption, remind the user the file is unencrypted.
                        // Decoy wallets are intentionally plaintext.
                        let msg = if outcome.is_decoy {
                            format!("Saved {} (plaintext)", outcome.saved_name)
                        } else {
                            format!(
                                "Saved {} (plaintext — no encryption, anyone \
                                 with the file can read it)",
                                outcome.saved_name
                            )
                        };
                        self.save_status = Some((msg, false));
                        self.save_status_time = Some(std::time::Instant::now());
                    } else {
                        self.save_status = Some((
                            format!(
                                "Saved {} (encrypted with age — {})",
                                outcome.saved_name, outcome.method_label
                            ),
                            false,
                        ));
                        self.save_status_time = Some(std::time::Instant::now());
                    }
                }
                Ok(Err(e)) => {
                    self.save_status = Some((e, true));
                    self.save_status_time = Some(std::time::Instant::now());
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.save_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.save_status =
                        Some((WORKER_DISCONNECTED_MSG.to_owned(), true));
                    self.save_status_time = Some(std::time::Instant::now());
                }
            }
        }
    }

    /// Poll the decrypt worker thread for results.
    fn poll_decrypt_worker(&mut self) {
        if let Some(rx) = self.decrypt_rx.take() {
            match rx.try_recv() {
                Ok(Ok(decrypted_text)) => {
                    // Clear any stale error from a previous failed decrypt
                    // attempt so the success path (and the next share's
                    // popup) isn't contradicted by it.
                    let rec = self.rec_mut();
                    rec.error = None;
                    // Remove the first pending armoured share (it's been
                    // decrypted). Append the plaintext as a new line.
                    rec.pending_armoured.remove(0);
                    // Append the decrypted plaintext as a new line.
                    if !rec.shares_text.is_empty() && !rec.shares_text.ends_with('\n') {
                        rec.shares_text.push('\n');
                    }
                    rec.shares_text.push_str(decrypted_text.as_str());
                    rec.shares_text.push('\n');
                    rec.decrypted = true;
                    rec.decrypted_count += 1;
                    rec.cached_analysis = Some(analyse_shares(&rec.shares_text));

                    // If there are more pending armoured shares, keep the
                    // popup open for the next one. Otherwise close it.
                    if rec.pending_armoured.is_empty() {
                        rec.decrypt_popup_open = false;
                        self.decrypt_popup = None;
                        self.file_load_rx = None;
                        self.file_load_target = None;
                    } else {
                        // Reset the popup method for the next share.
                        self.decrypt_popup = Some(DecryptPopupState {
                            method: DecryptPopupMethod::default(),
                            slide_offset: 24.0,
                        });
                    }
                }
                Ok(Err(e)) => {
                    let rec = self.rec_mut();
                    rec.error = Some(Zeroizing::new(e));
                    // Keep the popup open so the user can try again with a
                    // different credential.
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.decrypt_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    let rec = self.rec_mut();
                    rec.error = Some(Zeroizing::new(
                        WORKER_DISCONNECTED_MSG.to_owned(),
                    ));
                    rec.decrypt_popup_open = false;
                    self.decrypt_popup = None;
                    self.file_load_rx = None;
                    self.file_load_target = None;
                }
            }
        }
    }

    /// Launch an async file-load worker. Opens a native file dialog on a
    /// background thread (so the GUI doesn't freeze) and reads the file.
    /// The result is polled in [`poll_file_load_worker`].
    fn launch_file_load(&mut self, ctx: &egui::Context, target: FileLoadTarget) {
        // Guard against concurrent file loads. There is a single
        // file_load_rx / file_load_target pair — if a previous dialog is
        // still open (rx still pending), launching a new one would drop
        // the old receiver and silently lose that result. Instead, ignore
        // the new request; the user can click "Load file..." again after
        // the current dialog completes.
        if self.file_load_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.file_load_rx = Some(rx);
        self.file_load_target = Some(target);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // No file filter — accept any file. Real-world keys have
            // arbitrary extensions (id_ed25519, my_key.pem, key.txt, etc).
            // For RecoverShareFile, allow picking multiple files at once.
            let files = rfd::FileDialog::new().pick_files();
            match files {
                Some(paths) if !paths.is_empty() => {
                    // Read all selected files. For single-file targets
                    // (keys, identities), use the first file. For share
                    // files, send all contents as one blob joined by
                    // newlines.
                    match target {
                        FileLoadTarget::RecoverShareFile => {
                            let mut all_contents = Vec::new();
                            let mut names = Vec::new();
                            for path in &paths {
                                match std::fs::read(path) {
                                    Ok(data) => {
                                        if !all_contents.is_empty() {
                                            all_contents.push(b'\n');
                                        }
                                        all_contents.extend_from_slice(&data);
                                        names.push(
                                            path.file_name()
                                                .map(|n| n.to_string_lossy().to_string())
                                                .unwrap_or_default(),
                                        );
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Err(format!("Failed to read {}: {e}", path.display())));
                                        return;
                                    }
                                }
                            }
                            let name = names.join(", ");
                            let _ = tx.send(Ok((Zeroizing::new(all_contents), name)));
                        }
                        _ => {
                            // Single-file target (key / identity).
                            let path = &paths[0];
                            match std::fs::read(path) {
                                Ok(data) => {
                                    let name = path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_default();
                                    let _ = tx.send(Ok((Zeroizing::new(data), name)));
                                }
                                Err(e) => {
                                    let _ = tx.send(Err(format!("Failed to read file: {e}")));
                                }
                            }
                        }
                    }
                }
                _ => {
                    // User cancelled — send empty result so the poller clears.
                    let _ = tx.send(Err(String::new()));
                }
            }
            ctx.request_repaint();
        });
    }

    /// Poll the file-load worker. Routes the result to the appropriate
    /// field based on [`file_load_target`].
    fn poll_file_load_worker(&mut self) {
        if let Some(rx) = self.file_load_rx.take() {
            match rx.try_recv() {
                Ok(Ok((data, name))) => {
                    match self.file_load_target.take() {
                        Some(FileLoadTarget::SaveRecipient(idx)) => {
                            if let Some(popup) = &mut self.save_popup {
                                if let Some(MethodEditor::Recipient { text, last_parsed, .. }) = popup.methods.get_mut(idx) {
                                    let content = String::from_utf8_lossy(&data).trim().to_owned();
                                    *text = Zeroizing::new(content);
                                    // Force re-parse next frame.
                                    *last_parsed = Zeroizing::new(String::new());
                                }
                            }
                        }
                        Some(FileLoadTarget::DecryptKeyFile) => {
                            if let Some(popup) = &mut self.decrypt_popup {
                                if let DecryptPopupMethod::KeyFile {
                                    contents,
                                    loaded_name,
                                    pasted,
                                    ..
                                } = &mut popup.method
                                {
                                    // Populate the paste area so the user
                                    // can see what was loaded, and set the
                                    // raw bytes for the decrypt worker.
                                    *pasted =
                                        Zeroizing::new(String::from_utf8_lossy(&data).to_string());
                                    *contents = data;
                                    *loaded_name = name;
                                }
                            }
                        }
                        Some(FileLoadTarget::RecoverShareFile) => {
                            let content = String::from_utf8_lossy(&data);
                            let rec = self.rec_mut();
                            // Append as new line(s) — the armour
                            // interception will extract armoured blocks.
                            if !rec.shares_text.is_empty()
                                && !rec.shares_text.ends_with('\n')
                            {
                                rec.shares_text.push('\n');
                            }
                            rec.shares_text.push_str(content.trim());
                            rec.shares_text.push('\n');
                            // Trigger re-scan next frame by marking as changed.
                            // The text edit won't fire .changed() since we
                            // modified the backing store directly, so we
                            // manually re-run the interception.
                            let (new_text, new_armoured) =
                                extract_armoured_blocks(&rec.shares_text);
                            if !new_armoured.is_empty() {
                                rec.shares_text = Zeroizing::new(new_text);
                                rec.pending_armoured.extend(new_armoured);
                                rec.decrypt_popup_open = true;
                            }
                            rec.cached_analysis = Some(analyse_shares(&rec.shares_text));
                        }
                        None => {}
                    }
                }
                Ok(Err(e)) => {
                    // Empty error = user cancelled the dialog.
                    if !e.is_empty() {
                        let rec = self.rec_mut();
                        rec.error = Some(Zeroizing::new(e));
                    }
                    self.file_load_target = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.file_load_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.file_load_target = None;
                }
            }
        }
    }

    /// Launch the decrypt worker thread for the first pending armoured
    /// share in the queue.
    fn launch_decrypt_worker(&mut self, ctx: &egui::Context) {
        // Take the popup but keep it to restore on error.
        let popup = match self.decrypt_popup.take() {
            Some(p) => p,
            None => return,
        };

        // Pop the first pending armoured line.
        let rec = self.rec_mut();
        let armoured_line = match rec.pending_armoured.first() {
            Some(l) => l.clone(),
            None => {
                rec.error = Some(Zeroizing::new(
                    "No encrypted shares to decrypt.".to_owned(),
                ));
                return;
            }
        };

        // Build the DecryptMethod from the popup.
        let decrypt_method = match &popup.method {
            DecryptPopupMethod::Passphrase { pass, .. } => {
                DecryptMethod::Passphrase(Zeroizing::new(pass.as_str().to_owned()))
            }
            DecryptPopupMethod::KeyFile { contents, .. } => {
                DecryptMethod::AutoKey(contents.clone())
            }
        };

        let armoured_bytes = Zeroizing::new(armoured_line.into_bytes());
        let (tx, rx) = mpsc::channel();
        self.decrypt_rx = Some(rx);
        // Restore the popup so it stays visible while the worker runs.
        self.decrypt_popup = Some(popup);

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = gui_support::decrypt_share(&armoured_bytes, &decrypt_method);
            match result {
                Ok(plain) => {
                    let text = String::from_utf8_lossy(&plain).to_string();
                    let _ = tx.send(Ok(Zeroizing::new(text)));
                }
                Err(e) => {
                    let _ = tx.send(Err(format!("{e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    /// Render the decrypt popup if open.
    fn render_decrypt_popup(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let mut do_decrypt = false;
        let mut cancel_clicked = false;

        if self.decrypt_popup.is_none() {
            return;
        }

        let pending_count = self.rec_mut().pending_armoured.len();
        let mut decrypt_load_requests: Vec<FileLoadTarget> = Vec::new();

        egui::Window::new("Decrypt age-encrypted share")
            .collapsible(false)
            .resizable(true)
            .default_width(480.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .frame(
                egui::Frame::window(&ctx.style())
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0, ACCENT)),
            )
            .show(ctx, |ui| {
                ui.set_width(440.0);
                let header = if pending_count > 1 {
                    format!(
                        "Share 1 of {} is encrypted with age. \
                         Decrypt it to add it to your shares.",
                        pending_count
                    )
                } else {
                    "This share is encrypted with age. \
                     Decrypt it to add it to your shares.".to_owned()
                };
                ui.label(
                    egui::RichText::new(header)
                        .size(13.0)
                        .color(TEXT_WEAK),
                );
                ui.add_space(12.0);

                // Apply slide animation.
                let popup = self.decrypt_popup.as_mut().unwrap();
                if popup.slide_offset.abs() > 0.5 {
                    popup.slide_offset *= 0.78;
                    ui.ctx().request_repaint();
                } else {
                    popup.slide_offset = 0.0;
                }
                let offset = popup.slide_offset;

                let can_decrypt = if offset.abs() > 0.5 {
                    let mut can_dec = false;
                    let mut loads = Vec::new();
                    ui.horizontal(|ui| {
                        ui.add_space(offset);
                        ui.vertical(|ui| {
                            loads = decrypt_method_editor_ui(ui, &mut popup.method);
                            can_dec = decrypt_method_is_valid(&popup.method);
                        });
                    });
                    decrypt_load_requests.extend(loads);
                    can_dec
                } else {
                    let loads = decrypt_method_editor_ui(ui, &mut popup.method);
                    decrypt_load_requests.extend(loads);
                    decrypt_method_is_valid(&popup.method)
                };

                ui.add_space(16.0);

                // Show decrypt error (if any) inside the popup so the
                // user sees why decryption failed.
                let err_text = self
                    .rec_mut()
                    .error
                    .as_ref()
                    .map(|e| e.as_str())
                    .map(|s| s.to_owned());
                if let Some(err) = &err_text {
                    if !err.is_empty() {
                        ui.add_space(4.0);
                        error_card(ui, err);
                        ui.add_space(8.0);
                    }
                }

                // Carousel dots (if multiple pending shares).
                if pending_count > 1 {
                    let clicked_dot = carousel_dots(ui, pending_count, 0);
                    if let Some(dot) = clicked_dot {
                        // Swap the current share (index 0) with the clicked
                        // one so the clicked share becomes next.
                        let rec = self.rec_mut();
                        if dot < rec.pending_armoured.len() {
                            rec.pending_armoured.swap(0, dot);
                            // Kick the slide animation.
                            self.decrypt_popup.as_mut().unwrap().slide_offset =
                                if dot > 0 { 24.0 } else { -24.0 };
                        }
                    }
                    ui.add_space(12.0);
                }

                ui.horizontal(|ui| {
                    let decrypt_busy = self.decrypt_rx.is_some();
                    if decrypt_busy {
                        // Animated "Decrypting" with dots.
                        let dots = (ui.ctx().input(|i| i.time) * 2.0) as usize % 4;
                        let label = format!("Decrypting{}", ".".repeat(dots));
                        ui.add_enabled(false, egui::Button::new(label));
                        ui.add_space(8.0);
                        ui.spinner();
                        ui.ctx().request_repaint();
                    } else {
                        if ui.button("Cancel").clicked() {
                            cancel_clicked = true;
                        }
                        ui.add_space(10.0);
                        let btn = ui.add_enabled(
                            can_decrypt,
                            egui::Button::new(
                                egui::RichText::new("Decrypt").strong().color(TEXT_BRIGHT),
                            )
                            .fill(ACCENT)
                            .corner_radius(8.0),
                        );
                        if btn.clicked() && can_decrypt {
                            do_decrypt = true;
                        }
                        // Enter key triggers decrypt.
                        if can_decrypt
                            && ui.ctx().input(|i| i.key_pressed(egui::Key::Enter))
                        {
                            do_decrypt = true;
                        }
                    }
                });
            });

        for target in decrypt_load_requests {
            self.launch_file_load(ctx, target);
        }

        if cancel_clicked {
            // Close the popup but keep the armoured share in
            // `pending_armoured` so the user can retry later. The armoured
            // text must never be dumped back into the recover text area —
            // it would be indistinguishable from a plaintext share and
            // break the extract/decrypt flow.
            let rec = self.rec_mut();
            rec.decrypt_popup_open = false;
            rec.error = None;
            close = true;
        }

        if do_decrypt {
            // Clear any previous error before launching.
            self.rec_mut().error = None;
            self.launch_decrypt_worker(ctx);
        }
        if close {
            self.decrypt_popup = None;
            self.rec_mut().decrypt_popup_open = false;
            self.file_load_rx = None;
            self.file_load_target = None;
        }
    }
}

/// Render clickable carousel dots. Returns the index of a clicked dot,
/// or `None`.
///
/// The current dot is highlighted in `ACCENT`, others in `CARD_STROKE`.
/// Hovered dots get a slightly larger radius for feedback.
fn carousel_dots(
    ui: &mut egui::Ui,
    count: usize,
    current: usize,
) -> Option<usize> {
    let dot_size = 8.0_f32;
    let dot_spacing = 6.0;
    let total_dots_w = count as f32 * (dot_size + dot_spacing) - dot_spacing;
    let (dots_rect, dots_resp) = ui.allocate_exact_size(
        egui::vec2(total_dots_w, dot_size + 4.0),
        egui::Sense::click(),
    );
    let painter = ui.painter();
    let hover_pos = dots_resp.hover_pos();
    let mut clicked = None;

    for i in 0..count {
        let dot_center = egui::pos2(
            dots_rect.left() + i as f32 * (dot_size + dot_spacing) + dot_size / 2.0,
            dots_rect.center().y,
        );
        let is_current = i == current;
        let is_hovered = hover_pos.is_some_and(|p| {
            (p - dot_center).length() < dot_size
        });
        let color = if is_current {
            ACCENT
        } else if is_hovered {
            ACCENT_HOVER
        } else {
            CARD_STROKE
        };
        let radius = if is_current || is_hovered {
            dot_size / 2.0
        } else {
            dot_size / 2.5
        };
        painter.circle_filled(dot_center, radius, color);
    }

    // Click on a dot to jump to that index.
    if dots_resp.clicked() {
        if let Some(pos) = dots_resp.interact_pointer_pos() {
            let click_x = pos.x - dots_rect.left();
            let clicked_dot = (click_x / (dot_size + dot_spacing)).round() as isize;
            if clicked_dot >= 0 && (clicked_dot as usize) < count {
                clicked = Some(clicked_dot as usize);
            }
        }
    }
    clicked
}

/// Extract multi-line age armoured blocks from a text blob.
///
/// Returns `(plain_text, armoured_blocks)` where `plain_text` has all
/// armoured blocks removed and `armoured_blocks` is a vec of each complete
/// block (BEGIN line through END line, inclusive).
///
/// This handles age ASCII armour, which is a multi-line block:
/// ```text
/// -----BEGIN AGE ENCRYPTED FILE-----
/// <base64 body, possibly multiple lines>
/// -----END AGE ENCRYPTED FILE-----
/// ```
///
/// Plain (non-armoured) lines outside blocks are preserved in order.
fn extract_armoured_blocks(text: &str) -> (String, Vec<String>) {
    const BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
    const END: &str = "-----END AGE ENCRYPTED FILE-----";

    let mut plain_lines: Vec<String> = Vec::new();
    let mut armoured_blocks: Vec<String> = Vec::new();

    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim().starts_with(BEGIN) {
            // Start of an armoured block — collect until END (inclusive).
            let mut block = String::new();
            block.push_str(line);
            block.push('\n');
            let mut found_end = false;
            #[allow(clippy::while_let_on_iterator)]
            while let Some(body_line) = lines.next() {
                block.push_str(body_line);
                block.push('\n');
                if body_line.trim().starts_with(END) {
                    found_end = true;
                    break;
                }
            }
            if found_end {
                armoured_blocks.push(block);
            } else {
                // No END line found — the armour is corrupt/incomplete.
                // Push the entire block (BEGIN line + consumed body) back
                // into plain text so the user can see what they pasted and
                // fix it, rather than silently losing the body lines.
                plain_lines.push(block.trim_end_matches('\n').to_owned());
            }
        } else {
            plain_lines.push(line.to_owned());
        }
    }

    (plain_lines.join("\n"), armoured_blocks)
}

fn duress_notice_card(ui: &mut egui::Ui) {
    egui::Frame::group(ui.style())
        .fill(AMBER_BG)
        .stroke(egui::Stroke::new(1.0, AMBER))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                icon(ui, 16.0, Icon::Warning, AMBER);
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Duress notice: age armour stanza headers reveal the recipient type. \
                         For Real and Decoy shares to be indistinguishable, use matching methods \
                         in matching share positions."
                    )
                    .size(12.0)
                    .color(egui::Color32::from_rgb(255, 210, 120)),
                );
            });
        });
}

/// Render a method editor row (passphrase or recipient) inside the popup.
/// `method_idx` is the index of this method in the popup's `methods` vec,
/// used to route file-load results to the correct share.
fn method_editor_ui(
    ui: &mut egui::Ui,
    method: &mut MethodEditor,
    method_idx: usize,
) -> Vec<FileLoadTarget> {
    let mut load_requests = Vec::new();
    let current_kind = match method {
        MethodEditor::Passphrase { .. } => MethodKind::Passphrase,
        MethodEditor::Recipient { .. } => MethodKind::Recipient,
    };
    let mut new_kind = current_kind;

    ui.horizontal(|ui| {
        ui.radio_value(&mut new_kind, MethodKind::Passphrase, "Passphrase");
        ui.radio_value(&mut new_kind, MethodKind::Recipient, "age public key / SSH key");
    });
    ui.add_space(8.0);

    match method {
        MethodEditor::Passphrase { pass, confirm, error } => {
            field_label(ui, "Passphrase");
            ui.add_sized(
                [ui.available_width(), 32.0],
                egui::TextEdit::singleline(&mut **pass)
                    .password(true)
                    .id_salt(format!("popup_pass_{method_idx}")),
            );
            ui.add_space(4.0);
            field_label(ui, "Confirm passphrase");
            ui.add_sized(
                [ui.available_width(), 32.0],
                egui::TextEdit::singleline(&mut **confirm)
                    .password(true)
                    .id_salt(format!("popup_pass_confirm_{method_idx}")),
            );
            // Live mismatch check only (instant). The expensive age
            // round-trip self-test is deferred to save time.
            if !pass.is_empty() && pass.as_str() == confirm.as_str() {
                *error = None;
            } else if !pass.is_empty() || !confirm.is_empty() {
                *error = Some("Passphrases do not match.".to_owned());
            } else {
                *error = None;
            }
            if let Some(err) = error {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    icon(ui, 13.0, Icon::Warning, RED);
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(err.as_str()).size(12.0).color(RED));
                });
            }
        }
        MethodEditor::Recipient { text, fingerprint, confirmed, error, last_parsed } => {
            field_label(ui, "Recipient (paste age1... or ssh-... key)");
            let _text_resp = ui.add_sized(
                [ui.available_width(), 60.0],
                egui::TextEdit::multiline(&mut **text)
                    .code_editor()
                    .id_salt(format!("popup_recipient_{method_idx}")),
            );
            ui.add_space(4.0);
            if ui.button("Load file...").clicked() {
                load_requests.push(FileLoadTarget::SaveRecipient(method_idx));
            }
            ui.add_space(4.0);

            // Parse recipient and show fingerprint — only when the text
            // has changed since the last parse.
            let text_changed = text.as_str() != last_parsed.as_str();
            if text_changed {
                if !text.trim().is_empty() {
                    match gui_support::parse_recipient(text.trim()) {
                        Ok(m) => {
                            *fingerprint = gui_support::recipient_fingerprint(&m);
                            *error = None;
                        }
                        Err(e) => {
                            *fingerprint = None;
                            *error = Some(format!("Invalid recipient: {e}"));
                        }
                    }
                } else {
                    *fingerprint = None;
                    *error = None;
                }
                *last_parsed = Zeroizing::new(text.as_str().to_owned());
            }

            if let Some(fp) = fingerprint {
                ui.horizontal(|ui| {
                    icon(ui, 13.0, Icon::Check, GREEN);
                    ui.add_space(4.0);
                    // The full recipient string (age1... or ssh-ed25519
                    // AAAA...) can be very long — wrap in a horizontal
                    // scroll so the popup doesn't stretch off-screen and
                    // the user can still scroll to verify the full key.
                    egui::ScrollArea::horizontal()
                        .id_salt(format!("recipient_fp_{method_idx}"))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(format!("Recipient: {fp}"))
                                    .size(12.0)
                                    .color(GREEN),
                            );
                        });
                });
            }
            if let Some(err) = error {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    icon(ui, 13.0, Icon::Warning, RED);
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(err.as_str()).size(12.0).color(RED));
                });
            }

            ui.add_space(4.0);
            ui.checkbox(
                confirmed,
                "I confirm this recipient is correct",
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(
                    "You may be encrypting to someone else's public key. \
                     Confirm the fingerprint matches what you received."
                )
                .size(11.0)
                .color(TEXT_WEAK),
            );
        }
    }

    // Switch method kind if a radio was clicked.
    if new_kind != current_kind {
        *method = match new_kind {
            MethodKind::Passphrase => MethodEditor::default_passphrase(),
            MethodKind::Recipient => MethodEditor::Recipient {
                text: Zeroizing::new(String::new()),
                fingerprint: None,
                confirmed: false,
                error: None,
                last_parsed: Zeroizing::new(String::new()),
            },
        };
    }
    load_requests
}

/// Internal radio enum for method kind switching.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MethodKind {
    Passphrase,
    Recipient,
}

impl MethodEditor {
    fn default_passphrase() -> Self {
        MethodEditor::Passphrase {
            pass: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            error: None,
        }
    }
}

impl Default for MethodEditor {
    fn default() -> Self {
        Self::default_passphrase()
    }
}

/// Check if a method editor has valid input ready to encrypt.
fn method_is_valid(method: &MethodEditor) -> bool {
    match method {
        MethodEditor::Passphrase { pass, confirm, error } => {
            !pass.is_empty()
                && pass.as_str() == confirm.as_str()
                && error.is_none()
        }
        MethodEditor::Recipient { text, fingerprint, confirmed, error, .. } => {
            !text.trim().is_empty()
                && fingerprint.is_some()
                && *confirmed
                && error.is_none()
        }
    }
}

/// Render a decrypt method editor (passphrase / age identity / SSH key)
/// inside the Recover tab decrypt popup.
fn decrypt_method_editor_ui(
    ui: &mut egui::Ui,
    method: &mut DecryptPopupMethod,
) -> Vec<FileLoadTarget> {
    // Collects "Load file..." button clicks so the caller can launch
    // async file-load workers (we can't do it here because we don't own
    // the App / channels).
    let mut load_requests = Vec::new();

    let current_kind = match method {
        DecryptPopupMethod::Passphrase { .. } => DecryptKind::Passphrase,
        DecryptPopupMethod::KeyFile { .. } => DecryptKind::KeyFile,
    };
    let mut new_kind = current_kind;

    ui.horizontal(|ui| {
        ui.radio_value(&mut new_kind, DecryptKind::Passphrase, "Passphrase");
        ui.radio_value(&mut new_kind, DecryptKind::KeyFile, "age / SSH key");
    });
    ui.add_space(8.0);

    match method {
        DecryptPopupMethod::Passphrase { pass, error } => {
            field_label(ui, "Passphrase");
            ui.add_sized(
                [ui.available_width(), 32.0],
                egui::TextEdit::singleline(&mut **pass)
                    .password(true)
                    .id_salt("decrypt_pass"),
            );
            *error = None;
        }
        DecryptPopupMethod::KeyFile { contents, loaded_name, pasted, error } => {
            field_label(ui, "age identity or SSH private key (paste or load file)");
            ui.add_sized(
                [ui.available_width(), 70.0],
                egui::TextEdit::multiline(&mut **pasted)
                    .code_editor()
                    .id_salt("decrypt_key_paste"),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Load file...").clicked() {
                    load_requests.push(FileLoadTarget::DecryptKeyFile);
                }
                if !loaded_name.is_empty() {
                    ui.label(
                        egui::RichText::new(format!("Loaded: {}", loaded_name))
                            .size(12.0)
                            .color(GREEN),
                    );
                }
            });
            // `contents` is always derived from `pasted`. When a file
            // is loaded, poll_file_load_worker populates `pasted` with the
            // file text (and `loaded_name` for the badge), so the user sees
            // the contents and `contents` stays in sync. The key type (age
            // identity vs SSH) is auto-detected at decrypt time.
            *contents = if pasted.trim().is_empty() {
                Zeroizing::new(Vec::new())
            } else {
                Zeroizing::new(pasted.as_bytes().to_vec())
            };
            *error = None;
        }
    }

    if let Some(err) = decrypt_method_error(method) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            icon(ui, 13.0, Icon::Warning, RED);
            ui.add_space(4.0);
            ui.label(egui::RichText::new(err).size(12.0).color(RED));
        });
    }

    // Switch method kind if a radio was clicked.
    if new_kind != current_kind {
        *method = match new_kind {
            DecryptKind::Passphrase => DecryptPopupMethod::Passphrase {
                pass: Zeroizing::new(String::new()),
                error: None,
            },
            DecryptKind::KeyFile => DecryptPopupMethod::KeyFile {
                contents: Zeroizing::new(Vec::new()),
                loaded_name: String::new(),
                pasted: Zeroizing::new(String::new()),
                error: None,
            },
        };
    }
    load_requests
}

/// Internal radio enum for decrypt method kind switching.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DecryptKind {
    Passphrase,
    KeyFile,
}

/// Check if a decrypt method editor has valid input ready to decrypt.
fn decrypt_method_is_valid(method: &DecryptPopupMethod) -> bool {
    decrypt_method_has_input(method) && decrypt_method_error(method).is_none()
}

/// Return the validation error for a decrypt method, if any.
/// Returns None for simply-empty fields (the Decrypt button is disabled
/// silently — no red error text). Only returns Some for actual errors
/// like a wrong passphrase or failed load.
fn decrypt_method_error(method: &DecryptPopupMethod) -> Option<&str> {
    match method {
        DecryptPopupMethod::Passphrase { error, .. } => error.as_deref(),
        DecryptPopupMethod::KeyFile { error, .. } => error.as_deref(),
    }
}

/// Check if a decrypt method has enough input to attempt decryption
/// (fields are non-empty, regardless of errors).
fn decrypt_method_has_input(method: &DecryptPopupMethod) -> bool {
    match method {
        DecryptPopupMethod::Passphrase { pass, .. } => !pass.is_empty(),
        DecryptPopupMethod::KeyFile { contents, .. } => !contents.is_empty(),
    }
}

/// Build an `EncryptMethod` from a validated `MethodEditor`.
fn build_encrypt_method(method: &MethodEditor) -> Option<EncryptMethod> {
    match method {
        MethodEditor::Passphrase { pass, .. } => {
            if pass.is_empty() {
                None
            } else {
                Some(EncryptMethod::Passphrase(Zeroizing::new(pass.as_str().to_owned())))
            }
        }
        MethodEditor::Recipient { text, .. } => {
            let m = gui_support::parse_recipient(text.trim()).ok()?;
            Some(m)
        }
    }
}

/// Plain-word method label for the status banner.
fn method_label(methods: &[EncryptMethod]) -> String {
    if methods.len() == 1 {
        truncate_for_toast(&single_method_label(&methods[0]), 40)
    } else {
        // Per-share: list each share's method.
        let parts: Vec<String> = methods
            .iter()
            .enumerate()
            .map(|(i, m)| {
                format!(
                    "share {}: {}",
                    i + 1,
                    truncate_for_toast(&single_method_label(m), 30)
                )
            })
            .collect();
        parts.join(", ")
    }
}

fn single_method_label(m: &EncryptMethod) -> String {
    match m {
        EncryptMethod::Passphrase(_) => "passphrase".to_owned(),
        EncryptMethod::AgeRecipient(_) => {
            gui_support::recipient_fingerprint(m)
                .unwrap_or_else(|| "X25519 recipient".to_owned())
        }
        EncryptMethod::SshRecipient(_) => {
            gui_support::recipient_fingerprint(m)
                .unwrap_or_else(|| "SSH recipient".to_owned())
        }
    }
}

/// Truncate a string for display in a toast, keeping the prefix (key type)
/// and a tail snippet so the user can still identify which key was used.
/// e.g. "ssh-ed25519 AAAA...xyz" instead of the full multi-line key.
fn truncate_for_toast(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let keep = max.saturating_sub(3); // room for "..."
        let head: String = s.chars().take(keep).collect();
        format!("{head}...")
    }
}

/// Sanitize a popup title into a filesystem-safe filename stem.
fn sanitize_title(title: &str) -> String {
    title
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

// ─── Error classification ───────────────────────────────────────────────────

fn classify_generate_error(e: &anyhow::Error) -> String {
    format!("Error: {}", e)
}

fn classify_split_error(e: &anyhow::Error) -> String {
    let msg = e.to_string().to_lowercase();
    if msg.contains("invalid bip-39") || msg.contains("invalid mnemonic") {
        return "Error: Could not parse the secret. Check that the mnemonic is spelled correctly.".to_owned();
    }
    if msg.contains("hex") {
        return "Error: Invalid hex. A hex spend key must be an even number of hex digits.".to_owned();
    }
    format!("Error: {}", e)
}

fn classify_recover_error(e: &anyhow::Error) -> String {
    let msg = e.to_string().to_lowercase();

    if msg.contains("must begin with the same")
        || msg.contains("identifier")
        || msg.contains("iteration exponent")
        || msg.contains("group threshold")
        || msg.contains("group count")
        || msg.contains("member threshold")
        || msg.contains("invalid set of mnemonics")
        || msg.contains("insufficient number")
    {
        return "Error: Invalid shares. Did you mix Real and Decoy shares?".to_owned();
    }

    if msg.contains("digest")
        || msg.contains("decrypt")
        || msg.contains("checksum")
        || msg.contains("padding")
    {
        return "Error: Invalid password or corrupted shares.".to_owned();
    }

    if msg.contains("not an sssmc39 word") || msg.contains("invalid mnemonic") {
        return "Error: Invalid shares. Check that each share is spelled correctly and on its own line.".to_owned();
    }

    "Error: Could not recover the wallet from these shares.".to_owned()
}

/// Classify an error from the Derive tab into a user-facing message.
///
/// The derive path has no SLIP-0039 / password dimension — the only
/// failure modes are malformed input (bad hex, wrong word count, bad
/// checksum) — so we translate the two common ones and otherwise surface
/// the raw error.
fn classify_derive_error(e: &anyhow::Error) -> String {
    let msg = e.to_string().to_lowercase();
    if msg.contains("bip-39 entropy") || msg.contains("even number of hex digits") {
        return "Error: Invalid hex entropy. BIP-39 needs 16/20/24/28/32 bytes (32/40/48/56/64 hex chars).".to_owned();
    }
    if msg.contains("mnemonic") || msg.contains("spend key") || msg.contains("checksum") {
        return "Error: Could not derive keys. Check the spend key / mnemonic is correct.".to_owned();
    }
    format!("Error: {e}")
}
