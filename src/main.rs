#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use rss_registry::ui;

fn load_icon() -> Option<eframe::egui::IconData> {
    let bytes = include_bytes!("../rss.ico");
    let image = image::load_from_memory(bytes).ok()?;
    let image = image.to_rgba8();
    let (width, height) = image.dimensions();
    Some(eframe::egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    })
}

fn main() -> eframe::Result<()> {
    let mut viewport = eframe::egui::ViewportBuilder::default().with_inner_size([1280.0, 720.0]);
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "RSS-Registry",
        options,
        Box::new(|_cc| Box::new(ui::RegistryApp::new())),
    )
}
