use std::collections::HashSet;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, Align, Color32, Event, Key, Layout, Sense, TextStyle, Visuals};
use egui_extras::{Column, TableBuilder};

use crate::model::{ExtensionFilters, Record, SourceKind};
use crate::sources;
use crate::time::{format_datetime, format_file_times};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    File,
    Path,
    Date,
    Deleted,
    ExecutedAt,
}

pub struct RegistryApp {
    records: Vec<Record>,
    filters: ExtensionFilters,
    search_query: String,
    selected_sources: HashSet<SourceKind>,
    sort_column: SortColumn,
    sort_desc: bool,
    scanning: bool,
    status: String,
    rx: Option<Receiver<Vec<Record>>>,
    style_applied: bool,
    show_sources_modal: bool,
    zoom: f32,
}

impl RegistryApp {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            filters: ExtensionFilters::new(),
            search_query: String::new(),
            selected_sources: crate::model::all_sources().into_iter().collect(),
            sort_column: SortColumn::ExecutedAt,
            sort_desc: true,
            scanning: false,
            status: String::from("Готово"),
            rx: None,
            style_applied: false,
            show_sources_modal: false,
            zoom: 1.0,
        }
    }

    fn apply_style(&mut self, ctx: &egui::Context) {
        if self.style_applied {
            return;
        }
        let mut visuals = Visuals::dark();
        visuals.override_text_color = Some(Color32::from_rgb(230, 230, 230));
        visuals.window_fill = Color32::from_rgb(11, 11, 11);
        visuals.extreme_bg_color = Color32::from_rgb(8, 8, 8);
        visuals.widgets.active.bg_fill = Color32::from_rgb(30, 30, 30);
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(20, 20, 20);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(40, 15, 20);
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(176, 0, 32));
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(176, 0, 32));
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(90, 90, 90));
        visuals.selection.bg_fill = Color32::from_rgb(176, 0, 32);
        visuals.selection.stroke = egui::Stroke::new(1.0, Color32::from_rgb(220, 220, 220));
        ctx.set_visuals(visuals);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
        style.text_styles.insert(
            TextStyle::Heading,
            egui::FontId::new(22.0, egui::FontFamily::Proportional),
        );
        ctx.set_style(style);
        self.style_applied = true;
    }

    fn handle_zoom(&mut self, ctx: &egui::Context) {
        let (zoom_delta, ctrl, plus, minus, events) = ctx.input(|i| {
            (
                i.zoom_delta(),
                i.modifiers.ctrl,
                i.key_pressed(Key::Equals),
                i.key_pressed(Key::Minus),
                i.events.clone(),
            )
        });

        let mut factor = 1.0f32;

        // Built-in ctrl+scroll/pinch.
        if (zoom_delta - 1.0).abs() > f32::EPSILON {
            factor *= zoom_delta;
        }

        // Explicit ctrl + wheel handling to ensure we react even if scroll is consumed elsewhere.
        if ctrl {
            for ev in events {
                if let Event::Scroll(delta) = ev {
                    if delta.y > 0.0 {
                        factor *= 1.1;
                    } else if delta.y < 0.0 {
                        factor /= 1.1;
                    }
                }
            }
        }

        // Keyboard +/- when ctrl is held.
        if ctrl && plus {
            factor *= 1.1;
        }
        if ctrl && minus {
            factor /= 1.1;
        }

        if (factor - 1.0).abs() > f32::EPSILON {
            self.zoom = (self.zoom * factor).clamp(0.5, 3.0);
            ctx.request_repaint(); // ensure immediate refresh after zoom
        }

        ctx.set_pixels_per_point(self.zoom);
    }

    fn start_scan(&mut self) {
        let selected = self.selected_sources.clone();
        let (tx, rx) = mpsc::channel();
        self.scanning = true;
        self.status = "Сканирование...".to_string();
        thread::spawn(move || {
            let result = std::panic::catch_unwind(|| sources::scan_selected(&selected));
            let data = result.unwrap_or_else(|_| Vec::new());
            let _ = tx.send(data);
        });
        self.rx = Some(rx);
    }

    fn poll_results(&mut self) {
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(records) => {
                    self.records = records;
                    self.scanning = false;
                    self.status = format!("Найдено записей: {}", self.records.len());
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.scanning = false;
                    if self.records.is_empty() {
                        self.status = "Данные не получены".to_string();
                    }
                }
            }
        }
    }

    fn filtered_sorted_records(&self) -> Vec<Record> {
        let query = self.search_query.to_lowercase();
        let mut data: Vec<Record> = self
            .records
            .iter()
            .filter(|rec| self.filters.is_allowed(&rec.path))
            .filter(|rec| {
                if query.is_empty() {
                    true
                } else {
                    rec.file_name.to_lowercase().contains(&query)
                        || rec.path.to_lowercase().contains(&query)
                }
            })
            .cloned()
            .collect();

        data.sort_by(|a, b| self.compare_records(a, b));
        if self.sort_desc {
            data.reverse();
        }
        data
    }

    fn compare_records(&self, a: &Record, b: &Record) -> std::cmp::Ordering {
        match self.sort_column {
            SortColumn::File => a.file_name.to_lowercase().cmp(&b.file_name.to_lowercase()),
            SortColumn::Path => a.path.to_lowercase().cmp(&b.path.to_lowercase()),
            SortColumn::Deleted => a.deleted.cmp(&b.deleted),
            SortColumn::Date => {
                let am = a.file_times.as_ref().and_then(|ft| ft.modified);
                let bm = b.file_times.as_ref().and_then(|ft| ft.modified);
                am.cmp(&bm)
            }
            SortColumn::ExecutedAt => {
                let aexec = a.executed_at;
                let bexec = b.executed_at;
                if aexec == bexec {
                    let am = a.file_times.as_ref().and_then(|ft| ft.modified);
                    let bm = b.file_times.as_ref().and_then(|ft| ft.modified);
                    if am == bm {
                        return a.path.to_lowercase().cmp(&b.path.to_lowercase());
                    }
                    return am.cmp(&bm);
                }
                aexec.cmp(&bexec)
            }
        }
    }

    fn render_sources_modal(&mut self, ctx: &egui::Context) {
        egui::Window::new("Выбор источников")
            .collapsible(false)
            .resizable(false)
            .open(&mut self.show_sources_modal)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    for source in crate::model::all_sources() {
                        let mut enabled = self.selected_sources.contains(&source);
                        if ui.checkbox(&mut enabled, source.label()).clicked() {
                            if enabled {
                                self.selected_sources.insert(source);
                            } else {
                                self.selected_sources.remove(&source);
                            }
                        }
                    }
                });
            });
    }

    fn open_in_explorer(&mut self, rec: &Record) {
        if rec.deleted {
            self.status = "File not found".to_string();
            return;
        }
        let _ = std::process::Command::new("explorer.exe")
            .args(["/select,", &rec.path])
            .spawn();
    }

    fn render_top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("RSS-Registry");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let search = egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text("Search...")
                        .desired_width(240.0);
                    ui.add(search);
                });
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new("Сканировать")
                            .fill(Color32::from_rgb(176, 0, 32))
                            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(230, 230, 230))),
                    )
                    .clicked()
                {
                    if !self.scanning {
                        self.start_scan();
                    }
                }
                if ui
                    .add(
                        egui::Button::new("Выбор реестра")
                            .fill(Color32::from_rgb(30, 30, 30))
                            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(90, 90, 90))),
                    )
                    .clicked()
                {
                    self.show_sources_modal = true;
                }
                ui.separator();
                ui.label("Фильтры:");
                ui.checkbox(&mut self.filters.exe, ".exe");
                ui.checkbox(&mut self.filters.dll, ".dll");
                ui.checkbox(&mut self.filters.jar, ".jar");
                ui.checkbox(&mut self.filters.rar, ".rar");
                ui.checkbox(&mut self.filters.zip, ".zip");
                ui.checkbox(&mut self.filters.bat, ".bat");
                ui.checkbox(&mut self.filters.nfp, "NFP");
            });
            ui.add_space(4.0);
        });
    }

    fn render_table(&mut self, ui: &mut egui::Ui) {
        let data = self.filtered_sorted_records();
        let total = data.len();

        let row_height = 26.0;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(Align::Center))
            .column(Column::initial(180.0).at_least(140.0))
            .column(Column::remainder().at_least(250.0))
            .column(Column::initial(260.0).clip(true))
            .column(Column::initial(70.0))
            .column(Column::initial(180.0).clip(true))
            .header(row_height, |mut header| {
                header.col(|ui| {
                    if ui
                        .add(
                            egui::Label::new(" File")
                                .sense(Sense::click())
                                .truncate(true),
                        )
                        .clicked()
                    {
                        self.toggle_sort(SortColumn::File);
                    }
                });
                header.col(|ui| {
                    if ui
                        .add(
                            egui::Label::new("Path")
                                .sense(Sense::click())
                                .truncate(true),
                        )
                        .clicked()
                    {
                        self.toggle_sort(SortColumn::Path);
                    }
                });
                header.col(|ui| {
                    if ui
                        .add(
                            egui::Label::new("Date")
                                .sense(Sense::click())
                                .truncate(true),
                        )
                        .clicked()
                    {
                        self.toggle_sort(SortColumn::Date);
                    }
                });
                header.col(|ui| {
                    if ui
                        .add(
                            egui::Label::new("Deleted")
                                .sense(Sense::click())
                                .truncate(true),
                        )
                        .clicked()
                    {
                        self.toggle_sort(SortColumn::Deleted);
                    }
                });
                header.col(|ui| {
                    if ui
                        .add(
                            egui::Label::new("Executed At")
                                .sense(Sense::click())
                                .truncate(true),
                        )
                        .clicked()
                    {
                        self.toggle_sort(SortColumn::ExecutedAt);
                    }
                });
            })
            .body(|body| {
                body.rows(row_height, data.len(), |mut row| {
                    let rec = &data[row.index()];
                    let mut double_clicked = false;
                    row.col(|ui| {
                        let resp = ui.add(
                            egui::Label::new(format!("  {}", rec.file_name))
                                .sense(Sense::click())
                                .truncate(true),
                        );
                        if resp.double_clicked() {
                            double_clicked = true;
                        }
                    });
                    row.col(|ui| {
                        let resp = ui.add(
                            egui::Label::new(&rec.path)
                                .sense(Sense::click())
                                .truncate(true),
                        );
                        if resp.double_clicked() {
                            double_clicked = true;
                        }
                    });
                    row.col(|ui| {
                        if let Some(ft) = &rec.file_times {
                            ui.label(format_file_times(ft));
                        } else if let Some(exec) = rec.executed_at {
                            ui.label(format!("Executed: {}", format_datetime(&exec)));
                        } else {
                            ui.label("Отсутствует дата");
                        }
                    });
                    row.col(|ui| {
                        let text = if rec.deleted { "Yes" } else { "No" };
                        let color = if rec.deleted {
                            Color32::from_rgb(176, 0, 32)
                        } else {
                            Color32::from_rgb(140, 200, 140)
                        };
                        ui.colored_label(color, text);
                    });
                    row.col(|ui| {
                        if let Some(exec) = rec.executed_at {
                            ui.label(format_datetime(&exec));
                        } else {
                            ui.label("");
                        }
                    });

                    if double_clicked {
                        self.open_in_explorer(rec);
                    }
                });
            });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(format!("Всего записей: {}", total));
        });
    }

    fn toggle_sort(&mut self, col: SortColumn) {
        if self.sort_column == col {
            self.sort_desc = !self.sort_desc;
        } else {
            self.sort_column = col;
            self.sort_desc = true;
        }
    }
}

impl eframe::App for RegistryApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_style(ctx);
        self.handle_zoom(ctx);
        self.poll_results();

        self.render_top_bar(ctx);

        if self.show_sources_modal {
            self.render_sources_modal(ctx);
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(Color32::from_rgb(11, 11, 11)))
            .show(ctx, |ui| {
                self.render_table(ui);
            });

        egui::TopBottomPanel::bottom("status_bar")
            .frame(egui::Frame::none().fill(Color32::from_rgb(15, 15, 15)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(&self.status);
                    if self.scanning {
                        ui.spinner();
                    }
                });
            });
    }
}
