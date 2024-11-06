use libxml::parser::Parser as XmlParser;
use std::fs;
use rfd::FileDialog;
use hash_lyzer::{create_node_hash};
use hash_lyzer::error::Error;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "XML Hash Viewer",
        options,
        Box::new(|_cc| -> Result<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Box::new(MyApp::default()))
        }),
    )?;
    Ok(())
}
struct MyApp {
    file_path: String,
    header_hashes: Vec<String>,
    body_hashes: Vec<String>,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            header_hashes: Vec::new(),
            body_hashes: Vec::new(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if ui.button("Select XML File").clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.file_path = path.display().to_string();
                    self.process_file();
                }
            }

            ui.label(format!("File: {}", self.file_path));

            ui.separator();

            ui.heading("LogRecordHeader Hashes:");
            for (i, hash) in self.header_hashes.iter().enumerate() {
                ui.label(format!("{}: {}", i + 1, hash));
            }

            ui.separator();

            ui.heading("LogRecordBody Hashes:");
            for (i, hash) in self.body_hashes.iter().enumerate() {
                ui.label(format!("{}: {}", i + 1, hash));
            }
        });
    }
}

impl MyApp {
    fn process_file(&mut self) {
        if self.file_path.is_empty() {
            return;
        }

        let xml_content = fs::read_to_string(&self.file_path).expect("Unable to read file");
        let parser = XmlParser::default();
        let doc = parser.parse_string(&xml_content).expect("Unable to parse XML");
        let root = doc.get_root_element().expect("Root element not found");

        self.header_hashes.clear();
        self.body_hashes.clear();

        for child in root.get_child_nodes() {
            if child.get_name() == "LogRecordElement" {
                let grand_children = child.get_child_nodes();
                for mut grand_child in grand_children {
                    if grand_child.get_name() == "LogRecordHeader" {
                        let hash = create_node_hash(&doc, &grand_child).expect("Unable to create hash");
                        self.header_hashes.push(hash);
                    }
                    if grand_child.get_name() == "LogRecordBody" {
                        let hash = create_node_hash(&doc, &grand_child).expect("Unable to create hash");
                        self.body_hashes.push(hash);
                    }
                }
            }
        }
    }
}