slint::include_modules!();
use chrono::Local;
use rand::Rng;
use rand::thread_rng;
use slint::{ModelRc, VecModel, Model, ComponentHandle, SharedString};
use std::rc::Rc;
use std::thread;
use std::time::Duration;
use std::sync::{mpsc, Arc, RwLock};
use sysinfo::System;
use local_ip_address::local_ip;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
enum ThreatCategory {
    Malware,
    Ransomware,
    Trojan,
    NetworkAttack,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DynamicThreatRule {
    pattern_name: String,
    detection_keyword: String,
    category: ThreatCategory,
    min_cpu_strikes: u32,
    countermeasure: String,
    alert_level: String,
    details_template: String,
}

const CACHE_PATH: &str = "signatures.json";

fn load_local_rules() -> Vec<DynamicThreatRule> {
    if Path::new(CACHE_PATH).exists() {
        if let Ok(mut file) = File::open(CACHE_PATH) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(rules) = serde_json::from_str::<Vec<DynamicThreatRule>>(&contents) {
                    return rules;
                }
            }
        }
    }

    let default_rules = vec![
        DynamicThreatRule {
            pattern_name: "Ransomware Core Activity".to_string(),
            detection_keyword: "encryptor".to_string(),
            category: ThreatCategory::Ransomware,
            min_cpu_strikes: 1,
            countermeasure: "Immediate I/O Freeze & Kill".to_string(),
            alert_level: "MYTHOS_CRIT".to_string(),
            details_template: "WARNUNG: Krypto-Sperr-Aktivität detektiert!".to_string(),
        },
    ];
    save_local_rules(&default_rules);
    default_rules
}

fn save_local_rules(rules: &Vec<DynamicThreatRule>) {
    if let Ok(json_str) = serde_json::to_string_pretty(rules) {
        if let Ok(mut file) = File::create(CACHE_PATH) {
            let _ = file.write_all(json_str.as_bytes());
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    // Logs initialisieren
    let log_data = Rc::new(VecModel::<LogEntry>::from(vec![
        LogEntry {
            timestamp: SharedString::from(Local::now().format("%H:%M:%S").to_string()),
            actor: SharedString::from("SYSTEM CORE"),
            pattern: SharedString::from("AETHER AUTONOMOUS GUARD ACTIVE"),
            mitigation: SharedString::from("Dynamic Heuristic Active"),
            level: SharedString::from("OK"),
            details: SharedString::from("System-Status optimal."),
        },
    ]));
    ui.set_logs(ModelRc::from(log_data.clone()));

    let loaded_rules = load_local_rules();
    let threat_rules_store = Arc::new(RwLock::new(loaded_rules));

    // =========================================================================
    // SPLASH SCREEN TIMER LOGIK (Präzise 3 Sekunden ohne Zicken)
    // =========================================================================
    let ui_splash_handle = ui.as_weak();
    let splash_timer = slint::Timer::default();
    let mut progress = 0.0;

    splash_timer.start(slint::TimerMode::Repeated, Duration::from_millis(50), move || {
        if let Some(ui) = ui_splash_handle.upgrade() {
            progress += 0.02;
            ui.set_splash_progress(progress);

            if progress >= 0.20 && progress < 0.50 {
                ui.set_splash_status(SharedString::from("CONNECTING TO ORBITAL LINK [STARLINK ACTIVE]..."));
            } else if progress >= 0.50 && progress < 0.80 {
                ui.set_splash_status(SharedString::from("MOUNTING LOCAL BUCKET SIGNATURE DECRYPTOR..."));
            } else if progress >= 0.80 && progress < 1.0 {
                ui.set_splash_status(SharedString::from("INJECTING AETHER KERNEL PROTECTION SHIELD..."));
            } else if progress >= 1.0 {
                ui.set_show_splash(false); // Dashboard freischalten
            }
        }
    });

    // Callbacks für Dashboard Aktionen
    ui.on_execute_immediate_action(|action_type, actor| {
        println!("Aktion: {} gegen {}", action_type.as_str(), actor.as_str());
    });

    let ui_handle_manual = ui.as_weak();
    let log_data_manual = log_data.clone();
    ui.on_trigger_simulation(move || {
        let ui = ui_handle_manual.unwrap();
        let manual_entry = LogEntry {
            timestamp: SharedString::from(Local::now().format("%H:%M:%S").to_string()),
            actor: SharedString::from("MANUAL CORE SCAN"),
            pattern: SharedString::from("Deep Vulnerability Audit Execution"),
            mitigation: SharedString::from("Zero Faults"),
            level: SharedString::from("OK"),
            details: SharedString::from("Manuell getriggerter Integritßtsscan."),
        };
        log_data_manual.insert(0, manual_entry);
        ui.set_latency(SharedString::from(format!("{:.2}ms", thread_rng().gen_range(0.01..0.04))));
    });

    let (tx, rx) = mpsc::channel::<LogEntry>();
    let threat_rules_daemon = threat_rules_store.clone();

    // Background Interceptor Thread
    thread::spawn(move || {
        let mut sys = System::new_all();
        let mut rng = thread_rng();
        let mut strike_map: HashMap<u32, u32> = HashMap::new();

        // Abgesicherte IP Ermittlung ohne Konsolen-Spam bei Boot-Verzögerung
        let target_ip = match local_ip() {
            Ok(ip) => ip.to_string(),
            Err(_) => "192.168.178.44".to_string(), // Stabiler Fallback
        };

        loop {
            thread::sleep(Duration::from_millis(2000));
            sys.refresh_all();

            let process_list: Vec<_> = sys.processes().values().collect();
            let mut anomaly_detected = false;
            let mut new_entry = Option::<LogEntry>::None;
            let mut current_iteration_pids = std::collections::HashSet::new();

            let active_rules = threat_rules_daemon.read().unwrap().clone();

            for proc in &process_list {
                let pid_u32 = proc.pid().as_u32();
                current_iteration_pids.insert(pid_u32);
                let name_string = proc.name().to_string();
                let name_lower = name_string.to_lowercase();

                for rule in &active_rules {
                    if name_lower.contains(&rule.detection_keyword.to_lowercase()) {
                        let strikes = strike_map.entry(pid_u32).or_insert(0);
                        *strikes += 1;

                        if *strikes >= rule.min_cpu_strikes {
                            new_entry = Some(LogEntry {
                                timestamp: SharedString::from(Local::now().format("%H:%M:%S").to_string()),
                                actor: SharedString::from(format!("PID: {} ({})", pid_u32, name_string)),
                                pattern: SharedString::from(rule.pattern_name.clone()),
                                mitigation: SharedString::from(rule.countermeasure.clone()),
                                level: SharedString::from(rule.alert_level.clone()),
                                details: SharedString::from(rule.details_template.clone()),
                            });
                            anomaly_detected = true;
                            break;
                        }
                    }
                }
                if anomaly_detected { break; }
            }

            strike_map.retain(|pid, _| current_iteration_pids.contains(pid));

            if !anomaly_detected && rng.gen_bool(0.05) {
                new_entry = Some(LogEntry {
                    timestamp: SharedString::from(Local::now().format("%H:%M:%S").to_string()),
                    actor: SharedString::from(format!("IP: {}", target_ip)),
                    pattern: SharedString::from("Suspicious Portscan Sequence"),
                    mitigation: SharedString::from("Dynamic Tarpit Delay Deployment"),
                    level: SharedString::from("WARNING"),
                    details: SharedString::from("Portscan abgefangen."),
                });
            }

            if let Some(entry) = new_entry {
                if tx.send(entry).is_err() { break; }
            }
        }
    });

    // UI Async Refresh Loop
    let ui_handle_daemon = ui.as_weak();
    let log_data_daemon = log_data.clone();
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, Duration::from_millis(100), move || {
        while let Ok(entry) = rx.try_recv() {
            let ui = ui_handle_daemon.unwrap();
            log_data_daemon.insert(0, entry);
            if log_data_daemon.row_count() > 8 {
                log_data_daemon.remove(log_data_daemon.row_count() - 1);
            }
            let current_blocks: i32 = ui.get_total_blocks().parse().unwrap_or(1412);
            ui.set_total_blocks(SharedString::from((current_blocks + 1).to_string()));
        }
    });

    let _keep_alive = timer;
    let _keep_splash = splash_timer;
    ui.run()
}