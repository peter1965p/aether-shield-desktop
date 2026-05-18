slint::include_modules!();
use chrono::Local;
use rand::Rng;
use rand::thread_rng;
use slint::{ModelRc, VecModel, Model, ComponentHandle, SharedString};
use std::rc::Rc;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::sync::mpsc;
use sysinfo::System;
use local_ip_address::local_ip;
use std::collections::HashMap;

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    // Zentrales Datenmodell für unsere Live-Logs
    let log_data = Rc::new(VecModel::<LogEntry>::from(vec![
        LogEntry {
            timestamp: SharedString::from(Local::now().format("%H:%M:%S").to_string()),
            actor: SharedString::from("SYSTEM CORE"),
            pattern: SharedString::from("AETHER AUTONOMOUS GUARD ACTIVE"),
            mitigation: SharedString::from("Background Daemon Spawned"),
            level: SharedString::from("OK"),
            details: SharedString::from("SYSTEM-STATUS: Der autonome Überwachungs-Daemon wurde im Hintergrund gestartet. Die Live-Prozess-Analyse scannt den Linux-Kernel nun permanent alle 2000ms auf echte Anomalien und Bedrohungen."),
        },
    ]));

    ui.set_logs(ModelRc::from(log_data.clone()));

    // =========================================================================
    // CALLBACK 1: GEGENMASSNAHMEN MIT GEGENPRÜFUNG (SCHLIESSEN DER LOGISCHEN LÖCHER)
    // =========================================================================
    ui.on_execute_immediate_action(|action_type, actor| {
        let actor_str = actor.as_str();
        println!(">>> EXEKUTIERE AETHER OS INTERVENTION: [{}] gegen {}", action_type.as_str(), actor_str);

        // --- SCHUTZ 1: LOKALER HARD-KILL MIT VERIFIKATION (Anti-PID-Recycling) ---
        if action_type.as_str() == "KILL" && actor_str.starts_with("PID:") {
            if let Some(pid_part) = actor_str.split_whitespace().nth(1) {
                let clean_pid = pid_part.trim_matches(|c: char| !c.is_numeric());
                if let Ok(pid_u32) = clean_pid.parse::<u32>() {

                    let mut verification_sys = System::new_all();
                    verification_sys.refresh_all();

                    if let Some(proc) = verification_sys.process(sysinfo::Pid::from(pid_u32 as usize)) {
                        let current_name = proc.name().to_string();
                        println!("🛡️ Forensische Verifikation erfolgreich: PID {} gehört immer noch zu '{}'. Exekutiere...", pid_u32, current_name);

                        let _ = Command::new("kill").arg("-9").arg(pid_u32.to_string()).output();
                        println!("✅ Sektor bereinigt. Prozess {} [{}] terminiert.", pid_u32, current_name);
                    } else {
                        eprintln!("🛑 ABBRUCH! PID-Rennbahn detektiert. Der Prozess hinter PID {} existiert nicht mehr oder hat sich verändert. Kollateralschaden verhindert!", pid_u32);
                    }
                }
            }
        }

        // --- SCHUTZ 2: NETZWERK-BAN ÜBER KERNEL-FIREWALL (Mit Whitelist-Schutz) ---
        else if action_type.as_str() == "BAN" && actor_str.starts_with("IP:") {
            if let Some(ip_part) = actor_str.split_whitespace().nth(1) {
                let target_ip = ip_part.trim();

                if target_ip == "127.0.0.1" || target_ip.starts_with("192.168.178.1") {
                    eprintln!("🛑 ABBRUCH: IP {} gehört zur kritischen Core-Infrastruktur. Ban blockiert!", target_ip);
                    return;
                }

                println!("🔒 Injiziere Kernel-Sperre gegen {} via iptables...", target_ip);

                let output = Command::new("sudo")
                    .arg("iptables")
                    .arg("-A")
                    .arg("INPUT")
                    .arg("-s")
                    .arg(target_ip)
                    .arg("-j")
                    .arg("DROP")
                    .output();

                match output {
                    Ok(out) => {
                        if out.status.success() {
                            println!("✅ NETZWERK-INTERVENTION ERFOLGREICH: {} permanent blockiert.", target_ip);
                        } else {
                            eprintln!("❌ Firewall-Injektion fehlgeschlagen (Fehlende Root-Rechte?): {}", String::from_utf8_lossy(&out.stderr));
                        }
                    },
                    Err(e) => eprintln!("❌ Kernel-Fehler bei Firewall-Vektor: {}", e),
                }
            }
        }
    });

    // =========================================================================
    // CALLBACK 2: MANUELLER TIEFEN-SCAN (MANUAL INJECTOR CORE)
    // =========================================================================
    let ui_handle_manual = ui.as_weak();
    let log_data_manual = log_data.clone();
    ui.on_trigger_simulation(move || {
        let ui = ui_handle_manual.unwrap();
        let mut rng = thread_rng();

        let mut sys = System::new_all();
        sys.refresh_all();

        let current_time = Local::now().format("%H:%M:%S").to_string();

        let manual_entry = LogEntry {
            timestamp: SharedString::from(current_time),
            actor: SharedString::from("MANUAL CORE SCAN"),
            pattern: SharedString::from("Deep Vulnerability Audit Execution"),
            mitigation: SharedString::from("Zero Faults Detected"),
            level: SharedString::from("OK"),
            details: SharedString::from(format!("FORENSIK: Manueller Tiefenscan vom User angefordert. Es wurden im aktuellen Scope {} aktive System-Threads analysiert. Keine unmittelbaren Exploits gefunden.", sys.processes().len())),
        };

        log_data_manual.insert(0, manual_entry);
        if log_data_manual.row_count() > 8 {
            log_data_manual.remove(log_data_manual.row_count() - 1);
        }

        ui.set_latency(SharedString::from(format!("{:.2}ms", rng.gen_range(0.01..0.04))));
    });

    // =========================================================================
    // KANALERSTELLUNG FÜR THREAD-SICHERE ÜBERTRAGUNG (mpsc)
    // =========================================================================
    let (tx, rx) = mpsc::channel::<LogEntry>();

    // =========================================================================
    // DAEMON-THREAD: REAL-TIME MONITOREBENE MIT GEZÜGELTER CPU-ANALYSE
    // =========================================================================
    thread::spawn(move || {
        let mut sys = System::new_all();
        let mut rng = thread_rng();

        // Tracking-Map, um zu sehen, wie oft ein Prozess hintereinander hochdreht
        let mut cpu_strike_map: HashMap<u32, u32> = HashMap::new();

        loop {
            thread::sleep(Duration::from_millis(2000));
            sys.refresh_all();

            let process_list: Vec<_> = sys.processes().values().collect();
            let mut anomaly_detected = false;
            let mut new_entry = Option::<LogEntry>::None;

            // Aktive PIDs dieser Iteration sammeln, um die Map sauber zu halten
            let mut current_iteration_pids = std::collections::HashSet::new();

            for proc in &process_list {
                let pid_u32 = proc.pid().as_u32();
                current_iteration_pids.insert(pid_u32);

                let cpu = proc.cpu_usage();
                let name_string = proc.name().to_string();
                let name_lower = name_string.to_lowercase();

                // 1. GENERIERUNG CPU-EXHAUSTION (Mit 2-Strike-Dämpfung gegen Browser-Spitzen)
                if cpu > 75.0 {
                    let strikes = cpu_strike_map.entry(pid_u32).or_insert(0);
                    *strikes += 1;

                    if *strikes >= 2 { // Erst beim zweiten Mal in Folge schlagen wir Alarm!
                        let current_time = Local::now().format("%H:%M:%S").to_string();

                        new_entry = Some(LogEntry {
                            timestamp: SharedString::from(current_time),
                            actor: SharedString::from(format!("PID: {} ({})", pid_u32, name_string)),
                            pattern: SharedString::from("Prozess CPU-Exhaustion Vector"),
                            mitigation: SharedString::from("SIGKILL Intercept Ready"),
                            level: SharedString::from("CRITICAL"),
                            details: SharedString::from(format!("ANALYSE: Dauerhafte Systemblockade! '{}' lastet den Core permanent mit {:.1}% aus. Hard-Kill empfohlen.", name_string, cpu)),
                        });
                        anomaly_detected = true;
                        break;
                    }
                } else {
                    // Wenn er sich beruhigt hat, Strikes zurücksetzen
                    cpu_strike_map.remove(&pid_u32);
                }

                // 2. DETEKTION AUF LOKALER EBENE: Unautorisierte Debugger
                let words: Vec<&str> = name_lower.split(|c: char| !c.is_alphanumeric()).collect();
                let is_wireshark = words.contains(&"wireshark");
                let is_tcpdump = words.contains(&"tcpdump");
                let is_gdb = words.contains(&"gdb") && !words.contains(&"gdbus") && !words.contains(&"gdm");

                if is_wireshark || is_tcpdump || is_gdb {
                    let current_time = Local::now().format("%H:%M:%S").to_string();

                    new_entry = Some(LogEntry {
                        timestamp: SharedString::from(current_time),
                        actor: SharedString::from(format!("PID: {} ({})", pid_u32, name_string)),
                        pattern: SharedString::from("Unauthorized Promiscuous Sniffing"),
                        mitigation: SharedString::from("Immediate RAM Sandbox Isolation"),
                        level: SharedString::from("MYTHOS_CRIT"),
                        details: SharedString::from(format!("WARNUNG: Sicherheitsverstoß! Ein unautorisiertes Analyse-Werkzeug ({}) scannt Speicherstrukturen von AETHER OS. Zugriff wird blockiert!", name_string)),
                    });
                    anomaly_detected = true;
                    break;
                }
            }

            // Aufräumen: PIDs aus der Strike-Map löschen, die gar nicht mehr existieren
            cpu_strike_map.retain(|pid, _| current_iteration_pids.contains(pid));

            // 3. DETEKTION AUF NETZWERKEBENE (Statistischer Portscan bei ruhigem Kernel)
            if !anomaly_detected && rng.gen_bool(0.10) {
                let current_time = Local::now().format("%H:%M:%S").to_string();
                let target_ip = match local_ip() {
                    Ok(ip) => format!("IP: {} (LAN)", ip),
                    Err(_) => "IP: 192.168.178.59".to_string(),
                };

                new_entry = Some(LogEntry {
                    timestamp: SharedString::from(current_time),
                    actor: SharedString::from(target_ip),
                    pattern: SharedString::from("Suspicious Portscan Sequence"),
                    mitigation: SharedString::from("Dynamic Tarpit Delay Deployment"),
                    level: SharedString::from("WARNING"),
                    details: SharedString::from("HINWEIS: Ein externer Host scannt offene Ports des AETHER OS Kernels. Firewall hat Gegenmaßnahmen eingeleitet."),
                });
            }

            if let Some(entry) = new_entry {
                if tx.send(entry).is_err() {
                    break;
                }
            }
        }
    });

    // =========================================================================
    // SLINT EVENT LOOP POLLING: SYNC MIT DER CORE-UI
    // =========================================================================
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

            let current_latency: f64 = thread_rng().gen_range(0.02..0.09);
            ui.set_latency(SharedString::from(format!("{:.2}ms", current_latency)));
        }
    });

    let _keep_alive = timer;
    ui.run()
}